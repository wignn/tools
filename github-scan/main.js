import fs from "fs";
import path from "path";
import { CONFIG } from "./src/config.js";
import { parallel } from "./src/http.js";
import { getUserInfo, getAllRepos } from "./src/github.js";
import { scanRepo, scanGists, downloadMedia } from "./src/scanner.js";
import { parseArgs, showHelp } from "./src/cli.js";
import { c, fmt, printHeader } from "./src/colors.js";
import {
  printBanner, printTokenWarning, printScanMeta, printProfile,
  printRepoResult, printFindings, printDownloadResult,
  printSummary, printReportSaved,
} from "./src/reporter.js";

async function main() {
  const opts = parseArgs();

  if (opts.help) { showHelp(); process.exit(0); }

  printBanner();

  const username = opts.username;
  if (!username) {
    console.log(fmt.error("Username is required.\n"));
    showHelp();
    process.exit(1);
  }

  if (!CONFIG.token) printTokenWarning();

  const startTime = Date.now();
  printScanMeta(username, CONFIG);

  const user = await getUserInfo(username);
  if (!user) {
    console.log(fmt.error(`User "${username}" not found on GitHub.`));
    process.exit(1);
  }

  const profileFields = printProfile(user);

  printHeader("📦", "SCANNING REPOSITORIES");

  let repos = await getAllRepos(username);
  if (opts.maxRepos < repos.length) {
    repos = repos.slice(0, opts.maxRepos);
    console.log(`  ${c.dim}Limited to first ${opts.maxRepos} repositories${c.reset}`);
  }
  console.log(`  ${fmt.count(repos.length)} repositories to scan\n`);

  const allEmails = new Set();
  const allSecrets = {};
  const allMedia = [];
  const allSuspicious = [];
  const waFindings = [];
  const languages = {};
  let scannedCount = 0;

  await parallel(
    repos.map(repo => async () => {
      const name = repo.name;
      const lang = repo.language || "Unknown";
      const stars = repo.stargazers_count || 0;
      const isFork = repo.fork;

      if (lang !== "Unknown") languages[lang] = (languages[lang] || 0) + 1;

      const result = await scanRepo(username, name, waFindings);

      for (const e of result.emails) allEmails.add(e);
      allMedia.push(...result.media);
      allSuspicious.push(...result.suspicious);
      if (Object.keys(result.secrets).length) allSecrets[name] = result.secrets;

      scannedCount++;
      printRepoResult(scannedCount, repos.length, name, lang, stars, isFork, result);

      return result;
    }),
    CONFIG.repoBatch,
  );

  printHeader("📝", "SCANNING GISTS");
  const { gists, gistSecrets } = await scanGists(username, waFindings);
  console.log(`  ${fmt.count(gists.length)} gists scanned`);

  printFindings(waFindings, allSuspicious, allSecrets, gistSecrets, allEmails, languages);

  const imagesDir = opts.outputDir || `images_${username}`;

  if (!opts.noDownload && allMedia.length) {
    printHeader("🖼️ ", "DOWNLOADING MEDIA");
    console.log(`  ${fmt.count(allMedia.length)} media files to download`);
    console.log(`  ${c.dim}Output: ${path.resolve(imagesDir)}/${c.reset}\n`);

    const dl = await downloadMedia(allMedia, imagesDir);
    printDownloadResult(dl.downloaded, dl.waDl, dl.skipped);
  }

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  const secretsN = Object.values(allSecrets).reduce((a, v) => a + Object.keys(v).length, 0);

  printSummary({
    username,
    repos: repos.length,
    gists: gists.length,
    emails: allEmails.size,
    media: allMedia.length,
    waFindings: waFindings.length,
    suspicious: allSuspicious.length,
    secrets: secretsN,
    languages: Object.keys(languages).slice(0, 5).join(", ") || "—",
    duration: `${elapsed}s`,
  });

  const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const outputFile = `osint_${username}_${ts}.json`;

  fs.writeFileSync(outputFile, JSON.stringify({
    username,
    scanTime: new Date().toISOString(),
    duration: `${elapsed}s`,
    severity: waFindings.length > 0 ? "CRITICAL" : allSuspicious.length > 0 ? "WARNING" : "CLEAN",
    profile: profileFields,
    emailsFound: [...allEmails],
    waFindings,
    suspiciousFiles: allSuspicious,
    secretsFound: { ...allSecrets, ...gistSecrets },
    languages,
    mediaFiles: allMedia.map(m => ({
      repo: m.repo, branch: m.branch,
      path: m.path, sizeBytes: m.size, isWa: m.isWa,
    })),
  }, null, 2), "utf8");

  printReportSaved(outputFile);
}

main().catch(err => {
  console.error(`\n${fmt.error(`Fatal: ${err.message}`)}`);
  if (process.env.DEBUG) console.error(err.stack);
  process.exit(1);
});