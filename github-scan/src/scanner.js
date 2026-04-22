import fs from "fs";
import path from "path";
import { CONFIG } from "./config.js";
import { getRaw, downloadFile, parallel, stats } from "./http.js";
import {
    getAllBranches, getFullTree, getRawUrl,
    getCommitsHistory, getGists,
} from "./github.js";
import {
    isExcludedPath, isWaFilename, classifyFile, scanTextForSecrets,
} from "./detection.js";
import { c, fmt, printProgress, clearLine } from "./colors.js";

export async function scanRepo(owner, repoName, waFindings) {
    const result = {
        secrets: {},
        media: [],
        waFiles: [],
        suspicious: [],
        emails: new Set(),
    };

    const branches = await getAllBranches(owner, repoName);
    const seen = new Set();

    await parallel(branches.map(branch => async () => {
        const tree = await getFullTree(owner, repoName, branch);

        const items = tree.filter(item => {
            const p = item.path || "";
            if (isExcludedPath(p)) return false;
            const key = `${branch}/${p}`;
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });

        for (const item of items) {
            const filePath = item.path;
            const size = item.size || 0;
            const cl = classifyFile(filePath, size);
            const rawUrl = getRawUrl(owner, repoName, branch, filePath);

            if (cl.isWa) {
                const entry = {
                    repo: repoName, branch, path: filePath,
                    sizeKb: Math.floor(size / 1024),
                    reason: "WhatsApp pattern match", rawUrl,
                };
                result.waFiles.push(entry);
                waFindings.push(entry);
            } else if (cl.isSuspicious) {
                result.suspicious.push({
                    repo: repoName, branch, path: filePath,
                    sizeKb: Math.floor(size / 1024),
                    reason: "Suspicious keyword", rawUrl,
                });
            }

            if (cl.isMedia) {
                result.media.push({
                    repo: repoName, branch, path: filePath,
                    name: cl.fname, size, rawUrl, isWa: cl.isWa,
                });
            }
        }

        const textItems = items.filter(i => {
            const cl = classifyFile(i.path, i.size || 0);
            return cl.isText && i.size > 0;
        });

        await parallel(textItems.map(item => async () => {
            const rawUrl = getRawUrl(owner, repoName, branch, item.path);
            const content = await getRaw(rawUrl);
            if (content) {
                const found = scanTextForSecrets(content);
                if (Object.keys(found).length) {
                    result.secrets[`${branch}/${item.path}`] = found;
                }
            }
        }), CONFIG.concurrency);

    }), CONFIG.branchBatch);

    const commits = await getCommitsHistory(owner, repoName);
    for (const commit of commits) {
        for (const role of ["author", "committer"]) {
            const actor = commit?.commit?.[role] || {};
            const email = actor.email || "";
            const name = actor.name || "";
            if (email && !email.includes("noreply") && !email.includes("github")) {
                result.emails.add(`${name} <${email}>`);
            }
        }
    }

    return result;
}

export async function scanGists(username, waFindings) {
    const gists = await getGists(username);
    const gistSecrets = {};

    for (const gist of gists) {
        const files = Object.keys(gist.files || {});

        await parallel(files.map(fname => async () => {
            const finfo = gist.files[fname];
            const rawUrl = finfo?.raw_url;
            if (!rawUrl) return;

            if (isWaFilename(fname) || fname.toLowerCase().includes("whatsapp")) {
                waFindings.push({
                    repo: `gist:${gist.id}`, branch: "gist",
                    path: fname, sizeKb: 0,
                    reason: "WhatsApp file in Gist", rawUrl,
                });
            }

            const content = await getRaw(rawUrl);
            if (content) {
                const found = scanTextForSecrets(content);
                if (Object.keys(found).length)
                    gistSecrets[`gist:${gist.id}/${fname}`] = found;
            }
        }));
    }

    return { gists, gistSecrets };
}

export async function downloadMedia(allMedia, imagesDir) {
    fs.mkdirSync(imagesDir, { recursive: true });
    allMedia.sort((a, b) => (b.isWa ? 1 : 0) - (a.isWa ? 1 : 0));

    let downloaded = 0, skipped = 0, waDl = 0;

    await parallel(allMedia.map((item, idx) => async () => {
        const { repo, branch, path: fpath, size, rawUrl, isWa } = item;
        const dest = path.join(imagesDir, repo, branch, fpath);

        if (fs.existsSync(dest)) { skipped++; return; }

        const [ok] = await downloadFile(rawUrl, dest);
        if (ok) {
            downloaded++;
            if (isWa) waDl++;
        } else {
            skipped++;
        }

        printProgress(idx + 1, allMedia.length, `${c.dim}${repo}/${path.basename(fpath)}${c.reset}`);
    }), CONFIG.concurrency);

    clearLine();
    return { downloaded, skipped, waDl };
}
