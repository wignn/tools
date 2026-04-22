import path from "path";
import { c, fmt, printHeader, printKV } from "./colors.js";
import { stats } from "./http.js";

export function printBanner() {
    console.log(`
${c.cyan}${c.bold}  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${c.reset}
${c.cyan}${c.bold}  ┃${c.reset}   ${c.bold}${c.white}GitHub OSINT Deep Scanner${c.reset}  ${c.dim}v3.0${c.reset}                    ${c.cyan}${c.bold}┃${c.reset}
${c.cyan}${c.bold}  ┃${c.reset}   ${c.dim}High-performance concurrent analysis engine${c.reset}       ${c.cyan}${c.bold}┃${c.reset}
${c.cyan}${c.bold}  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${c.reset}
`);
}

export function printTokenWarning() {
    console.log(`  ${c.bgRed}${c.white}${c.bold} WARNING ${c.reset} ${c.yellow}GITHUB_TOKEN not set — limited to 60 req/hr${c.reset}`);
    console.log(`  ${c.dim}Set GITHUB_TOKEN in .env or environment for 5000 req/hr${c.reset}\n`);
}

export function printScanMeta(username, config) {
    console.log(`  ${c.dim}Target${c.reset}    ${c.bold}https://github.com/${username}${c.reset}`);
    console.log(`  ${c.dim}Started${c.reset}   ${new Date().toLocaleString("id-ID")}`);
    console.log(`  ${c.dim}Engine${c.reset}    ${c.green}concurrent${c.reset} ${c.dim}(${config.concurrency} workers, ${config.repoBatch} repo batch)${c.reset}`);
}

export function printProfile(user) {
    printHeader("📋", "PROFILE");
    const fields = {
        "Name": user.name,
        "Bio": user.bio,
        "Company": user.company,
        "Location": user.location,
        "Public Email": user.email,
        "Website": user.blog,
        "Twitter": user.twitter_username ? `@${user.twitter_username}` : null,
        "Created": user.created_at?.slice(0, 10),
        "Last Active": user.updated_at?.slice(0, 10),
        "Repos": user.public_repos,
        "Followers": `${user.followers} followers · ${user.following} following`,
        "Public Gists": user.public_gists,
    };
    for (const [k, v] of Object.entries(fields)) printKV(k, v);
    return fields;
}

export function printRepoResult(scannedCount, totalRepos, name, lang, stars, isFork, result) {
    const findings = [];
    if (result.waFiles.length) findings.push(`${c.red}${result.waFiles.length} WA${c.reset}`);
    if (result.suspicious.length) findings.push(`${c.yellow}${result.suspicious.length} sus${c.reset}`);
    if (Object.keys(result.secrets).length) findings.push(`${c.magenta}${Object.keys(result.secrets).length} sec${c.reset}`);

    const forkTag = isFork ? `${c.dim}[fork]${c.reset} ` : "";
    const findStr = findings.length
        ? `${c.dim}│${c.reset} ${findings.join(c.dim + " · " + c.reset)}`
        : `${c.dim}│ clean${c.reset}`;

    console.log(`  ${c.dim}[${scannedCount}/${totalRepos}]${c.reset} ${c.bold}${name}${c.reset} ${forkTag}${c.dim}(${lang})${c.reset} ⭐${stars} ${findStr}`);
}

export function printFindings(waFindings, allSuspicious, allSecrets, gistSecrets, allEmails, languages) {
    printHeader("🔴", "WHATSAPP LEAK REPORT");
    if (waFindings.length) {
        console.log(`  ${fmt.critical(`FOUND ${waFindings.length} WHATSAPP-RELATED FILES`)}\n`);
        waFindings.forEach((f, idx) => {
            console.log(`  ${c.red}${c.bold}[${idx + 1}]${c.reset} ${c.white}${f.repo}${c.reset}${c.dim}:${f.branch}${c.reset}`);
            console.log(`      ${c.dim}File  ${c.reset} ${f.path}`);
            console.log(`      ${c.dim}Why   ${c.reset} ${c.yellow}${f.reason}${c.reset}`);
            console.log(`      ${c.dim}URL   ${c.reset} ${c.cyan}${f.rawUrl}${c.reset}\n`);
        });
    } else {
        console.log(`  ${c.green}No WhatsApp files found${c.reset}`);
    }

    printHeader("⚠️ ", "SUSPICIOUS FILES");
    if (allSuspicious.length) {
        console.log(`  ${c.yellow}Found ${allSuspicious.length} suspicious files${c.reset}\n`);
        allSuspicious.slice(0, 30).forEach(s => {
            console.log(`  ${c.yellow}›${c.reset} ${c.dim}[${s.repo}:${s.branch}]${c.reset} ${s.path} ${c.dim}(${s.sizeKb}KB)${c.reset}`);
        });
        if (allSuspicious.length > 30)
            console.log(`\n  ${c.dim}... +${allSuspicious.length - 30} more in JSON report${c.reset}`);
    } else {
        console.log(`  ${c.green}None found${c.reset}`);
    }

    printHeader("🔐", "SENSITIVE DATA DETECTED");
    const combined = { ...allSecrets, ...gistSecrets };
    if (Object.keys(combined).length) {
        const totalF = Object.values(combined).reduce((a, v) => a + Object.keys(v).length, 0);
        console.log(`  ${c.red}${totalF} files contain potential secrets${c.reset}\n`);
        Object.entries(combined).slice(0, 10).forEach(([rname, files]) => {
            console.log(`  ${c.bold}📁 ${rname}${c.reset}`);
            Object.entries(files).slice(0, 3).forEach(([fpath, findings]) => {
                console.log(`     ${c.dim}📄 ${fpath}${c.reset}`);
                Object.entries(findings).forEach(([cat, matches]) => {
                    const preview = matches.slice(0, 2).map(m => String(m).slice(0, 50)).join(`${c.dim} │ ${c.reset}`);
                    console.log(`        ${c.yellow}${cat}${c.reset}: ${preview}`);
                });
            });
        });
    } else {
        console.log(`  ${c.green}None found${c.reset}`);
    }

    printHeader("📧", "EMAILS FROM COMMITS");
    if (allEmails.size) {
        [...allEmails].sort().forEach(e => console.log(`  ${c.cyan}+${c.reset} ${e}`));
    } else {
        console.log(`  ${c.dim}None found${c.reset}`);
    }

    printHeader("💻", "LANGUAGE DISTRIBUTION");
    const sorted = Object.entries(languages).sort((a, b) => b[1] - a[1]);
    const maxCount = sorted.length ? sorted[0][1] : 1;
    const colors = [c.cyan, c.green, c.yellow, c.magenta, c.blue, c.red];
    sorted.forEach(([lang, count], idx) => {
        const barLen = Math.max(1, Math.round((count / maxCount) * 30));
        const color = colors[idx % colors.length];
        console.log(`  ${lang.padEnd(18)} ${color}${"█".repeat(barLen)}${c.reset} ${c.dim}${count}${c.reset}`);
    });
}

export function printDownloadResult(downloaded, waDl, skipped) {
    console.log(`  ${c.green}Downloaded${c.reset}    ${downloaded} files`);
    if (waDl) console.log(`  ${c.red}WhatsApp${c.reset}      ${waDl} files`);
    if (skipped) console.log(`  ${c.dim}Skipped${c.reset}       ${skipped} files`);
}

export function printSummary(data) {
    printHeader("📊", "SCAN COMPLETE");

    const severity = data.waFindings > 0 ? c.red :
        data.suspicious > 0 ? c.yellow : c.green;
    const label = data.waFindings > 0 ? "CRITICAL" :
        data.suspicious > 0 ? "WARNING" : "CLEAN";

    console.log(`  ${severity}${c.bold}Overall: ${label}${c.reset}\n`);

    const rows = [
        ["Username", data.username],
        ["Repositories", data.repos],
        ["Gists", data.gists],
        ["Unique Emails", data.emails],
        ["Media Files", data.media],
        ["WhatsApp Leaks", data.waFindings],
        ["Suspicious", data.suspicious],
        ["Secrets Found", data.secrets],
        ["Languages", data.languages],
        ["Duration", data.duration],
        ["API Requests", stats.requests],
        ["Rate Limits", stats.rateLimitHits],
    ];

    rows.forEach(([key, val]) => {
        const hl = (key === "WhatsApp Leaks" && val > 0) ? c.red + c.bold :
            (key === "Secrets Found" && val > 0) ? c.magenta + c.bold : c.white;
        console.log(`  ${c.dim}${key.padEnd(18)}${c.reset} ${hl}${val}${c.reset}`);
    });
}

export function printReportSaved(filePath) {
    console.log(`\n  ${fmt.success(`Report saved: ${c.under}${filePath}${c.reset}`)}`);
    console.log(`  ${c.dim}${"─".repeat(62)}${c.reset}\n`);
}
