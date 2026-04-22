import fs from "fs";
import path from "path";
import { CONFIG } from "./config.js";
import { fmt } from "./colors.js";

const GH_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    ...(CONFIG.token ? { Authorization: `Bearer ${CONFIG.token}` } : {}),
};

export const stats = { requests: 0, rateLimitHits: 0, errors: 0 };

function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
}

export async function ghGet(url, params = {}) {
    const u = new URL(url);
    for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);

    for (let attempt = 0; attempt < CONFIG.retries; attempt++) {
        try {
            stats.requests++;
            const res = await fetch(u.toString(), { headers: GH_HEADERS });

            if (res.status === 200) return res.json();

            if (res.status === 403) {
                stats.rateLimitHits++;
                const reset = parseInt(res.headers.get("X-RateLimit-Reset") || "0");
                const wait = Math.max(reset - Math.floor(Date.now() / 1000), 10);
                console.log(fmt.warn(`Rate limit — pausing ${wait}s`));
                await sleep(wait * 1000);
                continue;
            }

            if (res.status === 404) return null;
            await sleep(2000);
        } catch {
            stats.errors++;
            if (attempt === CONFIG.retries - 1) return null;
            await sleep(3000);
        }
    }
    return null;
}

export async function getRaw(url) {
    try {
        stats.requests++;
        const res = await fetch(url, { headers: GH_HEADERS });
        if (res.status === 200) return res.text();
    } catch { }
    return "";
}

export async function downloadFile(url, destPath) {
    try {
        stats.requests++;
        const res = await fetch(url, { headers: GH_HEADERS });
        if (res.status !== 200) return [false, `HTTP ${res.status}`];

        const size = parseInt(res.headers.get("content-length") || "0");
        if (size > CONFIG.maxFileSizeMb * 1024 * 1024)
            return [false, `Too large (${Math.floor(size / 1024 / 1024)}MB)`];

        const buf = Buffer.from(await res.arrayBuffer());
        fs.mkdirSync(path.dirname(destPath), { recursive: true });
        fs.writeFileSync(destPath, buf);
        return [true, destPath];
    } catch (e) {
        stats.errors++;
        return [false, e.message];
    }
}

export async function parallel(tasks, limit = CONFIG.concurrency) {
    const results = [];
    for (let i = 0; i < tasks.length; i += limit) {
        const batch = tasks.slice(i, i + limit).map(fn => fn());
        results.push(...(await Promise.all(batch)));
        if (i + limit < tasks.length) await sleep(CONFIG.sleepMs);
    }
    return results;
}
