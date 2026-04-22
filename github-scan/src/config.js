import fs from "fs";
import path from "path";

function loadEnv() {
    const envPath = path.resolve(process.cwd(), ".env");
    if (!fs.existsSync(envPath)) return;
    const lines = fs.readFileSync(envPath, "utf-8").split("\n");
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        const eqIdx = trimmed.indexOf("=");
        if (eqIdx === -1) continue;
        const key = trimmed.slice(0, eqIdx).trim();
        const val = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, "");
        if (!process.env[key]) process.env[key] = val;
    }
}

loadEnv();

export const CONFIG = Object.freeze({
    token: process.env.GITHUB_TOKEN || "",
    baseUrl: "https://api.github.com",
    rawBase: "https://raw.githubusercontent.com",
    maxFileSizeMb: 30,
    maxCommitsScan: 200,
    concurrency: 20,
    sleepMs: 100,
    repoBatch: 5,
    branchBatch: 3,
    retries: 3,
});
