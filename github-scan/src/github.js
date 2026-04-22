import { CONFIG } from "./config.js";
import { ghGet } from "./http.js";
import { fmt } from "./colors.js";

export async function getUserInfo(username) {
    return ghGet(`${CONFIG.baseUrl}/users/${username}`);
}

export async function getAllRepos(username) {
    const repos = [];
    let page = 1;
    while (true) {
        const data = await ghGet(`${CONFIG.baseUrl}/users/${username}/repos`, {
            per_page: 100, page, type: "all",
        });
        if (!data || !data.length) break;
        repos.push(...data);
        page++;
    }
    return repos;
}

export async function getDefaultBranch(owner, repo) {
    const data = await ghGet(`${CONFIG.baseUrl}/repos/${owner}/${repo}`);
    return data?.default_branch || "main";
}

export async function getAllBranches(owner, repo) {
    const branches = [];
    let page = 1;
    while (true) {
        const data = await ghGet(`${CONFIG.baseUrl}/repos/${owner}/${repo}/branches`, {
            per_page: 100, page,
        });
        if (!data || !data.length) break;
        branches.push(...data.map(b => b.name));
        page++;
    }
    return branches.length ? branches : [await getDefaultBranch(owner, repo)];
}

export async function getFullTree(owner, repo, branch) {
    const data = await ghGet(
        `${CONFIG.baseUrl}/repos/${owner}/${repo}/git/trees/${branch}`,
        { recursive: "1" },
    );
    if (!data) return [];
    if (data.truncated) console.log(fmt.warn("Tree truncated (large repo)"));
    return (data.tree || []).filter(i => i.type === "blob");
}

export async function getCommitsHistory(owner, repo, maxN = CONFIG.maxCommitsScan) {
    const commits = [];
    let page = 1;
    while (commits.length < maxN) {
        const data = await ghGet(`${CONFIG.baseUrl}/repos/${owner}/${repo}/commits`, {
            per_page: 100, page,
        });
        if (!Array.isArray(data) || !data.length) break;
        commits.push(...data);
        page++;
        if (data.length < 100) break;
    }
    return commits.slice(0, maxN);
}

export async function getGists(username) {
    const data = await ghGet(`${CONFIG.baseUrl}/users/${username}/gists`);
    return data || [];
}

export function getRawUrl(owner, repo, branch, filePath) {
    const encoded = filePath.split("/").map(encodeURIComponent).join("/");
    return `${CONFIG.rawBase}/${owner}/${repo}/${branch}/${encoded}`;
}
