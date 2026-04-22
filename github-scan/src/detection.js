import path from "path";

export const IMAGE_EXT = new Set([
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
    ".svg", ".ico", ".tiff", ".tif", ".heic", ".avif",
    ".jfif", ".pjpeg", ".pjp",
]);

export const MEDIA_EXT = new Set([
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt",
    ".zip", ".rar", ".tar", ".gz", ".7z", ".bz2",
    ".mp4", ".avi", ".mov", ".mkv", ".3gp", ".wmv", ".flv", ".webm",
    ".mp3", ".wav", ".ogg", ".m4a", ".aac", ".opus",
    ".csv", ".tsv", ".log", ".sql", ".db", ".sqlite", ".sqlite3",
    ".crypt12", ".crypt14", ".crypt15",
]);

export const TEXT_EXT = new Set([
    ".py", ".js", ".ts", ".php", ".rb", ".go", ".java", ".cs", ".cpp", ".c",
    ".h", ".env", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".sh", ".bash", ".txt", ".md", ".xml", ".properties", ".sql", ".html",
    ".htm", ".vue", ".jsx", ".tsx", ".kt", ".swift", ".dart", ".rs", ".lua",
]);

export const EXCLUDED_FOLDERS = new Set([
    "node_modules", ".git", "vendor", "vendor_", "bower_components",
    ".npm", ".yarn", "dist", "build", ".next", ".nuxt",
    "__pycache__", ".pytest_cache", ".mypy_cache",
    "venv", ".venv", "env",
    ".idea", ".vscode", ".gradle",
    "target", "Pods", "packages", ".bundle",
]);

export const WA_FILENAME_PATTERNS = [
    /IMG-\d{8}-WA\d+\.(jpg|jpeg|png|mp4|3gp)/i,
    /VID-\d{8}-WA\d+\.(mp4|3gp|avi|mov)/i,
    /AUD-\d{8}-WA\d+\.(mp3|opus|m4a|ogg|wav)/i,
    /PTT-\d{8}-WA\d+\.(opus|mp3|m4a|ogg)/i,
    /DOC-\d{8}-WA\d+\./i,
    /STK-\d{8}-WA\d+\./i,
    /msgstore.*\.db/i,
    /msgstore.*\.crypt\d*/i,
    /^wa\.db$/i,
    /axolotl\.db/i,
    /whatsapp.*backup/i,
    /whatsapp.*export/i,
    /WhatsApp.Chat.*\.(txt|zip)/i,
    /_chat\.txt$/i,
];

export const WA_FOLDER_PATTERNS = [
    /whatsapp/i,
    /com\.whatsapp/i,
    /wa_backup/i,
    /whatsapp[._]media/i,
];

export const SUSPICIOUS_KEYWORDS = [
    "screenshot", "screenshoot", "screen_shot", "screen-shot",
    "ss_", "_ss.", "tangkap", "capture",
    "private", "pribadi", "rahasia",
    "chat", "pesan", "message", "inbox",
    "whatsapp", "telegram", "line", "bbm",
    "backup", "backup_chat", "chatbackup",
    "kontak", "contact_list",
    "personal", "personal_data", "data_diri",
    "nomor_hp", "nohp", "no_hp",
    "transfer", "bukti", "bukti_tf", "resi",
];

export const SECRET_PATTERNS = {
    "Email": /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
    "Phone (ID)": /(?:\+62|08)[0-9]{8,12}/g,
    "IP Address": /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    "AWS Key": /AKIA[0-9A-Z]{16}/g,
    "Private Key": /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    "Password": /(?:password|passwd|pwd)\s*=\s*['"][^'"]{4,}['"]/gi,
    "API Key": /(?:api[_-]?key|apikey)\s*[=:]\s*['"][a-zA-Z0-9\-_]{10,}['"]/gi,
    "Token/Secret": /(?:token|secret)\s*[=:]\s*['"][a-zA-Z0-9\-_.]{10,}['"]/gi,
    "URL+Credentials": /https?:\/\/[^:]+:[^@]+@[^\s]+/g,
    "JWT": /eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+/g,
    "Database URL": /(?:mysql|postgresql|mongodb|redis):\/\/[^\s"']+/gi,
    "Google API Key": /AIza[0-9A-Za-z\-_]{35}/g,
    "Slack Token": /xox[baprs]-[0-9a-zA-Z]{10,}/g,
    "SSH Key": /ssh-(?:rsa|dss|ed25519|ecdsa) [A-Za-z0-9+/=]+/g,
    "NIK (ID)": /\b[1-9][0-9]{15}\b/g,
    "WA Chat Format": /^\[\d{1,2}\/\d{1,2}\/\d{2,4},\s\d{1,2}:\d{2}/gm,
};

export function isExcludedPath(filePath) {
    return filePath.split("/").some(part => EXCLUDED_FOLDERS.has(part));
}

export function isWaFilename(fname) {
    return WA_FILENAME_PATTERNS.some(p => p.test(fname));
}

export function isWaFolder(filePath) {
    return WA_FOLDER_PATTERNS.some(p => p.test(filePath));
}

export function hasSuspiciousKeyword(filePath) {
    return SUSPICIOUS_KEYWORDS.some(kw => filePath.toLowerCase().includes(kw));
}

export function classifyFile(filePath, size) {
    const fname = path.basename(filePath);
    const ext = path.extname(fname).toLowerCase();
    return {
        isImage: IMAGE_EXT.has(ext),
        isMedia: MEDIA_EXT.has(ext) || IMAGE_EXT.has(ext),
        isWa: isWaFilename(fname) || isWaFolder(filePath),
        isSuspicious: hasSuspiciousKeyword(filePath),
        isText: TEXT_EXT.has(ext) && size < 2 * 1024 * 1024,
        ext, fname,
    };
}

export function scanTextForSecrets(text) {
    const found = {};
    for (const [label, pattern] of Object.entries(SECRET_PATTERNS)) {
        const rx = new RegExp(pattern.source, pattern.flags);
        const matches = [...new Set(text.match(rx) || [])].slice(0, 5);
        if (matches.length) found[label] = matches;
    }
    return found;
}
