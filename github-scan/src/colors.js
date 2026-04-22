const isTTY = process.stdout.isTTY !== false;
const e = (code) => isTTY ? `\x1b[${code}m` : "";

export const c = {
    reset: e(0), bold: e(1), dim: e(2),
    italic: e(3), under: e(4),
    red: e(31), green: e(32), yellow: e(33),
    blue: e(34), magenta: e(35), cyan: e(36),
    white: e(37), gray: e(90),
    bgRed: e(41), bgGreen: e(42), bgBlue: e(44), bgCyan: e(46),
};

export const fmt = {
    error: (s) => `${c.red}${c.bold}✗${c.reset} ${c.red}${s}${c.reset}`,
    warn: (s) => `${c.yellow}${c.bold}⚠${c.reset} ${c.yellow}${s}${c.reset}`,
    success: (s) => `${c.green}${c.bold}✓${c.reset} ${c.green}${s}${c.reset}`,
    info: (s) => `${c.cyan}${c.bold}ℹ${c.reset} ${c.dim}${s}${c.reset}`,
    label: (s) => `${c.bold}${c.white}${s}${c.reset}`,
    value: (s) => `${c.cyan}${s}${c.reset}`,
    count: (n) => `${c.bold}${c.yellow}${n}${c.reset}`,
    critical: (s) => `${c.bgRed}${c.white}${c.bold} ${s} ${c.reset}`,
    tag: (s) => `${c.bgCyan}${c.bold} ${s} ${c.reset}`,
    dim: (s) => `${c.dim}${s}${c.reset}`,
};

export function printHeader(emoji, title) {
    const line = `${c.dim}${"─".repeat(62)}${c.reset}`;
    console.log(`\n${line}`);
    console.log(`  ${emoji}  ${c.bold}${c.white}${title}${c.reset}`);
    console.log(line);
}

export function printKV(key, value, indent = 2) {
    if (value == null || value === "") return;
    console.log(`${" ".repeat(indent)}${c.dim}${key.padEnd(20)}${c.reset}${c.white}${value}${c.reset}`);
}

export function printProgress(current, total, label = "") {
    const pct = Math.round((current / total) * 100);
    const width = 24;
    const fill = Math.round((current / total) * width);
    const bar = `${c.green}${"█".repeat(fill)}${c.dim}${"░".repeat(width - fill)}${c.reset}`;
    const text = `\r  ${bar} ${c.bold}${pct}%${c.reset} ${c.dim}(${current}/${total})${c.reset} ${label}`;
    process.stdout.write(text.padEnd(100) + "\r");
}

export function clearLine() {
    if (isTTY) process.stdout.write("\r\x1b[K");
}
