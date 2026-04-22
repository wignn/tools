import { c } from "./colors.js";

export function parseArgs() {
    const args = process.argv.slice(2);
    const opts = {
        username: null,
        noDownload: false,
        outputDir: null,
        maxRepos: Infinity,
        help: false,
    };

    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        switch (arg) {
            case "-h": case "--help":
                opts.help = true; break;
            case "--no-download":
                opts.noDownload = true; break;
            case "-o": case "--output":
                opts.outputDir = args[++i]; break;
            case "--max-repos":
                opts.maxRepos = parseInt(args[++i]) || Infinity; break;
            default:
                if (!arg.startsWith("-")) opts.username = arg;
        }
    }

    return opts;
}

export function showHelp() {
    console.log(`
${c.bold}${c.cyan}GitHub OSINT Deep Scanner v3.0${c.reset}
${c.dim}Concurrent deep-scan of GitHub profiles for sensitive data leaks${c.reset}

${c.bold}USAGE${c.reset}
  ${c.green}bun run main.js${c.reset} ${c.yellow}<username>${c.reset} [options]
  ${c.green}node main.js${c.reset} ${c.yellow}<username>${c.reset} [options]

${c.bold}ARGUMENTS${c.reset}
  ${c.yellow}<username>${c.reset}           GitHub username to scan ${c.dim}(required)${c.reset}

${c.bold}OPTIONS${c.reset}
  ${c.cyan}-h, --help${c.reset}           Show this help message
  ${c.cyan}--no-download${c.reset}        Skip downloading media files
  ${c.cyan}-o, --output${c.reset} ${c.yellow}<dir>${c.reset}   Output directory for downloads ${c.dim}(default: images_<user>)${c.reset}
  ${c.cyan}--max-repos${c.reset} ${c.yellow}<n>${c.reset}      Limit number of repos to scan

${c.bold}ENVIRONMENT${c.reset}
  ${c.cyan}GITHUB_TOKEN${c.reset}         Personal access token ${c.dim}(highly recommended)${c.reset}
                       Without: 60 req/hr │ With: 5,000 req/hr
                       Set in ${c.dim}.env${c.reset} file or export as env variable

${c.bold}EXAMPLES${c.reset}
  ${c.dim}$${c.reset} bun run main.js octocat
  ${c.dim}$${c.reset} bun run main.js torvalds --max-repos 10
  ${c.dim}$${c.reset} bun run main.js defunkt --no-download -o ./output
`);
}
