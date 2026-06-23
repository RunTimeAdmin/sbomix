#!/usr/bin/env node
'use strict';

/**
 * PackrAI CLI
 *
 * Usage:
 *   packrai <dir>                          local directory
 *   packrai owner/repo                     GitHub repo (default branch)
 *   packrai owner/repo@v1.2.0             GitHub repo at tag/branch
 *   packrai https://github.com/owner/repo  full GitHub URL
 *
 * Options:
 *   -o, --out <dir>       output directory (default: .)
 *   -n, --name <name>     project name override
 *   -v, --ver <version>   version override
 *   -a, --author <org>    author / org name
 *   --token <ghtoken>     GitHub token for private repos ($GITHUB_TOKEN)
 *   --no-vulns            skip OSV vulnerability lookup
 *   --no-recursive        do not recurse into subdirectories
 *   --format <fmt>        both | cyclonedx | spdx  (default: both)
 *   --json                machine-readable JSON summary to stdout
 */

const { program } = require('commander');
const path = require('path');
const fs = require('fs');
const { generateFromDirectory } = require('../src/pipeline');
const { isGitHubTarget, parseGitHubTarget, cloneRepo } = require('../src/github');
const pkg = require('../package.json');

program
    .name('packrai')
    .description('Generate accurate SBOMs from any GitHub repo or local directory')
    .version(pkg.version)
    .argument('<source>', 'Local path  OR  owner/repo[@ref]  OR  GitHub URL')
    .option('-o, --out <dir>',      'Output directory',                        '.')
    .option('-n, --name <name>',    'Project name (default: repo / dir name)')
    .option('-v, --ver <version>',  'Project version (default: tag or unknown)')
    .option('-a, --author <org>',   'Author or organisation name')
    .option('--token <token>',      'GitHub token for private repos (or set $GITHUB_TOKEN)')
    .option('--no-vulns',           'Skip OSV vulnerability enrichment')
    .option('--no-licenses',        'Skip deps.dev license enrichment')
    .option('--no-recursive',       'Do not recurse into subdirectories')
    .option('--format <fmt>',       'Output format: both|cyclonedx|spdx',      'both')
    .option('--json',               'Print summary as JSON (machine-readable)')
    .action(async (source, opts) => {
        let scanDir   = null;
        let cleanup   = null;
        let repoName  = opts.name  || null;
        let repoVer   = opts.ver   || null;
        let commitSha = null;

        try {
            // ── Resolve source: GitHub URL/shorthand or local path ──────────
            if (isGitHubTarget(source)) {
                const target = parseGitHubTarget(source);
                const token  = opts.token || process.env.GITHUB_TOKEN;

                if (!opts.json) {
                    process.stdout.write(`\n  packrai v${pkg.version}\n`);
                }

                const cloned = cloneRepo(target, { token, quiet: opts.json });
                scanDir   = cloned.dir;
                cleanup   = cloned.cleanup;
                commitSha = cloned.commitSha;

                repoName  = repoName || target.repo;
                repoVer   = repoVer  || target.ref || commitSha?.slice(0, 7) || 'unknown';

                if (!opts.json) {
                    process.stdout.write(`  Scanning ${target.owner}/${target.repo}${target.ref ? `@${target.ref}` : ''}\n\n`);
                }
            } else {
                scanDir  = path.resolve(source);
                repoName = repoName || path.basename(scanDir);
                repoVer  = repoVer  || 'unknown';

                if (!opts.json) {
                    process.stdout.write(`\n  packrai v${pkg.version}\n`);
                    process.stdout.write(`  Scanning ${scanDir}\n\n`);
                }
            }

            // ── Run pipeline ─────────────────────────────────────────────────
            const result = await generateFromDirectory(scanDir, {
                name:      repoName,
                version:   repoVer,
                author:    opts.author,
                vulns:     opts.vulns,
                licenses:  opts.licenses,
                recursive: opts.recursive,
            });

            const { stats } = result;
            const outDir = path.resolve(opts.out);
            fs.mkdirSync(outDir, { recursive: true });

            // ── Write output files ────────────────────────────────────────────
            const written = {};
            if (opts.format !== 'spdx') {
                written.cyclonedx = path.join(outDir, 'bom.cyclonedx.json');
                fs.writeFileSync(written.cyclonedx, JSON.stringify(result.cyclonedx, null, 2));
            }
            if (opts.format !== 'cyclonedx') {
                written.spdx = path.join(outDir, 'bom.spdx.json');
                fs.writeFileSync(written.spdx, JSON.stringify(result.spdx, null, 2));
            }

            // ── Output ────────────────────────────────────────────────────────
            if (opts.json) {
                console.log(JSON.stringify({ ...stats, commitSha, outputs: written }, null, 2));
            } else {
                const ok   = (s) => `\x1b[32m✓\x1b[0m ${s}`;
                const warn = (s) => `\x1b[33m⚠\x1b[0m ${s}`;
                const info = (s) => `  \x1b[2m${s}\x1b[0m`;

                console.log(ok(`${stats.totalComponents} components  ·  ${stats.ecosystems.join(', ')}`));
                if (written.cyclonedx) console.log(ok(`CycloneDX 1.6  →  ${written.cyclonedx}`));
                if (written.spdx)      console.log(ok(`SPDX 2.3       →  ${written.spdx}`));

                if (stats.vulnerabilities === 0) {
                    console.log(ok('0 known vulnerabilities'));
                } else if (stats.critical > 0) {
                    console.log(warn(`${stats.vulnerabilities} vulnerabilities  (${stats.critical} CRITICAL)`));
                } else {
                    console.log(warn(`${stats.vulnerabilities} vulnerabilities`));
                }

                console.log(ok(`Quality score  ${stats.qualityScore}/100`));
                console.log(info(`${stats.lockFilesScanned.length} lock file(s) · ${stats.elapsedMs}ms`));
                console.log('');

                if (stats.critical > 0) process.exit(1);
            }

        } catch (err) {
            if (!opts.json) {
                console.error(`\n  \x1b[31mError:\x1b[0m ${err.message}\n`);
            } else {
                console.error(JSON.stringify({ error: err.message }));
            }
            process.exit(1);
        } finally {
            if (cleanup) cleanup();
        }
    });

program.parse();
