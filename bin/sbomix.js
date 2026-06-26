#!/usr/bin/env node
'use strict';

/**
 * SBOMix CLI
 *
 * Usage:
 *   sbomix <dir>                          local directory
 *   sbomix owner/repo                     GitHub repo (default branch)
 *   sbomix owner/repo@v1.2.0             GitHub repo at tag/branch
 *   sbomix https://github.com/owner/repo  full GitHub URL
 *   sbomix diff <from.cdx.json> <to.cdx.json>   diff two local CycloneDX files
 *
 * Scan options:
 *   -o, --out <dir>         output directory (default: .)
 *   -n, --name <name>       project name override
 *   -v, --ver <version>     version override
 *   -a, --author <org>      author / org name
 *   --token <ghtoken>       GitHub token for private repos ($GITHUB_TOKEN)
 *   --no-vulns              skip OSV vulnerability lookup
 *   --no-recursive          do not recurse into subdirectories
 *   --format <fmt>          both | cyclonedx | spdx  (default: both)
 *   --license-check         flag forbidden/restricted licenses; exit 1 if any found
 *   --json                  machine-readable JSON summary to stdout
 */

const { Command, program } = require('commander');
const path  = require('path');
const fs    = require('fs');
const { generateFromDirectory } = require('../src/pipeline');
const { diffCycloneDX } = require('../src/diff');
const { explainVulnerabilities } = require('../src/explain');
const { fetchKEVSet }            = require('../src/kev');
const { isGitHubTarget, parseGitHubTarget, cloneRepo } = require('../src/github');
const pkg = require('../package.json');

// ── diff subcommand ───────────────────────────────────────────────────────────
program.addCommand(
    new Command('diff')
        .description('Compare two CycloneDX SBOM files and show what changed')
        .argument('<from>', 'Older SBOM (bom.cyclonedx.json)')
        .argument('<to>',   'Newer SBOM (bom.cyclonedx.json)')
        .option('--json', 'Machine-readable JSON output')
        .action((fromPath, toPath, opts) => {
            try {
                const oldCdx = JSON.parse(fs.readFileSync(path.resolve(fromPath), 'utf8'));
                const newCdx = JSON.parse(fs.readFileSync(path.resolve(toPath),   'utf8'));
                const diff   = diffCycloneDX(oldCdx, newCdx);

                if (opts.json) {
                    console.log(JSON.stringify(diff, null, 2));
                    process.exit(diff.summary.newVulnerabilities > 0 ? 1 : 0);
                }

                const ok   = (s) => `\x1b[32m✓\x1b[0m ${s}`;
                const warn = (s) => `\x1b[33m⚠\x1b[0m ${s}`;
                const err  = (s) => `\x1b[31m✖\x1b[0m ${s}`;
                const dim  = (s) => `  \x1b[2m${s}\x1b[0m`;

                console.log(`\n  sbomix diff  ${path.basename(fromPath)} → ${path.basename(toPath)}\n`);

                const { summary } = diff;
                if (summary.added   > 0) console.log(warn(`${summary.added} component(s) added`));
                if (summary.removed > 0) console.log(warn(`${summary.removed} component(s) removed`));
                if (summary.updated > 0) console.log(warn(`${summary.updated} component(s) updated`));
                if (summary.added + summary.removed + summary.updated === 0) {
                    console.log(ok('No component changes'));
                }

                if (summary.newVulnerabilities > 0) {
                    console.log(err(`${summary.newVulnerabilities} new vulnerability/vulnerabilities introduced`));
                    for (const v of diff.newVulnerabilities) {
                        console.log(dim(`  ${v.osv_id}  ${v.purl}  ${v.severity ?? ''}`));
                    }
                }
                if (summary.resolvedVulnerabilities > 0) {
                    console.log(ok(`${summary.resolvedVulnerabilities} vulnerability/vulnerabilities resolved`));
                }
                if (summary.newVulnerabilities === 0 && summary.resolvedVulnerabilities === 0) {
                    console.log(ok('No vulnerability changes'));
                }

                if (diff.updated.length) {
                    console.log('');
                    for (const u of diff.updated) {
                        console.log(dim(`  ${u.name}  ${u.from} → ${u.to}`));
                    }
                }

                console.log('');
                if (summary.newVulnerabilities > 0) process.exit(1);

            } catch (e) {
                console.error(`\n  \x1b[31mError:\x1b[0m ${e.message}\n`);
                process.exit(2);
            }
        })
);

// ── scan (default) command ────────────────────────────────────────────────────
program
    .name('sbomix')
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
    .option('--no-docker',          'Skip Dockerfile audit')
    .option('--format <fmt>',       'Output format: both|cyclonedx|spdx',      'both')
    .option('--license-check',      'Flag forbidden/restricted licenses; exit 1 if any found')
    .option('--explain',            'Use AI to explain vulnerabilities and suggest a remediation plan (requires DEEPSEEK_API_KEY)')
    .option('--json',               'Print summary as JSON (machine-readable)')
    .action(async (source, opts) => {
        let scanDir   = null;
        let cleanup   = null;
        let repoName  = opts.name  || null;
        let repoVer   = opts.ver   || null;
        let commitSha = null;

        try {
            // Local check comes FIRST — "tests/fixtures" must not be mistaken for owner/repo.
            const isLocal = source.startsWith('.')
                || source.startsWith('/')
                || path.isAbsolute(source)
                || fs.existsSync(source);

            if (!isLocal && isGitHubTarget(source)) {
                const target = parseGitHubTarget(source);
                const token  = opts.token || process.env.GITHUB_TOKEN;

                if (!opts.json) process.stdout.write(`\n  sbomix v${pkg.version}\n`);

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
                    process.stdout.write(`\n  sbomix v${pkg.version}\n`);
                    process.stdout.write(`  Scanning ${scanDir}\n\n`);
                }
            }

            const result = await generateFromDirectory(scanDir, {
                name:      repoName,
                version:   repoVer,
                author:    opts.author,
                vulns:     opts.vulns,
                licenses:  opts.licenses,
                recursive: opts.recursive,
                docker:    opts.docker,
                format:    opts.format,
            });

            const { stats } = result;
            const outDir = path.resolve(opts.out);
            fs.mkdirSync(outDir, { recursive: true });

            const written = {};
            if (opts.format !== 'spdx') {
                written.cyclonedx = path.join(outDir, 'bom.cyclonedx.json');
                fs.writeFileSync(written.cyclonedx, JSON.stringify(result.cyclonedx, null, 2));
            }
            if (opts.format !== 'cyclonedx') {
                written.spdx = path.join(outDir, 'bom.spdx.json');
                fs.writeFileSync(written.spdx, JSON.stringify(result.spdx, null, 2));
            }

            if (opts.json) {
                console.log(JSON.stringify({ ...stats, commitSha, outputs: written }, null, 2));
            } else {
                const ok   = (s) => `\x1b[32m✓\x1b[0m ${s}`;
                const warn = (s) => `\x1b[33m⚠\x1b[0m ${s}`;
                const err  = (s) => `\x1b[31m✖\x1b[0m ${s}`;
                const dim  = (s) => `  \x1b[2m${s}\x1b[0m`;

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

                // ── Dockerfile audit ──────────────────────────────────────────
                if (result.dockerfileAudit.length > 0) {
                    console.log('');
                    for (const audit of result.dockerfileAudit) {
                        const rel = path.relative(scanDir, audit.path);
                        if (audit.findings.length === 0) {
                            console.log(ok(`${rel}  ·  no Dockerfile issues`));
                        } else {
                            const { high, medium, low } = audit.summary;
                            const parts = [];
                            if (high)   parts.push(`${high} HIGH`);
                            if (medium) parts.push(`${medium} MEDIUM`);
                            if (low)    parts.push(`${low} LOW`);
                            const label = high > 0 ? err : warn;
                            console.log(label(`${rel}  ·  ${parts.join('  ')}${audit.hasMultiStage ? '  · multi-stage' : ''}`));
                            for (const f of audit.findings) {
                                const loc = f.line ? `:${f.line}` : '';
                                console.log(dim(`  [${f.severity}] ${f.rule}${loc}  ${f.message}`));
                            }
                        }
                        // Base image CVEs (from SBOM attestation lookup)
                        // Deduplicate — multi-stage builds often reuse the same base image
                        const shownBase = new Set();
                        for (const img of audit.baseImages) {
                            if (shownBase.has(img.raw)) continue;
                            shownBase.add(img.raw);

                            const imgVulns = result.components
                                .filter((c) => c.ecosystem === 'container' && c.name === img.name)
                                .flatMap((c) => c.vulnerabilities || []);

                            if (imgVulns.length === 0) {
                                console.log(dim(`  base: ${img.raw}  ·  no CVE data`));
                            } else {
                                const crit = imgVulns.filter((v) => v.severity === 'CRITICAL').length;
                                const high = imgVulns.filter((v) => v.severity === 'HIGH').length;
                                const parts = [`${imgVulns.length} CVEs`];
                                if (crit) parts.push(`${crit} CRITICAL`);
                                if (high) parts.push(`${high} HIGH`);
                                const vulnStr = crit > 0 ? err(parts.join('  ')) : warn(parts.join('  '));
                                console.log(dim(`  base: ${img.raw}  ·`) + ' ' + vulnStr);
                                // Show up to 5 critical/high CVEs
                                const top = imgVulns
                                    .filter((v) => v.severity === 'CRITICAL' || v.severity === 'HIGH')
                                    .slice(0, 5);
                                for (const v of top) {
                                    console.log(dim(`    ${v.id}  [${v.severity}]  ${v.summary.slice(0, 80)}`));
                                }
                            }
                        }
                    }
                }

                if (stats.baseImageVulns > 0) {
                    const baseLabel = stats.baseImageCritical > 0 ? err : warn;
                    const baseParts = [`${stats.baseImageVulns} base-image CVEs`];
                    if (stats.baseImageCritical) baseParts.push(`${stats.baseImageCritical} CRITICAL`);
                    console.log(baseLabel(baseParts.join('  ')));
                }

                console.log(dim(`${stats.lockFilesScanned.length} lock file(s)${stats.dockerfilesScanned.length ? `  ·  ${stats.dockerfilesScanned.length} Dockerfile(s)` : ''}  ·  ${stats.elapsedMs}ms`));

                // ── License compliance ────────────────────────────────────────
                if (opts.licenseCheck) {
                    const lc = stats.licenseCompliance;
                    console.log('');
                    if (lc.forbidden.length === 0 && lc.restricted.length === 0) {
                        console.log(ok(`License score ${lc.score}/100  ·  no forbidden or restricted licenses`));
                    } else {
                        if (lc.forbidden.length > 0) {
                            console.log(warn(`${lc.forbidden.length} forbidden license(s)  (strong copyleft)`));
                            for (const c of lc.forbidden) {
                                console.log(dim(`  ${c.license}  ${c.name}@${c.version}`));
                            }
                        }
                        if (lc.restricted.length > 0) {
                            console.log(warn(`${lc.restricted.length} restricted license(s)  (weak copyleft — review required)`));
                            for (const c of lc.restricted) {
                                console.log(dim(`  ${c.license}  ${c.name}@${c.version}`));
                            }
                        }
                        console.log(dim(`License score ${lc.score}/100`));
                    }
                }

                // ── AI remediation advice ─────────────────────────────────────
                if (opts.explain && stats.vulnerabilities > 0) {
                    if (!process.env.DEEPSEEK_API_KEY) {
                        console.log(warn('--explain requires DEEPSEEK_API_KEY to be set'));
                    } else {
                        process.stdout.write('\n  \x1b[2mAsking DeepSeek for remediation advice…\x1b[0m\n');
                        try {
                            const kevSet = await fetchKEVSet().catch(() => null);
                            const advice = await explainVulnerabilities(result.components, repoName, kevSet);
                            if (advice) {
                                console.log('\n\x1b[1m  AI Remediation Advice\x1b[0m');
                                console.log('  ' + '─'.repeat(50));
                                for (const line of advice.split('\n')) {
                                    console.log('  ' + line);
                                }
                            }
                        } catch (e) {
                            console.log(warn(`AI explain failed: ${e.message}`));
                        }
                    }
                } else if (opts.explain && stats.vulnerabilities === 0) {
                    console.log(ok('No vulnerabilities to explain'));
                }

                console.log('');

                let exitCode = 0;
                if (stats.critical > 0) exitCode = 1;
                if (opts.licenseCheck && stats.licenseCompliance.forbidden.length > 0) exitCode = 1;
                if (exitCode) process.exit(exitCode);
            }

        } catch (err) {
            if (!opts.json) {
                console.error(`\n  \x1b[31mError:\x1b[0m ${err.message}\n`);
            } else {
                console.error(JSON.stringify({ error: err.message }));
            }
            process.exit(2);
        } finally {
            if (cleanup) cleanup();
        }
    });

program.parse();
