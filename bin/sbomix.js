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
 *   --aibom-format <fmt>    json | yaml  (default: json)
 *   --profile <name>        crypto-agent — adds an Agent Trust Report (MCP tool surface,
 *                            signing-surface, known-bad match) as agent-trust-report.json/.html
 *   --license-check         flag forbidden/restricted licenses; exit 1 if any found
 *   --json                  machine-readable JSON summary to stdout
 *   --push                  push SBOM to SBOMix API (requires --api-key or $SBOMIX_API_KEY)
 *   --api-key <key>         SBOMix API key (or set $SBOMIX_API_KEY)
 *   --api-url <url>         SBOMix API base URL (or set $SBOMIX_API_URL)
 */

const { Command, program } = require('commander');
const path  = require('path');
const fs    = require('fs');
const { generateFromDirectory, writeOutputs } = require('../src/pipeline');
const { diffCycloneDX } = require('../src/diff');
const { explainVulnerabilities } = require('../src/explain');
const { fetchKEVSet }            = require('../src/kev');
const { isGitHubTarget, parseGitHubTarget, cloneRepo } = require('../src/github');
const { buildAgentTrustReport, renderAgentTrustReportHTML } = require('../src/agentTrustReport');
const pkg = require('../package.json');

const VALID_PROFILES = new Set(['crypto-agent']);

const DEFAULT_API_URL = 'https://api.sbomix.com';

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

// ── push helper ───────────────────────────────────────────────────────────────
async function pushSbom(result, { apiUrl, apiKey, appName, version, commit, branch }) {
    const targetUrl = new URL('/api/v1/ingest', apiUrl);
    const protocol  = require(targetUrl.protocol === 'https:' ? 'https' : 'http');
    const payload   = JSON.stringify({
        app:       appName,
        version,
        commit:    commit || undefined,
        branch:    branch || undefined,
        cyclonedx: result.cyclonedx,
        spdx:      result.spdx,
        aibom:     result.aiBom,
        stats:     result.stats,
    });

    return new Promise((resolve, reject) => {
        const req = protocol.request({
            hostname: targetUrl.hostname,
            port:     targetUrl.port || undefined,
            path:     targetUrl.pathname,
            method:   'POST',
            headers:  {
                'Content-Type':   'application/json',
                'Authorization':  `Bearer ${apiKey}`,
                'Content-Length': Buffer.byteLength(payload),
            },
        }, (res) => {
            let body = '';
            res.on('data', (d) => body += d);
            res.on('end', () => {
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    try { resolve(JSON.parse(body)); } catch { resolve({}); }
                } else {
                    reject(new Error(`${res.statusCode}: ${body.slice(0, 200)}`));
                }
            });
        });
        req.on('error', reject);
        req.write(payload);
        req.end();
    });
}

// ── scan (default) command ────────────────────────────────────────────────────
program
    .name('sbomix')
    .description('Generate accurate SBOMs from any GitHub repo or local directory')
    .version(pkg.version)
    .argument('<source>', 'Local path  OR  owner/repo[@ref]  OR  GitHub URL')
    .option('-o, --out <dir>',          'Output directory',                        '.')
    .option('-n, --name <name>',        'Project name (default: repo / dir name)')
    .option('-v, --ver <version>',      'Project version (default: tag or unknown)')
    .option('-a, --author <org>',       'Author or organisation name')
    .option('--token <token>',          'GitHub token for private repos (or set $GITHUB_TOKEN)')
    .option('--no-vulns',               'Skip OSV vulnerability enrichment')
    .option('--no-licenses',            'Skip deps.dev license enrichment')
    .option('--no-recursive',           'Do not recurse into subdirectories')
    .option('--no-docker',              'Skip Dockerfile audit')
    .option('--format <fmt>',           'Output format: both|cyclonedx|spdx',      'both')
    .option('--aibom-format <fmt>',     'AI-BOM format: json|yaml',                'json')
    .option('--profile <name>',         'Report profile: crypto-agent (adds signing-surface + MCP tool-surface report)')
    .option('--license-check',          'Flag forbidden/restricted licenses; exit 1 if any found')
    .option('--explain',                'AI remediation advice (requires EXPLAIN_API_KEY; defaults to Claude Haiku)')
    .option('--json',                   'Print summary as JSON (machine-readable)')
    .option('--push',                   'Push SBOM to SBOMix API (requires --api-key or $SBOMIX_API_KEY)')
    .option('--api-key <key>',          'SBOMix API key (or set $SBOMIX_API_KEY)')
    .option('--api-url <url>',          'SBOMix API base URL',                    DEFAULT_API_URL)
    .action(async (source, opts) => {
        let scanDir   = null;
        let cleanup   = null;
        let repoName  = opts.name  || null;
        let repoVer   = opts.ver   || null;
        let commitSha = null;

        const ok   = (s) => `\x1b[32m✓\x1b[0m ${s}`;
        const warn = (s) => `\x1b[33m⚠\x1b[0m ${s}`;
        const err  = (s) => `\x1b[31m✖\x1b[0m ${s}`;
        const dim  = (s) => `  \x1b[2m${s}\x1b[0m`;

        if (opts.profile && !VALID_PROFILES.has(opts.profile)) {
            console.error(`\n  \x1b[31mError:\x1b[0m Unknown profile '${opts.profile}'. Valid profiles: ${[...VALID_PROFILES].join(', ')}\n`);
            process.exit(2);
        }

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
            const written = writeOutputs(result, outDir, { aibomFormat: opts.aibomFormat });

            let agentTrustPaths = null;
            if (opts.profile === 'crypto-agent') {
                const report = buildAgentTrustReport(result, {
                    name: repoName, version: repoVer, scanTarget: source, commitSha, scanDir,
                });
                const jsonPath = path.join(outDir, 'agent-trust-report.json');
                const htmlPath = path.join(outDir, 'agent-trust-report.html');
                fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2));
                fs.writeFileSync(htmlPath, renderAgentTrustReportHTML(report));
                agentTrustPaths = { json: jsonPath, html: htmlPath, summary: report.execSummary };
            }

            if (opts.json) {
                console.log(JSON.stringify({
                    ...stats,
                    commitSha,
                    outputs: {
                        cyclonedx: written.cyclonedxPath,
                        spdx:      written.spdxPath,
                        aibom:     written.aibomPath,
                        agentTrustReport: agentTrustPaths ? { json: agentTrustPaths.json, html: agentTrustPaths.html } : undefined,
                    },
                }, null, 2));
            } else {
                console.log(ok(`${stats.totalComponents} components  ·  ${stats.ecosystems.join(', ')}`));
                if (written.cyclonedxPath) console.log(ok(`CycloneDX 1.6  →  ${written.cyclonedxPath}`));
                if (written.spdxPath)      console.log(ok(`SPDX 2.3       →  ${written.spdxPath}`));
                if (written.aibomPath)     console.log(ok(`AI-BOM         →  ${written.aibomPath}`));

                if (stats.vulnerabilities === 0) {
                    console.log(ok('0 known vulnerabilities'));
                } else if (stats.critical > 0) {
                    console.log(warn(`${stats.vulnerabilities} vulnerabilities  (${stats.critical} CRITICAL)`));
                } else {
                    console.log(warn(`${stats.vulnerabilities} vulnerabilities`));
                }

                if (stats.aiModels > 0) {
                    if (stats.aiCritical > 0) {
                        console.log(err(`${stats.aiModels} AI model(s)  ·  ${stats.aiCritical} critical threat(s)`));
                    } else if (stats.aiThreats > 0) {
                        console.log(warn(`${stats.aiModels} AI model(s)  ·  ${stats.aiThreats} threat(s)`));
                    } else {
                        console.log(ok(`${stats.aiModels} AI model(s) detected`));
                    }
                }

                console.log(ok(`Quality score  ${stats.qualityScore}/100`));

                // ── Agent Trust Report (crypto-agent profile) ─────────────────
                if (agentTrustPaths) {
                    const s = agentTrustPaths.summary;
                    const critFlags = s.flags.filter((f) => f.severity === 'Critical').length;
                    console.log('');
                    const label = critFlags > 0 ? err : (s.flags.length > 0 ? warn : ok);
                    console.log(label(`Agent Trust Report  ·  ${s.mcpServersDetected} MCP server(s)  ·  signing surface: ${s.signingSurfaceDetected ? 'yes' : 'no'}  ·  ${s.flags.length} flag(s)`));
                    console.log(ok(`Agent Trust Report  →  ${agentTrustPaths.html}`));
                }

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
                    const explainReady = process.env.EXPLAIN_API_KEY ||
                        (process.env.EXPLAIN_BASE_URL || '').includes('localhost') ||
                        (process.env.EXPLAIN_BASE_URL || '').includes('127.0.0.1');
                    if (!explainReady) {
                        console.log(warn('--explain requires EXPLAIN_API_KEY (Anthropic Claude by default). See https://sbomix.com/docs/explain'));
                    } else {
                        process.stdout.write('\n  \x1b[2mAsking AI for remediation advice…\x1b[0m\n');
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
            }

            // ── Push to API ───────────────────────────────────────────────────
            if (opts.push) {
                const apiKey = opts.apiKey || process.env.SBOMIX_API_KEY;
                const apiUrl = opts.apiUrl || process.env.SBOMIX_API_URL || DEFAULT_API_URL;
                if (!apiKey) {
                    if (!opts.json) console.log(warn('--push requires --api-key or $SBOMIX_API_KEY'));
                } else {
                    try {
                        const pushed = await pushSbom(result, {
                            apiUrl, apiKey,
                            appName: repoName,
                            version: repoVer,
                            commit:  commitSha,
                            branch:  null,
                        });
                        if (!opts.json) {
                            const ref = pushed.sbomId || pushed.scanId || 'accepted';
                            console.log(ok(`Pushed to ${apiUrl}  →  ${ref}`));
                        }
                    } catch (e) {
                        if (!opts.json) console.log(warn(`Push failed: ${e.message}`));
                        else process.stderr.write(JSON.stringify({ pushError: e.message }) + '\n');
                    }
                }
            }

            let exitCode = 0;
            if (stats.critical > 0) exitCode = 1;
            if (opts.licenseCheck && stats.licenseCompliance?.forbidden?.length > 0) exitCode = 1;
            if (exitCode && !opts.json) process.exit(exitCode);

        } catch (error) {
            if (!opts.json) {
                console.error(`\n  \x1b[31mError:\x1b[0m ${error.message}\n`);
            } else {
                console.error(JSON.stringify({ error: error.message }));
            }
            process.exit(2);
        } finally {
            if (cleanup) cleanup();
        }
    });

program.parse();
