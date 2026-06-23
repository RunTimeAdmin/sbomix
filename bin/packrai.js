#!/usr/bin/env node
'use strict';

/**
 * PackrAI CLI
 * Usage:
 *   packrai <dir>                        generate SBOM from local directory
 *   packrai <dir> --out <outdir>         write to specific output directory
 *   packrai <dir> --name foo --ver 1.2.0 set project name and version
 *   packrai <dir> --no-vulns            skip OSV vulnerability lookup
 *   packrai <dir> --format cyclonedx    output only CycloneDX (default: both)
 */

const { program } = require('commander');
const path = require('path');
const { generateFromDirectory, writeOutputs } = require('../src/pipeline');
const pkg = require('../package.json');

program
    .name('packrai')
    .description('Generate accurate SBOMs from any project directory')
    .version(pkg.version)
    .argument('<dir>', 'Project directory containing lock files')
    .option('-o, --out <dir>', 'Output directory', '.')
    .option('-n, --name <name>', 'Project name (default: directory name)')
    .option('-v, --ver <version>', 'Project version')
    .option('-a, --author <author>', 'Project author or organisation')
    .option('--no-vulns', 'Skip OSV vulnerability enrichment')
    .option('--no-recursive', 'Do not recurse into subdirectories')
    .option('--format <fmt>', 'Output format: both|cyclonedx|spdx (default: both)', 'both')
    .option('--json', 'Print summary as JSON (machine-readable)')
    .action(async (dir, opts) => {
        const absDir = path.resolve(dir);

        try {
            process.stdout.write(`\n  packrai v${pkg.version}\n`);
            process.stdout.write(`  Scanning ${absDir}\n\n`);

            const result = await generateFromDirectory(absDir, {
                name: opts.name,
                version: opts.ver,
                author: opts.author,
                vulns: opts.vulns,
                recursive: opts.recursive,
            });

            const { stats } = result;
            const outDir = path.resolve(opts.out);

            const written = {};
            if (opts.format !== 'spdx') written.cyclonedx = path.join(outDir, 'bom.cyclonedx.json');
            if (opts.format !== 'cyclonedx') written.spdx = path.join(outDir, 'bom.spdx.json');

            // Write requested formats
            const fs = require('fs');
            require('fs').mkdirSync(outDir, { recursive: true });
            if (written.cyclonedx) fs.writeFileSync(written.cyclonedx, JSON.stringify(result.cyclonedx, null, 2));
            if (written.spdx)      fs.writeFileSync(written.spdx,      JSON.stringify(result.spdx, null, 2));

            if (opts.json) {
                console.log(JSON.stringify({ ...stats, outputs: written }, null, 2));
                return;
            }

            // Human-readable summary
            const vuln = stats.vulnerabilities;
            const crit = stats.critical;
            const ok = (s) => `\x1b[32m✓\x1b[0m ${s}`;
            const warn = (s) => `\x1b[33m⚠\x1b[0m ${s}`;
            const info = (s) => `  \x1b[2m${s}\x1b[0m`;

            console.log(ok(`${stats.totalComponents} components across ${stats.ecosystems.join(', ')}`));
            if (written.cyclonedx) console.log(ok(`CycloneDX 1.6  →  ${written.cyclonedx}`));
            if (written.spdx)      console.log(ok(`SPDX 2.3       →  ${written.spdx}`));

            if (vuln === 0) {
                console.log(ok('0 known vulnerabilities'));
            } else if (crit > 0) {
                console.log(warn(`${vuln} vulnerabilities (${crit} CRITICAL)`));
            } else {
                console.log(warn(`${vuln} vulnerabilities`));
            }

            console.log(info(`${stats.lockFilesScanned.length} lock file(s) scanned in ${stats.elapsedMs}ms`));
            console.log('');

            if (crit > 0) process.exit(1); // non-zero exit for CI gating

        } catch (err) {
            console.error(`\n  \x1b[31mError:\x1b[0m ${err.message}\n`);
            process.exit(1);
        }
    });

program.parse();
