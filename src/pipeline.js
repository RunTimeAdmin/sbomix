'use strict';

/**
 * Main SBOM generation pipeline.
 *
 * Input:  a local directory (or GitHub owner/repo@tag)
 * Output: { cyclonedx: object, spdx: object, components: [], stats: {} }
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { detect } = require('./parsers/detect');
const { parseLockFile } = require('./parsers/index');
const { enrichWithOSV } = require('./osv');
const { generateCycloneDX } = require('./generators/cyclonedx');
const { generateSPDX } = require('./generators/spdx');

/**
 * Generate SBOMs from a local directory.
 *
 * @param {string} dir         - local path containing lock files
 * @param {object} opts
 * @param {string} [opts.name]     - project name (default: basename of dir)
 * @param {string} [opts.version] - version / tag
 * @param {string} [opts.author]  - org or author name
 * @param {boolean} [opts.vulns]  - run OSV enrichment (default: true)
 * @param {boolean} [opts.recursive] - walk subdirs for monorepos (default: true)
 */
async function generateFromDirectory(dir, opts = {}) {
    const startMs = Date.now();
    const name = opts.name || path.basename(dir);
    const version = opts.version || 'unknown';
    const runVulns = opts.vulns !== false;

    // 1. Detect lock files
    const lockFiles = detect(dir, { recursive: opts.recursive !== false });
    if (lockFiles.length === 0) {
        throw new Error(`No supported lock files found in ${dir}.\n`
            + 'Expected one of: package-lock.json, yarn.lock, poetry.lock, Pipfile.lock, Cargo.lock, go.mod');
    }

    // 2. Parse all lock files
    const allComponents = [];
    const ecosystemsFound = new Set();
    for (const lf of lockFiles) {
        const comps = parseLockFile(lf);
        allComponents.push(...comps);
        ecosystemsFound.add(lf.ecosystem);
    }

    // 3. Enrich with vulnerability data (parallel OSV batch)
    if (runVulns && allComponents.length > 0) {
        await enrichWithOSV(allComponents);
    }

    // 4. Generate both formats
    const meta = { name, version, author: opts.author };
    const cyclonedx = generateCycloneDX(allComponents, meta);
    const spdx = generateSPDX(allComponents, meta);

    const elapsedMs = Date.now() - startMs;
    const vulnCount = allComponents.reduce((n, c) => n + (c.vulnerabilities ? c.vulnerabilities.length : 0), 0);
    const criticalCount = allComponents.reduce((n, c) =>
        n + (c.vulnerabilities || []).filter((v) => v.severity === 'CRITICAL').length, 0);

    return {
        cyclonedx,
        spdx,
        components: allComponents,
        stats: {
            totalComponents: allComponents.length,
            ecosystems: [...ecosystemsFound],
            lockFilesScanned: lockFiles.map((lf) => lf.path),
            vulnerabilities: vulnCount,
            critical: criticalCount,
            elapsedMs,
        },
    };
}

/**
 * Write SBOM output files to a directory.
 *
 * @param {object} result   - from generateFromDirectory
 * @param {string} outDir   - directory to write to
 * @returns {{ cyclonedxPath, spdxPath }}
 */
function writeOutputs(result, outDir) {
    fs.mkdirSync(outDir, { recursive: true });
    const cdxPath = path.join(outDir, 'bom.cyclonedx.json');
    const spdxPath = path.join(outDir, 'bom.spdx.json');
    fs.writeFileSync(cdxPath, JSON.stringify(result.cyclonedx, null, 2));
    fs.writeFileSync(spdxPath, JSON.stringify(result.spdx, null, 2));
    return { cyclonedxPath: cdxPath, spdxPath };
}

module.exports = { generateFromDirectory, writeOutputs };
