'use strict';

/**
 * Main SBOM generation pipeline.
 *
 * Input:  a local directory (or GitHub owner/repo@tag)
 * Output: { cyclonedx: object, spdx: object, components: [], stats: {} }
 */

const fs = require('fs');
const path = require('path');
const { detect } = require('./parsers/detect');
const { parseLockFile } = require('./parsers/index');
const { enrichWithOSV } = require('./osv');
const { enrichWithLicenses } = require('./licenses');
const { generateCycloneDX, validateCycloneDX } = require('./generators/cyclonedx');
const { generateSPDX } = require('./generators/spdx');
const { assessLicenses } = require('./licensePolicy');

/**
 * Generate SBOMs from a local directory.
 *
 * @param {string} dir         - local path containing lock files
 * @param {object} opts
 * @param {string} [opts.name]     - project name (default: basename of dir)
 * @param {string} [opts.version] - version / tag
 * @param {string} [opts.author]  - org or author name
 * @param {boolean} [opts.vulns]     - run OSV vulnerability enrichment (default: true)
 * @param {boolean} [opts.licenses]  - run deps.dev license enrichment (default: true)
 * @param {boolean} [opts.recursive] - walk subdirs for monorepos (default: true)
 * @param {string}  [opts.format]    - 'both' | 'cyclonedx' | 'spdx' (default: 'both')
 */
async function generateFromDirectory(dir, opts = {}) {
    const startMs = Date.now();
    const name = opts.name || path.basename(dir);
    const version = opts.version || 'unknown';
    const runVulns    = opts.vulns    !== false;
    const runLicenses = opts.licenses !== false;
    const fmt = opts.format || 'both';
    const wantCDX  = fmt !== 'spdx';
    const wantSPDX = fmt !== 'cyclonedx';

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

    // 3. Parallel enrichment — license and vulnerability data
    await Promise.all([
        runLicenses && allComponents.length > 0 ? enrichWithLicenses(allComponents) : null,
        runVulns    && allComponents.length > 0 ? enrichWithOSV(allComponents)      : null,
    ]);

    // 4. Generate only requested formats
    const meta = { name, version, author: opts.author };
    let cyclonedx, spdx;

    if (wantCDX) {
        cyclonedx = generateCycloneDX(allComponents, meta);
        const cdxCheck = validateCycloneDX(cyclonedx);
        if (!cdxCheck.valid) {
            throw new Error(`CycloneDX generator produced invalid output: ${cdxCheck.errors.join('; ')}`);
        }
    }
    if (wantSPDX) {
        spdx = generateSPDX(allComponents, meta);
    }

    const elapsedMs = Date.now() - startMs;
    const { vulnCount, criticalCount } = countVulns(allComponents);
    const licenseCompliance = assessLicenses(allComponents);

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
            qualityScore: computeQualityScore(allComponents, lockFiles),
            licenseCompliance,
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

/**
 * Score 0-100 measuring SBOM completeness against CISA 2025 minimum elements.
 *
 * 25 pts  — all components have a valid purl
 * 25 pts  — all components have at least one hash
 * 25 pts  — all components have a known license (not NOASSERTION)
 * 25 pts  — all lock files are high-fidelity (not requirements.txt fallbacks)
 */
function countVulns(components) {
    let vulnCount = 0, criticalCount = 0;
    for (const c of components) {
        for (const v of (c.vulnerabilities || [])) {
            vulnCount++;
            if (v.severity === 'CRITICAL') criticalCount++;
        }
    }
    return { vulnCount, criticalCount };
}

function computeQualityScore(components, lockFiles) {
    if (!components.length) return 0;

    const NOASSERT = new Set(['NOASSERTION', 'UNKNOWN', null, undefined, '']);
    let withPurl = 0, withHash = 0, withLicense = 0;

    for (const c of components) {
        if (c.purl && !c.purl.includes('NOASSERTION')) withPurl++;
        if (c.hashes?.length) withHash++;
        if (c.licenses?.length && !NOASSERT.has(c.licenses[0])) withLicense++;
    }

    const weakCount = lockFiles.filter((lf) => lf.type === 'requirements-txt').length;
    const strongFraction = lockFiles.length > 0
        ? (lockFiles.length - weakCount) / lockFiles.length
        : 1;

    return Math.round(
        25 * (withPurl    / components.length) +
        25 * (withHash    / components.length) +
        25 * (withLicense / components.length) +
        25 * strongFraction
    );
}

module.exports = { generateFromDirectory, writeOutputs };
