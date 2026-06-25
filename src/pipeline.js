'use strict';

/**
 * Main SBOM generation pipeline.
 *
 * Input:  a local directory (or GitHub owner/repo@tag)
 * Output: { cyclonedx: object, spdx: object, components: [], stats: {} }
 */

const fs = require('fs');
const path = require('path');
const { detect, detectDockerfiles } = require('./parsers/detect');
const { parseLockFile } = require('./parsers/index');
const { parseDockerfile } = require('./parsers/dockerfile');
const { fetchBaseImageVulns } = require('./basevuln');
const { enrichWithOSV } = require('./osv');
const { enrichWithLicenses } = require('./licenses');
const { generateCycloneDX, validateCycloneDX } = require('./generators/cyclonedx');
const { generateSPDX } = require('./generators/spdx');
const { assessLicenses } = require('./licensePolicy');
const { detectAILocal, enrichAIComponents, finalizeAIResult } = require('./aibom');
const { buildAIBomDocument, attachToCycloneDX } = require('./ai/document');

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
 * @param {boolean} [opts.docker]    - audit Dockerfiles and include base images (default: true)
 * @param {boolean} [opts.aibom]     - detect AI/ML components and assess threats (default: true)
 * @param {boolean} [opts.aibomEnrich] - run HuggingFace Hub enrichment for AI components
 *                                        (network). Defaults to opts.vulns — off on fast scans.
 * @param {object}  [opts.signingKeys] - { classicalPrivateKey, classicalPublicKey, pqcPrivateKey?, pqcPublicKey? }
 *                                        when present, the AI BOM lineage is cryptographically signed
 */
async function generateFromDirectory(dir, opts = {}) {
    const startMs = Date.now();
    const name = opts.name || path.basename(dir);
    const version = opts.version || 'unknown';
    const runVulns    = opts.vulns    !== false;
    const runLicenses = opts.licenses !== false;
    const runDocker   = opts.docker   !== false;
    const runAIBOM    = opts.aibom    !== false;
    // AI Hub enrichment is network-bound — defaults to follow vulns (off on the
    // server fast-scan path), so local detection alone keeps the hot path fast.
    const runAIEnrich = opts.aibomEnrich !== undefined ? opts.aibomEnrich : runVulns;
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

    // 2b. AI BOM — LOCAL detection only (filesystem, no network). Fast hot path.
    //     Hub enrichment is deferred to the parallel block below, mirroring OSV.
    let aiLocal = null;
    let aiBOM   = { components: [], threats: [], stats: {} };
    if (runAIBOM) {
        try {
            const pypiComps = allComponents.filter((c) => c.ecosystem === 'pypi');
            // Weight hashing is local but I/O-heavy on large models — follow the
            // same gate as enrichment so the server fast scan stays fast.
            aiLocal = detectAILocal(dir, pypiComps, { hashWeights: runAIEnrich });
            allComponents.push(...aiLocal.components);
        } catch (e) {
            console.warn(`[packrai] AI BOM warning: ${e.message}`);
        }
    }

    // 2c. Dockerfile audit — runs independently of lock-file count
    const dockerfileAudit = [];
    if (runDocker) {
        const maxDepth = opts.recursive !== false ? 4 : 0;
        for (const df of detectDockerfiles(dir, { maxDepth })) {
            try {
                dockerfileAudit.push(parseDockerfile(df.path));
            } catch (e) {
                console.warn(`[packrai] Dockerfile parse warning (${df.path}): ${e.message}`);
            }
        }
    }

    // 3. Parallel enrichment — all network lookups fire concurrently:
    //    library OSV + licenses, container base-image CVEs, and AI Hub metadata.
    //    AI library components skip OSV/license (they're models, not packages).
    const libCompsForEnrich = allComponents.filter((c) => c.ecosystem !== 'ai' && c.ecosystem !== 'container');
    const baseVulnMap = new Map();
    await Promise.all([
        runLicenses && libCompsForEnrich.length > 0 ? enrichWithLicenses(libCompsForEnrich) : null,
        runVulns    && libCompsForEnrich.length > 0 ? enrichWithOSV(libCompsForEnrich)      : null,
        runDocker   ? fetchAllBaseVulns(dockerfileAudit, baseVulnMap)                        : null,
        (runAIBOM && runAIEnrich && aiLocal) ? enrichAIComponents(aiLocal.enrichTargets) : null,
    ]);

    // 3a. Finalize AI BOM result after enrichment (recomputes threat counts)
    if (aiLocal) aiBOM = finalizeAIResult(aiLocal);

    // 3b. Add container base images after enrichment — keeps them out of OSV/license
    //     lookups and the quality score calculation.
    for (const audit of dockerfileAudit) {
        for (const img of audit.baseImages) {
            const comp = makeContainerComponent(img);
            comp.vulnerabilities = baseVulnMap.get(img.raw) || [];
            allComponents.push(comp);
        }
    }

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

    // 4b. Assemble the AI BOM attestation: hash-chained lineage, optional PQC
    //     signature, and ISO 42001 / EU AI Act control mapping. Attach the
    //     signature + lineage reference to the CycloneDX BOM.
    let aiBomDocument = null;
    if (runAIBOM && aiBOM.components.length > 0) {
        try {
            aiBomDocument = buildAIBomDocument({
                aiComponents:   aiBOM.components,
                threats:        aiBOM.threats,
                meta,
                keys:           opts.signingKeys || null,
                agentic:        aiBOM.agentic || null,
            });
            if (cyclonedx) attachToCycloneDX(cyclonedx, aiBomDocument);
        } catch (e) {
            console.warn(`[packrai] AI BOM attestation warning: ${e.message}`);
        }
    }

    const elapsedMs = Date.now() - startMs;
    const libComponents = allComponents.filter((c) => c.ecosystem !== 'container' && c.ecosystem !== 'ai');
    const { vulnCount, criticalCount } = countVulns(libComponents);
    const licenseCompliance = assessLicenses(libComponents);

    const dockerFindings    = dockerfileAudit.reduce((acc, a) => acc + a.findings.length, 0);
    const dockerHigh        = dockerfileAudit.reduce((acc, a) => acc + a.summary.high, 0);
    const { vulnCount: baseVulnCount, criticalCount: baseCriticalCount } =
        countVulns(allComponents.filter((c) => c.ecosystem === 'container'));

    return {
        cyclonedx,
        spdx,
        components: allComponents,
        dockerfileAudit,
        aiThreats: aiBOM.threats,
        aiBom: aiBomDocument,
        stats: {
            totalComponents: allComponents.length,
            ecosystems: [...ecosystemsFound],
            lockFilesScanned: lockFiles.map((lf) => lf.path),
            dockerfilesScanned: dockerfileAudit.map((a) => a.path),
            vulnerabilities: vulnCount,
            critical: criticalCount,
            baseImageVulns: baseVulnCount,
            baseImageCritical: baseCriticalCount,
            qualityScore: computeQualityScore(allComponents, lockFiles),
            licenseCompliance,
            dockerFindings,
            dockerHigh,
            elapsedMs,
            // AI BOM stats
            aiModels:        aiBOM.stats.aiModels        ?? 0,
            aiApiProviders:  aiBOM.stats.apiProviders    ?? 0,
            aiFrameworks:    aiBOM.stats.frameworks      ?? 0,
            aiThreats:       aiBOM.stats.aiThreats       ?? 0,
            aiCritical:      aiBOM.stats.criticalThreats ?? 0,
            aiHigh:          aiBOM.stats.highThreats     ?? 0,
        },
    };
}

/**
 * Write SBOM output files to a directory.
 *
 * @param {object} result   - from generateFromDirectory
 * @param {string} outDir   - directory to write to
 * @param {object} [opts]
 * @param {string} [opts.aibomFormat] - 'json' | 'yaml' for the AI BOM (default: 'json')
 * @returns {{ cyclonedxPath, spdxPath, aibomPath }}
 */
function writeOutputs(result, outDir, opts = {}) {
    fs.mkdirSync(outDir, { recursive: true });
    const cdxPath  = path.join(outDir, 'bom.cyclonedx.json');
    const spdxPath = path.join(outDir, 'bom.spdx.json');
    if (result.cyclonedx) fs.writeFileSync(cdxPath,  JSON.stringify(result.cyclonedx, null, 2));
    if (result.spdx)      fs.writeFileSync(spdxPath, JSON.stringify(result.spdx,      null, 2));

    let aibomPath = null;
    if (result.aiBom) {
        const { serializeAIBom } = require('./ai/document');
        const fmt = (opts.aibomFormat || 'json').toLowerCase();
        const ext = (fmt === 'yaml' || fmt === 'yml') ? 'yaml' : 'json';
        aibomPath = path.join(outDir, `aibom.${ext}`);
        fs.writeFileSync(aibomPath, serializeAIBom(result.aiBom, fmt));
    }

    return {
        cyclonedxPath: result.cyclonedx ? cdxPath : null,
        spdxPath:      result.spdx ? spdxPath : null,
        aibomPath,
    };
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

async function fetchAllBaseVulns(audits, vulnMap) {
    // Deduplicate across Dockerfiles so a shared base image is only queried once
    const unique = [...new Map(
        audits.flatMap((a) => a.baseImages).map((i) => [i.raw, i])
    ).values()];

    await Promise.all(unique.map(async (img) => {
        try {
            const vulns = await fetchBaseImageVulns(img);
            if (vulns && vulns.length > 0) vulnMap.set(img.raw, vulns);
        } catch {
            // best-effort — never fail the pipeline
        }
    }));
}

function makeContainerComponent(img) {
    const tag     = img.tag || null;
    const digest  = img.digest || null;
    const version = tag || digest || 'unknown';
    // PURL spec: pkg:docker/<name>@<tag-or-digest>
    // Official Docker Hub images (no slash) are under the 'library' namespace
    const purlName = img.name.includes('/') ? img.name : `library/${img.name}`;
    const purl = `pkg:docker/${purlName}@${version}`;
    return {
        type: 'container',
        name: img.name,
        version,
        ecosystem: 'container',
        purl,
        scope: 'required',
        licenses: [],
        hashes: digest ? [{ alg: 'SHA-256', content: digest.replace('sha256:', '') }] : [],
        dependsOn: [],
        description: 'Docker base image',
        homepage: '',
        vulnerabilities: [],
    };
}

function computeQualityScore(components, lockFiles) {
    // Only score library components — container and AI components are tracked separately
    const libs = components.filter((c) => c.ecosystem !== 'container' && c.ecosystem !== 'ai');
    if (!libs.length) return 0;

    const NOASSERT = new Set(['NOASSERTION', 'UNKNOWN', null, undefined, '']);
    let withPurl = 0, withHash = 0, withLicense = 0;

    for (const c of libs) {
        if (c.purl && !c.purl.includes('NOASSERTION')) withPurl++;
        if (c.hashes?.length) withHash++;
        if (c.licenses?.length && !NOASSERT.has(c.licenses[0])) withLicense++;
    }

    const weakCount = lockFiles.filter((lf) => lf.type === 'requirements-txt').length;
    const strongFraction = lockFiles.length > 0
        ? (lockFiles.length - weakCount) / lockFiles.length
        : 1;

    return Math.round(
        25 * (withPurl    / libs.length) +
        25 * (withHash    / libs.length) +
        25 * (withLicense / libs.length) +
        25 * strongFraction
    );
}

module.exports = { generateFromDirectory, writeOutputs };
