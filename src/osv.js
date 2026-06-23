'use strict';

/**
 * OSV (Open Source Vulnerabilities) enricher.
 * https://osv.dev/docs/
 *
 * Batches all components into a single POST to the OSV batch API.
 * Results are attached to components in-place.
 *
 * Ecosystem mapping: our internal names -> OSV ecosystem names.
 */

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_ECOSYSTEM = {
    npm:    'npm',
    pypi:   'PyPI',
    cargo:  'crates.io',
    golang: 'Go',
};

/**
 * Enrich an array of components with vulnerability data from OSV.
 * Modifies components in place, adds `vulnerabilities` array.
 *
 * @param {object[]} components
 * @param {{ timeout?: number }} [opts]
 */
async function enrichWithOSV(components, opts = {}) {
    const timeout = opts.timeout || 10_000;

    // Only query ecosystems we know how to map
    const queryable = components.filter((c) => OSV_ECOSYSTEM[c.ecosystem]);
    if (queryable.length === 0) return;

    // OSV batch limit is 1000 queries per request
    for (let i = 0; i < queryable.length; i += 1000) {
        const batch = queryable.slice(i, i + 1000);
        await queryBatch(batch, timeout);
    }
}

async function queryBatch(components, timeout) {
    const queries = components.map((comp) => ({
        version: comp.version,
        package: {
            name: osvName(comp),
            ecosystem: OSV_ECOSYSTEM[comp.ecosystem],
        },
    }));

    const body = JSON.stringify({ queries });

    let res;
    try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeout);
        res = await fetch(OSV_BATCH_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body,
            signal: controller.signal,
        });
        clearTimeout(timer);
    } catch (err) {
        console.warn(`[packrai] OSV query failed: ${err.message} — continuing without vulnerability data`);
        return;
    }

    if (!res.ok) {
        console.warn(`[packrai] OSV API returned ${res.status} — continuing without vulnerability data`);
        return;
    }

    const data = await res.json();
    const results = data.results || [];

    for (let i = 0; i < components.length; i++) {
        const vulns = (results[i] && results[i].vulns) || [];
        if (vulns.length > 0) {
            components[i].vulnerabilities = vulns.map((v) => ({
                id: v.id,
                aliases: v.aliases || [],
                summary: v.summary || '',
                severity: extractSeverity(v),
                cvss: extractCVSS(v),
                fixedIn: extractFixes(v, components[i].name),
                url: `https://osv.dev/vulnerability/${v.id}`,
            }));
        } else {
            components[i].vulnerabilities = [];
        }
    }
}

function osvName(comp) {
    // PyPI names are case-insensitive and normalised to lowercase with hyphens
    if (comp.ecosystem === 'pypi') return comp.name.replace(/_/g, '-').toLowerCase();
    return comp.name;
}

function extractSeverity(vuln) {
    if (!vuln.severity || vuln.severity.length === 0) return 'UNKNOWN';
    // Prefer CVSS_V3 over CVSS_V2
    const v3 = vuln.severity.find((s) => s.type === 'CVSS_V3');
    const v2 = vuln.severity.find((s) => s.type === 'CVSS_V2');
    const s = v3 || v2;
    if (!s) return 'UNKNOWN';
    const score = parseFloat(s.score);
    if (isNaN(score)) return 'UNKNOWN';
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    return 'LOW';
}

function extractCVSS(vuln) {
    if (!vuln.severity || vuln.severity.length === 0) return null;
    const v3 = vuln.severity.find((s) => s.type === 'CVSS_V3');
    return v3 ? v3.score : null;
}

function extractFixes(vuln, pkgName) {
    const fixes = [];
    for (const affected of (vuln.affected || [])) {
        for (const range of (affected.ranges || [])) {
            for (const event of (range.events || [])) {
                if (event.fixed) fixes.push(event.fixed);
            }
        }
    }
    return [...new Set(fixes)]; // dedupe
}

module.exports = { enrichWithOSV };
