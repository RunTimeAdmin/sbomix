'use strict';

/**
 * License enrichment via the deps.dev API.
 * Fills in `component.license` for any component where it's missing or NOASSERTION.
 *
 * API: https://api.deps.dev/v3/systems/{system}/packages/{name}/versions/{version}
 * Covers: npm, pypi, cargo, go, maven — one unified source.
 */

const SYSTEM_MAP = {
    npm:    'npm',
    pypi:   'pypi',
    cargo:  'cargo',
    golang: 'go',
    maven:  'maven',
};

const BASE_URL    = 'https://api.deps.dev/v3/systems';
const CONCURRENCY = 10;
const TIMEOUT_MS  = 8_000;

const UNKNOWN = new Set([null, undefined, 'NOASSERTION', 'UNKNOWN', '']);

/**
 * Enrich components with license data from deps.dev.
 * Mutates components in place — only updates those with missing/unknown licenses.
 *
 * @param {object[]} components
 * @param {{ timeout?: number }} [opts]
 */
async function enrichWithLicenses(components, opts = {}) {
    const timeout = opts.timeout ?? TIMEOUT_MS;

    // Only target components that need enrichment
    const targets = components.filter((c) => UNKNOWN.has(c.license));
    if (targets.length === 0) return;

    // Deduplicate by (ecosystem, name, version) — update all matching components
    const keyMap = new Map();
    for (const c of targets) {
        const system = SYSTEM_MAP[c.ecosystem];
        if (!system) continue;
        const key = `${system}:${c.name}@${c.version}`;
        if (!keyMap.has(key)) keyMap.set(key, { system, name: c.name, version: c.version, comps: [] });
        keyMap.get(key).comps.push(c);
    }

    const entries = [...keyMap.values()];

    // Process in parallel chunks
    for (let i = 0; i < entries.length; i += CONCURRENCY) {
        const chunk = entries.slice(i, i + CONCURRENCY);
        await Promise.all(chunk.map(async ({ system, name, version, comps }) => {
            try {
                const license = await fetchLicense(system, name, version, timeout);
                if (license) {
                    for (const c of comps) c.license = license;
                }
            } catch {
                // Network failure — leave license as NOASSERTION, don't crash
            }
        }));
    }
}

async function fetchLicense(system, name, version, timeout) {
    // Encode name segments individually (preserve `/` separators for Go modules and Maven)
    const encodedName = name.split('/').map(encodeURIComponent).join('/');
    const encodedVer  = encodeURIComponent(version);
    const url = `${BASE_URL}/${system}/packages/${encodedName}/versions/${encodedVer}`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
        const res = await fetch(url, {
            signal: controller.signal,
            headers: { 'User-Agent': 'packrai/0.1 (https://packrai.xyz)' },
        });
        if (!res.ok) return null;

        const data = await res.json();

        // deps.dev v3 response: { licenses: ['MIT', ...] }
        const licenses = data.licenses;
        if (Array.isArray(licenses) && licenses.length > 0) {
            return licenses.join(' AND ');
        }
        return null;
    } finally {
        clearTimeout(timer);
    }
}

module.exports = { enrichWithLicenses };
