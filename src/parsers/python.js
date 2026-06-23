'use strict';

/**
 * Python lock file parser.
 * Handles: poetry.lock (TOML), Pipfile.lock (JSON), requirements.txt (best-effort).
 *
 * requirements.txt WARNING: it is NOT a lock file — no transitive deps are
 * captured unless it was produced by `pip freeze`. We parse it but flag it.
 */

const fs = require('fs');
const { parse: parseToml } = require('smol-toml');
const { createComponent, makePurl } = require('../component');

// ── poetry.lock ───────────────────────────────────────────────────────────────

function parsePoetryLock(filePath) {
    const raw = fs.readFileSync(filePath, 'utf8');
    const data = parseToml(raw);
    const packages = data.package || [];

    // Build name->version map for dep resolution
    const nameToVersion = new Map();
    for (const pkg of packages) {
        nameToVersion.set(pkg.name.toLowerCase(), pkg.version);
    }

    return packages.map((pkg) => {
        const deps = pkg.dependencies || {};
        const dependsOn = Object.keys(deps)
            .filter((d) => d.toLowerCase() !== 'python')
            .map((d) => {
                const v = nameToVersion.get(d.toLowerCase()) || '*';
                return makePurl('pypi', d, v);
            });

        const licenses = [];
        if (pkg.license) licenses.push(pkg.license);

        return createComponent({
            name: pkg.name,
            version: pkg.version,
            ecosystem: 'pypi',
            scope: pkg.optional ? 'optional' : 'required',
            licenses,
            description: pkg.description || '',
            homepage: (pkg.homepage) || '',
            dependsOn,
        });
    });
}

// ── Pipfile.lock ──────────────────────────────────────────────────────────────

function parsePipfileLock(filePath) {
    const raw = fs.readFileSync(filePath, 'utf8');
    const data = JSON.parse(raw);
    const components = [];

    for (const [scope, pkgs] of [['required', data.default || {}], ['dev', data.develop || {}]]) {
        for (const [name, info] of Object.entries(pkgs)) {
            if (name === '_meta') continue;
            const version = (info.version || '').replace(/^==/, '');
            if (!version) continue;

            const hashes = (info.hashes || []).map((h) => {
                const m = h.match(/^(sha\d+):(.+)$/i);
                if (!m) return null;
                const algMap = { sha256: 'SHA-256', sha384: 'SHA-384', sha512: 'SHA-512' };
                return { alg: algMap[m[1].toLowerCase()] || m[1].toUpperCase(), content: m[2] };
            }).filter(Boolean);

            components.push(createComponent({
                name,
                version,
                ecosystem: 'pypi',
                scope,
                hashes,
            }));
        }
    }

    return components;
}

// ── requirements.txt (best-effort) ───────────────────────────────────────────

function parseRequirementsTxt(filePath) {
    console.warn('[packrai] requirements.txt is not a lock file — transitive deps will be missing. '
        + 'Use poetry.lock or Pipfile.lock for complete SBOM coverage.');

    const raw = fs.readFileSync(filePath, 'utf8');
    const components = [];

    for (const line of raw.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;

        // Handle: name==version, name>=version (best effort: take first version)
        const m = trimmed.match(/^([A-Za-z0-9_.\-[\]]+)\s*[=~><!\s]+\s*([0-9][0-9a-zA-Z.\-*+!]*).*$/);
        if (!m) continue;

        components.push(createComponent({
            name: m[1].split('[')[0], // strip extras like [security]
            version: m[2],
            ecosystem: 'pypi',
        }));
    }

    return components;
}

module.exports = { parsePoetryLock, parsePipfileLock, parseRequirementsTxt };
