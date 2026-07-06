'use strict';

const fs = require('fs');
const yaml = require('yaml');
const { createComponent, parseIntegritySRI } = require('../component');

/**
 * Parse pnpm-lock.yaml
 * Supports lockfileVersion 5.x, 6.x (pnpm 7-8), and 9.x (pnpm 9+)
 */
function parsePnpmLock(filePath) {
    const raw  = fs.readFileSync(filePath, 'utf8');
    const data = loadPnpmYaml(raw);
    const ver  = String(data.lockfileVersion || '6');
    const major = parseInt(ver.split('.')[0], 10);

    if (major >= 9) return parsePnpmV9(data);
    return parsePnpmV6(data);
}

// A pnpm-lock.yaml is usually one YAML document, but some real locks (e.g.
// pnpm's own repo) concatenate multiple lockfileVersion documents. yaml.parse()
// throws on those ("Source contains multiple documents"), so parse them all and
// merge the maps — losing no packages, and never aborting the scan.
function loadPnpmYaml(raw) {
    const docs = yaml.parseAllDocuments(raw)
        .map((d) => d.toJS())
        .filter((d) => d && typeof d === 'object');
    if (docs.length === 0) return {};
    if (docs.length === 1) return docs[0];

    const merged = {};
    for (const doc of docs) {
        for (const [k, v] of Object.entries(doc)) {
            if (v && typeof v === 'object' && !Array.isArray(v) && merged[k] && typeof merged[k] === 'object') {
                Object.assign(merged[k], v); // merge maps like packages / snapshots / importers
            } else if (merged[k] === undefined) {
                merged[k] = v;
            }
        }
    }
    return merged;
}

// ── v9 format (pnpm 9+) ────────────────────────────────────────────────────
// packages:  name@version → resolution metadata
// snapshots: name@version → resolved dependency graph
// importers: workspace paths → direct dep specs
function parsePnpmV9(data) {
    const packages   = data.packages   || {};
    const snapshots  = data.snapshots  || {};
    const importers  = data.importers  || { '.': data };
    const components = [];
    const purlMap    = {};   // "name@version" → purl

    // First pass: build components from packages map
    for (const [key, pkg] of Object.entries(packages)) {
        const { name, version } = splitKey(key);
        if (!name || !version) continue;

        const integrity = pkg.resolution?.integrity;
        const hashes    = integrity ? parseIntegritySRI(integrity) : [];

        const comp = createComponent({
            name, version, ecosystem: 'npm', hashes,
            license: pkg.license || null,
            scope: 'required',
        });
        purlMap[key] = comp.purl;
        components.push(comp);
    }

    // Build lookup index for O(1) component resolution in the next two passes
    const compByKey = new Map(components.map(c => [`${c.name}@${c.version}`, c]));

    // Second pass: wire dependency edges from snapshots
    for (const [key, snap] of Object.entries(snapshots)) {
        if (!snap.dependencies) continue;
        const { name, version } = splitKey(key);
        const comp = compByKey.get(`${name}@${version}`);
        if (!comp) continue;

        for (const [depName, depVer] of Object.entries(snap.dependencies)) {
            const depPurl = purlMap[`${depName}@${depVer}`];
            if (depPurl) comp.dependsOn.push(depPurl);
        }
    }

    // Mark dev deps from importers
    for (const importer of Object.values(importers)) {
        markDevDeps(importer.devDependencies || {}, compByKey);
    }

    return components;
}

// ── v6 format (pnpm 7-8) ───────────────────────────────────────────────────
// packages: /name@version → resolution + dependencies (version strings)
// dependencies / devDependencies at root for direct deps
function parsePnpmV6(data) {
    const packages   = data.packages || {};
    const components = [];
    const purlMap    = {};   // "/name@version" → purl

    // First pass: build all components
    for (const [key, pkg] of Object.entries(packages)) {
        // Strip leading "/" from key
        const stripped = key.startsWith('/') ? key.slice(1) : key;
        const { name, version } = splitKey(stripped);
        if (!name || !version) continue;

        const integrity = pkg.resolution?.integrity;
        const hashes    = integrity ? parseIntegritySRI(integrity) : [];

        const comp = createComponent({
            name, version, ecosystem: 'npm', hashes,
            license: pkg.license || null,
            scope: pkg.dev ? 'dev' : 'required',
        });
        purlMap[key] = comp.purl;

        // Store raw dep refs for resolution in second pass
        if (pkg.dependencies) {
            comp._depRefs = Object.entries(pkg.dependencies).map(
                ([n, v]) => (v.startsWith('/') ? v : `/${n}@${v}`)
            );
        }

        components.push(comp);
    }

    // Second pass: resolve dep refs to purls
    for (const comp of components) {
        for (const ref of (comp._depRefs || [])) {
            const depPurl = purlMap[ref];
            if (depPurl) comp.dependsOn.push(depPurl);
        }
        delete comp._depRefs;
    }

    // Mark dev deps declared at root (catches cases pkg.dev wasn't set)
    const compByKeyV6 = new Map(components.map(c => [`${c.name}@${c.version}`, c]));
    const importers = data.importers || {};
    if (Object.keys(importers).length > 0) {
        for (const importer of Object.values(importers)) {
            markDevDeps(importer.devDependencies || {}, compByKeyV6);
        }
    } else {
        markDevDeps(data.devDependencies || {}, compByKeyV6);
    }

    return components;
}

// ── Helpers ────────────────────────────────────────────────────────────────

/**
 * Split "name@version" or "@scope/name@version" into { name, version }.
 * Handles peer dependency suffixes like "name@version(peer@ver)".
 */
function splitKey(key) {
    // Strip parenthesized peer suffixes: name@1.0.0(react@18.0.0) → name@1.0.0
    const clean = key.replace(/\([^)]*\)/g, '').trim();

    if (clean.startsWith('@')) {
        // Scoped: @scope/name@version
        const idx = clean.indexOf('@', 1);
        if (idx === -1) return { name: clean, version: undefined };
        return { name: clean.slice(0, idx), version: clean.slice(idx + 1) };
    }

    const idx = clean.lastIndexOf('@');
    if (idx <= 0) return { name: clean, version: undefined };
    return { name: clean.slice(0, idx), version: clean.slice(idx + 1) };
}

function markDevDeps(devDeps, compByKey) {
    for (const [name, spec] of Object.entries(devDeps)) {
        const ver  = typeof spec === 'object' ? spec.version : spec;
        const comp = compByKey.get(`${name}@${ver}`);
        if (comp) comp.scope = 'dev';
    }
}

module.exports = { parsePnpmLock };
