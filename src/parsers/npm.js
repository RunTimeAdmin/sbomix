'use strict';

/**
 * npm lock file parser.
 * Handles: package-lock.json (lockfileVersion 1, 2, 3), yarn.lock v1.
 *
 * Transitive accuracy strategy:
 *   - v3/v2: flat `packages` map — path structure encodes the hoisted tree.
 *     We reconstruct which package depends on which by resolving each dep name
 *     upward through the path hierarchy (mirrors Node's require() resolution).
 *   - v1: recursive `dependencies` tree — walk it depth-first.
 *   - yarn v1: flat map keyed by "name@range" — build a name->version index,
 *     then resolve requires.
 */

const fs = require('fs');
const { createComponent, makePurl } = require('../component');

// ── package-lock.json ─────────────────────────────────────────────────────────

function parsePackageLock(filePath) {
    const raw = fs.readFileSync(filePath, 'utf8');
    const data = JSON.parse(raw);
    const v = data.lockfileVersion || 1;
    if (v >= 2 && data.packages) return parseV3(data);
    return parseV1(data);
}

// v3 (and v2 which also has packages)
function parseV3(data) {
    const packages = data.packages || {};
    // Build path -> component map (path used for dependency resolution)
    const byPath = new Map();

    for (const [path, pkg] of Object.entries(packages)) {
        if (path === '' || !pkg.version) continue;
        // Extract canonical name: last segment after "node_modules/"
        const parts = path.split('node_modules/').filter(Boolean);
        const name = parts[parts.length - 1].replace(/\/$/, '');
        const version = pkg.version;

        if (byPath.has(path)) continue; // dedupe hoisted copies

        const comp = createComponent({
            name,
            version,
            ecosystem: 'npm',
            scope: pkg.dev ? 'dev' : (pkg.optional ? 'optional' : 'required'),
            integrity: pkg.integrity || '',
            licenses: normLicense(pkg.license),
            description: pkg.description || '',
            homepage: pkg.homepage || '',
        });
        // Stash for graph resolution
        comp._path = path;
        comp._requires = {
            ...(pkg.dependencies || {}),
            ...(pkg.optionalDependencies || {}),
        };
        byPath.set(path, comp);
    }

    // Resolve dep names to purls
    for (const comp of byPath.values()) {
        for (const depName of Object.keys(comp._requires || {})) {
            const depPurl = resolveV3(depName, comp._path, byPath);
            if (depPurl) comp.dependsOn.push(depPurl);
        }
        delete comp._path;
        delete comp._requires;
    }

    return Array.from(byPath.values());
}

// Mirror Node's require() resolution: try nested paths first, then walk up.
function resolveV3(depName, fromPath, byPath) {
    const segments = fromPath.split('node_modules/').filter(Boolean);
    for (let i = segments.length; i >= 0; i--) {
        const base = i === 0
            ? 'node_modules/' + depName
            : segments.slice(0, i).join('node_modules/') + 'node_modules/' + depName;
        const candidate = byPath.get(base) || byPath.get(base + '/');
        if (candidate) return candidate.purl;
    }
    return null;
}

// v1: nested dependencies tree
function parseV1(data) {
    const results = [];
    walkV1(data.dependencies || {}, results);
    return results;
}

function walkV1(deps, out) {
    for (const [name, pkg] of Object.entries(deps)) {
        if (!pkg.version) continue;
        const requires = pkg.requires || {};
        const childComps = [];
        if (pkg.dependencies) walkV1(pkg.dependencies, childComps);
        out.push(...childComps);

        const comp = createComponent({
            name,
            version: pkg.version,
            ecosystem: 'npm',
            scope: pkg.dev ? 'dev' : (pkg.optional ? 'optional' : 'required'),
            integrity: pkg.integrity || '',
            licenses: normLicense(pkg.license),
            dependsOn: Object.keys(requires).map((r) => makePurl('npm', r, requires[r])),
        });
        out.push(comp);
    }
}

// ── yarn.lock v1 ──────────────────────────────────────────────────────────────

function parseYarnLock(filePath) {
    const raw = fs.readFileSync(filePath, 'utf8');
    if (raw.includes('__metadata:')) {
        // yarn v2/berry — not yet supported
        console.warn('[packrai] yarn.lock v2 (berry) detected — skipping (use package-lock.json or pnpm-lock.yaml)');
        return [];
    }
    return parseYarnV1(raw);
}

function parseYarnV1(raw) {
    // Yarn v1 lock format: blocks separated by blank lines
    // Each block: "name@range, name@range2:\n  version \"x.y.z\"\n  ..."
    const blocks = raw.split(/\n\n+/).filter((b) => b.trim() && !b.startsWith('#'));
    const nameToComp = new Map(); // canonical "name@version" -> comp

    const parsed = blocks.map((block) => {
        const lines = block.split('\n');
        const header = lines[0];
        const names = header.replace(/:$/, '').split(', ').map((s) => s.trim().replace(/^"|"$/g, ''));

        const versionLine = lines.find((l) => l.trim().startsWith('version '));
        if (!versionLine) return null;
        const version = versionLine.trim().replace(/^version\s+"?/, '').replace(/"$/, '');

        const integrityLine = lines.find((l) => l.trim().startsWith('integrity '));
        const integrity = integrityLine ? integrityLine.trim().replace(/^integrity\s+/, '') : '';

        const requiresStart = lines.findIndex((l) => l.trim() === 'dependencies:');
        const requires = {};
        if (requiresStart !== -1) {
            for (let i = requiresStart + 1; i < lines.length; i++) {
                const m = lines[i].match(/^\s+"?([^"]+)"?\s+"?([^"]+)"?\s*$/);
                if (!m) break;
                requires[m[1]] = m[2];
            }
        }

        // Extract canonical package name from first header entry
        const firstName = names[0];
        const atIdx = firstName.lastIndexOf('@');
        const name = atIdx > 0 ? firstName.slice(0, atIdx) : firstName;

        return { name, version, integrity, requires, _names: names };
    }).filter(Boolean);

    // Build name->version lookup (for resolving requires)
    const nameVersionMap = new Map();
    for (const p of parsed) {
        for (const n of p._names) {
            nameVersionMap.set(n, p.version);
        }
    }

    const components = [];
    for (const p of parsed) {
        const key = `${p.name}@${p.version}`;
        if (nameToComp.has(key)) continue;

        const dependsOn = Object.entries(p.requires).map(([depName, depRange]) => {
            const resolvedV = nameVersionMap.get(`${depName}@${depRange}`) || depRange;
            return makePurl('npm', depName, resolvedV);
        });

        const comp = createComponent({
            name: p.name,
            version: p.version,
            ecosystem: 'npm',
            integrity: p.integrity,
            dependsOn,
        });
        nameToComp.set(key, comp);
        components.push(comp);
    }
    return components;
}

// ── helpers ───────────────────────────────────────────────────────────────────

function normLicense(raw) {
    if (!raw) return [];
    if (typeof raw === 'string') return [raw];
    if (Array.isArray(raw)) return raw.map((l) => (typeof l === 'string' ? l : l.type)).filter(Boolean);
    if (typeof raw === 'object' && raw.type) return [raw.type];
    return [];
}

module.exports = { parsePackageLock, parseYarnLock };
