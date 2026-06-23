'use strict';

/**
 * Go modules parser.
 * Reads both go.mod (direct vs indirect markers) and go.sum (hashes).
 *
 * go.sum has every module downloaded including transitive deps.
 * go.mod marks which are direct ("require" without "// indirect").
 * Together they give a complete, accurate dependency graph.
 */

const fs = require('fs');
const path = require('path');
const { createComponent } = require('../component');

/**
 * Parse a directory containing go.mod and optionally go.sum.
 * @param {string} dir - directory containing go.mod
 */
function parseGoModules(dir) {
    const modPath = path.join(dir, 'go.mod');
    const sumPath = path.join(dir, 'go.sum');

    if (!fs.existsSync(modPath)) return [];

    const directDeps = parseGoMod(modPath);
    const hashes = fs.existsSync(sumPath) ? parseGoSum(sumPath) : new Map();

    // go.sum has entries for both the module itself and its go.mod file.
    // We want unique module@version pairs (ignore the "/go.mod" suffix entries).
    const seen = new Set();
    const components = [];

    for (const [modVer, hashList] of hashes) {
        if (modVer.endsWith('/go.mod')) continue; // skip go.mod hash entries
        if (seen.has(modVer)) continue;
        seen.add(modVer);

        const atIdx = modVer.lastIndexOf('@');
        if (atIdx === -1) continue;
        const name = modVer.slice(0, atIdx);
        const version = modVer.slice(atIdx + 1);

        const isDirectSet = directDeps.direct.has(`${name}@${version}`);
        const scope = isDirectSet ? 'required' : 'required'; // all are required; direct flag is metadata

        const h1Hashes = hashList.map((h) => ({
            alg: 'SHA-256',
            content: h.replace(/^h1:/, ''), // h1: prefix = SHA-256 of zip hash tree
        }));

        components.push(createComponent({
            name,
            version,
            ecosystem: 'golang',
            scope,
            hashes: h1Hashes,
        }));
    }

    // If go.sum is missing (vendored project), fall back to go.mod requires only
    if (hashes.size === 0) {
        for (const [modVer] of directDeps.all) {
            const atIdx = modVer.lastIndexOf('@');
            if (atIdx === -1) continue;
            components.push(createComponent({
                name: modVer.slice(0, atIdx),
                version: modVer.slice(atIdx + 1),
                ecosystem: 'golang',
            }));
        }
    }

    return components;
}

function parseGoMod(filePath) {
    const raw = fs.readFileSync(filePath, 'utf8');
    const direct = new Set();
    const all = new Map();

    let inRequire = false;
    for (const line of raw.split('\n')) {
        const t = line.trim();
        if (t === 'require (') { inRequire = true; continue; }
        if (t === ')' && inRequire) { inRequire = false; continue; }

        // Single-line require: "require module v1.2.3"
        const singleMatch = t.match(/^require\s+(\S+)\s+(\S+)(\s+\/\/\s*indirect)?/);
        if (singleMatch) {
            const key = `${singleMatch[1]}@${singleMatch[2]}`;
            all.set(key, true);
            if (!singleMatch[3]) direct.add(key);
            continue;
        }

        if (inRequire) {
            const m = t.match(/^(\S+)\s+(\S+)(\s+\/\/\s*indirect)?/);
            if (m && !t.startsWith('//')) {
                const key = `${m[1]}@${m[2]}`;
                all.set(key, true);
                if (!m[3]) direct.add(key);
            }
        }
    }

    return { direct, all };
}

function parseGoSum(filePath) {
    const raw = fs.readFileSync(filePath, 'utf8');
    const hashes = new Map();

    for (const line of raw.split('\n')) {
        const parts = line.trim().split(/\s+/);
        if (parts.length !== 3) continue;
        const [modVer, , hash] = parts;
        if (!hashes.has(modVer)) hashes.set(modVer, []);
        hashes.get(modVer).push(hash);
    }

    return hashes;
}

module.exports = { parseGoModules };
