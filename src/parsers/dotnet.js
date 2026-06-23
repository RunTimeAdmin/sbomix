'use strict';

const fs = require('fs');
const { createComponent } = require('../component');

/**
 * Parse packages.lock.json (NuGet dependency lock file)
 *
 * Enabled in .csproj with:
 *   <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
 *
 * Format:
 * {
 *   "version": 1,
 *   "dependencies": {
 *     ".NETCoreApp,Version=v8.0": {
 *       "Newtonsoft.Json": {
 *         "type": "Direct" | "Transitive",
 *         "resolved": "13.0.3",
 *         "contentHash": "<base64-sha512>",
 *         "dependencies": { "OtherPkg": "1.0.0" }
 *       }
 *     }
 *   }
 * }
 */
function parsePackagesLock(filePath) {
    const raw  = fs.readFileSync(filePath, 'utf8');
    const data = JSON.parse(raw);

    const seen   = new Map();   // "name.lower@version" → component
    const purlMap = new Map();  // same key → purl

    // First pass: collect all packages across all target frameworks (dedup)
    for (const packages of Object.values(data.dependencies || {})) {
        for (const [name, pkg] of Object.entries(packages)) {
            const version = pkg.resolved;
            if (!version) continue;

            const key = `${name.toLowerCase()}@${version}`;
            if (seen.has(key)) continue;

            const hashes = pkg.contentHash
                ? [{ alg: 'SHA-512', content: pkg.contentHash }]
                : [];

            const comp = createComponent({
                name,
                version,
                ecosystem: 'nuget',
                hashes,
                license: null,
                scope: 'required',
            });

            seen.set(key, comp);
            purlMap.set(key, comp.purl);
        }
    }

    // Second pass: build dependency graph
    for (const packages of Object.values(data.dependencies || {})) {
        for (const [name, pkg] of Object.entries(packages)) {
            const version = pkg.resolved;
            if (!version) continue;

            const comp = seen.get(`${name.toLowerCase()}@${version}`);
            if (!comp || !pkg.dependencies) continue;

            for (const [depName, depVer] of Object.entries(pkg.dependencies)) {
                const depPurl = purlMap.get(`${depName.toLowerCase()}@${depVer}`);
                if (depPurl && !comp.dependsOn.includes(depPurl)) {
                    comp.dependsOn.push(depPurl);
                }
            }
        }
    }

    return [...seen.values()];
}

module.exports = { parsePackagesLock };
