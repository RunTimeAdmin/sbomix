'use strict';

const fs = require('fs');
const { createComponent } = require('../component');

/**
 * Parse Gemfile.lock (Bundler Ruby dependency lock file).
 *
 * Format:
 *   GEM
 *     remote: https://rubygems.org/
 *     specs:
 *       rack (2.2.7)           ← 4-space indent = gem name + version
 *         concurrent-ruby (~>)  ← 6-space indent = dependency (constraint only)
 *
 *   DEPENDENCIES
 *     rails (~> 7.0)           ← direct deps (no dev/runtime distinction in lock)
 *
 * Note: Gemfile.lock does not preserve group (dev/runtime) information.
 * All gems are marked scope=required. To detect dev scope, read Gemfile groups.
 */
function parseGemfileLock(filePath) {
    const lines     = fs.readFileSync(filePath, 'utf8').split('\n');
    const components = [];
    const byName    = new Map();   // name → comp
    const rawDeps   = new Map();   // name → [depName, ...]

    let inSpecs     = false;
    let currentName = null;

    for (const line of lines) {
        const trimmed = line.trimEnd();
        const lstripped = trimmed.trimStart();

        // Section transitions
        if (lstripped === 'GEM')         { inSpecs = false; continue; }
        if (lstripped === 'specs:')      { inSpecs = true;  continue; }
        if (/^(PLATFORMS|DEPENDENCIES|BUNDLED WITH|GIT|PATH|PLUGIN SOURCE)$/.test(lstripped)) {
            inSpecs = false;
            continue;
        }
        if (!inSpecs) continue;
        if (!lstripped) continue;

        const indent = trimmed.length - lstripped.length;

        if (indent === 4) {
            // "    name (version)" — a gem entry
            const m = lstripped.match(/^(.+?)\s+\(([^)]+)\)$/);
            if (!m) continue;
            const [, name, version] = m;
            // Skip entries whose "version" is actually a constraint (no semver digit start)
            if (!/^\d/.test(version)) continue;

            const comp = createComponent({
                name,
                version,
                ecosystem: 'gem',
                hashes:    [],
                licenses:  [],
                scope:     'required',
            });
            components.push(comp);
            byName.set(name, comp);
            rawDeps.set(name, []);
            currentName = name;

        } else if (indent === 6 && currentName) {
            // "      depname (constraint)" — a dependency of currentName
            const depName = lstripped.split(/\s+/)[0];
            rawDeps.get(currentName)?.push(depName);
        }
    }

    // Resolve dependency edges
    for (const [gemName, deps] of rawDeps) {
        const comp = byName.get(gemName);
        if (!comp) continue;
        for (const depName of deps) {
            const depComp = byName.get(depName);
            if (depComp && !comp.dependsOn.includes(depComp.purl)) {
                comp.dependsOn.push(depComp.purl);
            }
        }
    }

    return components;
}

module.exports = { parseGemfileLock };
