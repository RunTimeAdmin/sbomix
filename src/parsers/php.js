'use strict';

const fs = require('fs');
const { createComponent } = require('../component');

/**
 * Parse composer.lock (PHP Composer dependency lock file).
 *
 * Format:
 * {
 *   "packages":     [ { name, version, require, license, dist: { shasum } } ],
 *   "packages-dev": [ ... ]
 * }
 *
 * purl: pkg:composer/vendor/package@version
 */
function parseComposerLock(filePath) {
    const raw  = fs.readFileSync(filePath, 'utf8');
    const data = JSON.parse(raw);

    const components = [];
    const byName     = new Map();  // "vendor/package" → comp

    // Runtime deps
    for (const pkg of (data.packages || [])) {
        const comp = buildComponent(pkg, 'required');
        components.push(comp);
        byName.set(pkg.name.toLowerCase(), comp);
    }

    // Dev deps
    for (const pkg of (data['packages-dev'] || [])) {
        const comp = buildComponent(pkg, 'dev');
        components.push(comp);
        byName.set(pkg.name.toLowerCase(), comp);
    }

    // Resolve dependency edges from require fields
    for (const pkg of [...(data.packages || []), ...(data['packages-dev'] || [])]) {
        const comp = byName.get(pkg.name.toLowerCase());
        if (!comp) continue;

        for (const depName of Object.keys(pkg.require || {})) {
            // Skip PHP runtime itself and extensions
            if (depName === 'php' || depName.startsWith('ext-') || depName.startsWith('lib-')) continue;
            const depComp = byName.get(depName.toLowerCase());
            if (depComp && !comp.dependsOn.includes(depComp.purl)) {
                comp.dependsOn.push(depComp.purl);
            }
        }
    }

    return components;
}

function buildComponent(pkg, scope) {
    // Composer versions often have a leading 'v'
    const version = (pkg.version || '').replace(/^v/, '');

    // SHA-1 content hash from dist
    const hashes = pkg.dist?.shasum
        ? [{ alg: 'SHA-1', content: pkg.dist.shasum }]
        : [];

    // License: can be an array or a string in Composer
    let license = null;
    if (Array.isArray(pkg.license) && pkg.license.length > 0) {
        license = pkg.license.join(' OR ');
    } else if (typeof pkg.license === 'string' && pkg.license) {
        license = pkg.license;
    }

    return createComponent({
        name:     pkg.name,
        version,
        ecosystem: 'composer',
        hashes,
        licenses:  license ? [license] : [],
        scope,
        description: pkg.description || '',
    });
}

module.exports = { parseComposerLock };
