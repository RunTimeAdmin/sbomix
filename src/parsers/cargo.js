'use strict';

/**
 * Cargo.lock parser (Rust).
 * Cargo.lock is a complete, authoritative dependency graph — every transitive
 * dep is listed with its exact version and checksum. No inference needed.
 *
 * Supports both Cargo.lock v3 (checksum per-package) and v4 (same structure).
 */

const fs = require('fs');
const { parse: parseToml } = require('smol-toml');
const { createComponent, makePurl } = require('../component');

function parseCargoLock(filePath) {
    const raw = fs.readFileSync(filePath, 'utf8');
    const data = parseToml(raw);
    const packages = data.package || [];

    // Build name+version -> purl map for dependency resolution
    const index = new Map();
    for (const pkg of packages) {
        const key = `${pkg.name}@${pkg.version}`;
        index.set(key, makePurl('cargo', pkg.name, pkg.version));
    }

    return packages.map((pkg) => {
        const hashes = [];
        if (pkg.checksum) {
            // Cargo.lock checksum is a hex SHA-256
            hashes.push({ alg: 'SHA-256', content: pkg.checksum });
        }

        // dependencies: array of "name version" or "name version (registry)" strings
        const dependsOn = (pkg.dependencies || []).map((dep) => {
            const parts = dep.split(/\s+/);
            const depName = parts[0];
            const depVersion = parts[1] || '';
            const key = `${depName}@${depVersion}`;
            return index.get(key) || makePurl('cargo', depName, depVersion);
        });

        return createComponent({
            name: pkg.name,
            version: pkg.version,
            ecosystem: 'cargo',
            hashes,
            dependsOn,
        });
    });
}

module.exports = { parseCargoLock };
