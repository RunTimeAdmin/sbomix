'use strict';

/**
 * Internal component representation shared by all parsers.
 * One Component = one package (direct or transitive).
 */

function makePurl(ecosystem, name, version) {
    switch (ecosystem) {
        case 'npm': {
            // scoped packages: @scope/name -> pkg:npm/%40scope%2Fname@version
            const encoded = name.startsWith('@')
                ? name.replace('@', '%40').replace('/', '%2F')
                : name;
            return `pkg:npm/${encoded}@${version}`;
        }
        case 'pypi':
            // normalize: underscores and hyphens are equivalent in PyPI
            return `pkg:pypi/${name.replace(/_/g, '-').toLowerCase()}@${version}`;
        case 'cargo':
            return `pkg:cargo/${name}@${version}`;
        case 'golang':
            return `pkg:golang/${name}@${version}`;
        case 'maven':
            // name expected as "groupId/artifactId"
            return `pkg:maven/${name}@${version}`;
        case 'nuget':
            return `pkg:nuget/${name}@${version}`;
        default:
            return `pkg:generic/${name}@${version}`;
    }
}

function parseIntegritySRI(integrity) {
    if (!integrity) return [];
    // SRI format: "sha512-<base64> sha256-<base64>" (space-separated)
    return integrity.split(/\s+/).flatMap((tok) => {
        const m = tok.match(/^(sha\d+)-(.+)$/i);
        if (!m) return [];
        const algMap = { sha1: 'SHA-1', sha256: 'SHA-256', sha384: 'SHA-384', sha512: 'SHA-512' };
        const alg = algMap[m[1].toLowerCase()];
        return alg ? [{ alg, content: m[2] }] : [];
    });
}

/**
 * Create a normalised component object.
 *
 * @param {object} opts
 * @param {string} opts.name
 * @param {string} opts.version
 * @param {'npm'|'pypi'|'cargo'|'golang'} opts.ecosystem
 * @param {'required'|'optional'|'dev'} [opts.scope]
 * @param {string[]} [opts.licenses]       SPDX expression strings
 * @param {Array<{alg,content}>} [opts.hashes]
 * @param {string[]} [opts.dependsOn]      purls of immediate deps
 * @param {string} [opts.description]
 * @param {string} [opts.homepage]
 * @param {string} [opts.integrity]        SRI string (npm lockfiles) — parsed automatically
 * @returns {object}
 */
function createComponent(opts) {
    const { name, version, ecosystem } = opts;
    const purl = makePurl(ecosystem, name, version);
    const hashes = [
        ...(opts.hashes || []),
        ...parseIntegritySRI(opts.integrity || ''),
    ];
    return {
        type: 'library',
        name,
        version,
        ecosystem,
        purl,
        scope: opts.scope || 'required',
        licenses: opts.licenses || [],
        hashes,
        dependsOn: opts.dependsOn || [],
        description: opts.description || '',
        homepage: opts.homepage || '',
    };
}

module.exports = { createComponent, makePurl, parseIntegritySRI };
