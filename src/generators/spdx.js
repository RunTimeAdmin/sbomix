'use strict';

/**
 * SPDX 2.3 JSON generator.
 * Spec: https://spdx.github.io/spdx-spec/v2.3/
 *
 * SPDX uses a different identity model from CycloneDX:
 *   - Every element has an SPDXID (SPDXRef-<id>)
 *   - Relationships are expressed as triples: (A, RELATIONSHIP_TYPE, B)
 *   - The document itself is a package (SPDXRef-DOCUMENT)
 */

const crypto = require('crypto');

const SPDX_VERSION = 'SPDX-2.3';

/**
 * Generate an SPDX 2.3 document.
 * @param {object[]} components
 * @param {object} meta
 * @param {string} meta.name
 * @param {string} meta.version
 * @param {string} [meta.author]
 * @returns {object} parsed JSON
 */
function generateSPDX(components, meta = {}) {
    const deduped = deduplicateComponents(components);
    const now = new Date().toISOString();
    const docName = `${meta.name || 'unknown'}-${meta.version || '0.0.0'}`;
    const namespace = `https://packrai.xyz/sbom/${docName}-${shortHash()}`;

    const packages = deduped.map(spdxPackage);
    const relationships = buildRelationships(deduped, docName);

    return {
        spdxVersion: SPDX_VERSION,
        dataLicense: 'CC0-1.0',
        SPDXID: 'SPDXRef-DOCUMENT',
        name: docName,
        documentNamespace: namespace,
        creationInfo: {
            created: now,
            creators: [
                `Tool: packrai-${require('../../package.json').version}`,
                ...(meta.author ? [`Organization: ${meta.author}`] : []),
            ],
            licenseListVersion: '3.22',
        },
        packages,
        relationships,
    };
}

function spdxPackage(comp) {
    const spdxId = `SPDXRef-${sanitizeSpdxId(comp.purl)}`;
    const pkg = {
        SPDXID: spdxId,
        name: comp.name,
        versionInfo: comp.version,
        downloadLocation: comp.homepage || 'NOASSERTION',
        filesAnalyzed: false,
        externalRefs: [{
            referenceCategory: 'PACKAGE-MANAGER',
            referenceType: 'purl',
            referenceLocator: comp.purl,
        }],
    };

    if (comp.description) pkg.comment = comp.description;

    if (comp.licenses && comp.licenses.length > 0) {
        pkg.licenseConcluded = comp.licenses.join(' AND ');
        pkg.licenseDeclared = comp.licenses.join(' AND ');
    } else {
        pkg.licenseConcluded = 'NOASSERTION';
        pkg.licenseDeclared = 'NOASSERTION';
    }

    pkg.copyrightText = 'NOASSERTION';

    if (comp.hashes && comp.hashes.length > 0) {
        pkg.checksums = comp.hashes.map((h) => ({
            algorithm: h.alg.replace('-', ''),  // SHA-256 -> SHA256
            checksumValue: h.content,
        }));
    }

    return pkg;
}

function buildRelationships(components, docName) {
    const rels = [];

    // Document DESCRIBES all top-level (direct) components
    for (const comp of components) {
        if (comp.scope === 'required' || comp.scope === 'dev') {
            rels.push({
                spdxElementId: 'SPDXRef-DOCUMENT',
                relationshipType: 'DESCRIBES',
                relatedSpdxElement: `SPDXRef-${sanitizeSpdxId(comp.purl)}`,
            });
        }
    }

    // Component DEPENDS_ON relationships
    const purlToSpdxId = new Map(components.map((c) => [c.purl, `SPDXRef-${sanitizeSpdxId(c.purl)}`]));
    for (const comp of components) {
        for (const depPurl of (comp.dependsOn || [])) {
            const depId = purlToSpdxId.get(depPurl);
            if (depId) {
                rels.push({
                    spdxElementId: `SPDXRef-${sanitizeSpdxId(comp.purl)}`,
                    relationshipType: 'DEPENDS_ON',
                    relatedSpdxElement: depId,
                });
            }
        }
    }

    return rels;
}

function sanitizeSpdxId(purl) {
    // SPDX IDs: only letters, numbers, '.', '-'
    return purl.replace(/[^a-zA-Z0-9.\-]/g, '-').replace(/-+/g, '-').slice(0, 128);
}

function deduplicateComponents(components) {
    const seen = new Map();
    for (const comp of components) {
        if (!seen.has(comp.purl)) seen.set(comp.purl, comp);
    }
    return Array.from(seen.values());
}

function shortHash() {
    return crypto.randomBytes(4).toString('hex');
}

module.exports = { generateSPDX };
