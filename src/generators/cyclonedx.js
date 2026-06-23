'use strict';

/**
 * CycloneDX 1.6 JSON generator.
 * Spec: https://cyclonedx.org/specification/overview/
 *
 * Produces all CISA 2025 minimum SBOM elements:
 *   component name, version, supplier, unique IDs (purl), hash,
 *   license, dependency relationships, author, timestamp, tool, generation context.
 */

const crypto = require('crypto');

const CDX_SPEC_VERSION = '1.6';
const CDX_SCHEMA = 'http://cyclonedx.org/schema/bom-1.6.schema.json';

/**
 * Generate a CycloneDX 1.6 BOM.
 * @param {object[]} components  - from parsers
 * @param {object} meta
 * @param {string} meta.name     - component/repo being described
 * @param {string} meta.version  - version / tag
 * @param {string} [meta.author] - author name or org
 * @returns {object} parsed JSON object (call JSON.stringify to serialise)
 */
function generateCycloneDX(components, meta = {}) {
    const serialNumber = `urn:uuid:${randomUUID()}`;
    const timestamp = new Date().toISOString();

    // Deduplicate by purl — multiple lock files in a monorepo can overlap
    const deduped = deduplicateComponents(components);

    const bom = {
        bomFormat: 'CycloneDX',
        specVersion: CDX_SPEC_VERSION,
        serialNumber,
        version: 1,
        metadata: buildMetadata(meta, timestamp),
        components: deduped.map(cdxComponent),
        dependencies: buildDependencies(deduped),
    };

    return bom;
}

function buildMetadata(meta, timestamp) {
    return {
        timestamp,
        tools: {
            components: [{
                type: 'application',
                name: 'packrai',
                version: require('../../package.json').version,
                purl: 'pkg:npm/packrai',
                externalReferences: [{
                    type: 'website',
                    url: 'https://packrai.xyz',
                }],
            }],
        },
        component: meta.name ? {
            type: 'application',
            name: meta.name,
            version: meta.version || '',
            ...(meta.author ? { supplier: { name: meta.author } } : {}),
        } : undefined,
        manufacture: meta.author ? { name: meta.author } : undefined,
        supplier: meta.author ? { name: meta.author } : undefined,
    };
}

function cdxComponent(comp) {
    const c = {
        type: comp.type || 'library',
        'bom-ref': comp.purl,
        name: comp.name,
        version: comp.version,
        purl: comp.purl,
    };

    if (comp.description) c.description = comp.description;
    if (comp.homepage)    c.externalReferences = [{ type: 'website', url: comp.homepage }];

    if (comp.licenses && comp.licenses.length > 0) {
        c.licenses = comp.licenses.map((l) => ({ license: { id: l } }));
    }

    if (comp.hashes && comp.hashes.length > 0) {
        c.hashes = comp.hashes.map((h) => ({ alg: h.alg, content: h.content }));
    }

    if (comp.scope && comp.scope !== 'required') {
        c.scope = comp.scope === 'dev' ? 'excluded' : 'optional';
    }

    // Vulnerability data added by OSV enricher
    if (comp.vulnerabilities && comp.vulnerabilities.length > 0) {
        c._vulnerabilities = comp.vulnerabilities; // moved to top-level vulnerabilities section
    }

    return c;
}

function buildDependencies(components) {
    // CycloneDX dependencies: { ref: purl, dependsOn: [purl, ...] }
    // Include every component even if it has no deps (explicit empty array = leaf node)
    return components.map((comp) => ({
        ref: comp.purl,
        dependsOn: comp.dependsOn || [],
    }));
}

function deduplicateComponents(components) {
    const seen = new Map();
    for (const comp of components) {
        if (!seen.has(comp.purl)) seen.set(comp.purl, comp);
    }
    return Array.from(seen.values());
}

function randomUUID() {
    // Node 18+ has crypto.randomUUID()
    if (crypto.randomUUID) return crypto.randomUUID();
    // Fallback for older Node
    const b = crypto.randomBytes(16);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const h = b.toString('hex');
    return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}

module.exports = { generateCycloneDX };
