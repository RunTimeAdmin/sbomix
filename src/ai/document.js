'use strict';

/**
 * AI BOM document assembler.
 *
 * Combines everything into one signable, serializable attestation:
 *   subject → AI component inventory → hash-chained lineage → cryptographic
 *   signature (hybrid PQC-ready) → regulatory control mapping.
 *
 * Serializes to JSON or YAML, and can attach the signature to a CycloneDX BOM's
 * top-level `signature` field (JSF) so a single CycloneDX file carries both the
 * component graph and the lineage attestation reference.
 */

const YAML = require('yaml');
const { lineageFromComponents, verifyLineage, chainHead } = require('./lineage');
const { signDocument, verifyDocument, capabilities } = require('./sign');
const { assessCompliance } = require('./compliance');

const AIBOM_SPEC = 'packrai-aibom/1.0';

/**
 * Build a complete AI BOM attestation document.
 *
 * @param {object} params
 * @param {object[]} params.aiComponents  - components with ecosystem==='ai'
 * @param {object[]} params.threats       - AI threat findings
 * @param {object}   params.meta          - { name, version }
 * @param {object}   [params.keys]        - signing keys (from sign.generateClassicalKeyPair etc.)
 *                                          if omitted, the document is built unsigned
 * @param {object}   [params.lineageEntries] - explicit lifecycle entries; otherwise derived
 * @returns {object} the assembled (and possibly signed) AI BOM
 */
function buildAIBomDocument({ aiComponents = [], threats = [], meta = {}, keys = null, lineageEntries = null, agentic = null }) {
    const lineage = lineageEntries
        ? require('./lineage').buildLineage(lineageEntries)
        : lineageFromComponents(aiComponents, meta);

    const lineageVerification = verifyLineage(lineage);

    // The signature commits to the lineage chain + the component inventory digest.
    const signable = {
        spec:        AIBOM_SPEC,
        subject:     { name: meta.name || 'application', version: meta.version || 'unknown' },
        lineageHead: chainHead(lineage),
        lineage,
        components:  aiComponents.map(slimComponent),
    };

    let signature = null;
    if (keys?.classicalPrivateKey) {
        signature = signDocument(signable, keys, { hybrid: true });
    }

    const compliance = assessCompliance({ aiComponents, threats, lineage, lineageVerification, signature, agentic });

    return {
        bomFormat:   'PackrAI-AIBOM',
        specVersion: AIBOM_SPEC,
        generatedAt: new Date().toISOString(),
        generator:   { name: 'packrai', cryptoCapabilities: capabilities() },
        subject:     signable.subject,
        components:  aiComponents.map(slimComponent),
        lineage,
        lineageHead: signable.lineageHead,
        lineageVerification,
        signature,
        threats: threats.map((t) => ({
            id: t.id, severity: t.severity, name: t.name,
            component: t.component, description: t.description, mitigations: t.mitigations,
        })),
        compliance,
        agentic: agentic ? {
            mcpServers: agentic.mcpServers,
            prompts:    (agentic.prompts || []).map((p) => ({ name: p.name, path: p.path, sha256: p.sha256 })),
            boundaries: agentic.boundaries,
        } : null,
        summary: {
            aiModels:        aiComponents.filter((c) => ['model-weights', 'code-reference'].includes(c.aiMetadata?.role)).length,
            apiProviders:    aiComponents.filter((c) => c.aiMetadata?.role === 'api-provider').length,
            frameworks:      aiComponents.filter((c) => c.aiMetadata?.role === 'framework').length,
            datasets:        aiComponents.filter((c) => c.aiMetadata?.role === 'dataset').length,
            mcpServers:      aiComponents.filter((c) => c.aiMetadata?.role === 'mcp-server').length,
            prompts:         aiComponents.filter((c) => c.aiMetadata?.role === 'prompt').length,
            leastAgencyScore: agentic?.boundaries?.leastAgencyScore ?? null,
            criticalThreats: threats.filter((t) => t.severity === 'CRITICAL').length,
            highThreats:     threats.filter((t) => t.severity === 'HIGH').length,
        },
    };
}

function slimComponent(c) {
    return {
        name: c.name, version: c.version, purl: c.purl,
        type: c.type, role: c.aiMetadata?.role,
        source: c.aiMetadata?.source, license: c.licenses?.[0] || null,
        hashes: c.hashes || [],
        aiMetadata: c.aiMetadata || {},
    };
}

/**
 * Verify a previously-built AI BOM document end to end.
 * @returns {{ lineage: object, signature: object|null }}
 */
function verifyAIBomDocument(doc) {
    const lineage = verifyLineage(doc.lineage || []);
    let signature = null;
    if (doc.signature) {
        const signable = {
            spec:        AIBOM_SPEC,
            subject:     doc.subject,
            lineageHead: doc.lineageHead,
            lineage:     doc.lineage,
            components:  doc.components,
        };
        signature = verifyDocument(signable, doc.signature);
    }
    return { lineage, signature };
}

/** Serialize the AI BOM to a string. format: 'json' | 'yaml'. */
function serializeAIBom(doc, format = 'json') {
    if (format === 'yaml' || format === 'yml') return YAML.stringify(doc);
    return JSON.stringify(doc, null, 2);
}

/**
 * Attach the AI BOM signature + lineage reference to a CycloneDX BOM in place.
 * Uses the spec's top-level `signature` (JSF) and a `properties` pointer to the
 * lineage head so the CycloneDX file alone proves which lineage it was signed with.
 */
function attachToCycloneDX(cdxBom, aiBom) {
    if (!cdxBom || !aiBom) return cdxBom;

    if (aiBom.signature?.value) {
        cdxBom.signature = {
            algorithm: aiBom.signature.algorithm,
            value:     aiBom.signature.value,
            ...(aiBom.signature.publicKey ? { publicKey: aiBom.signature.publicKey } : {}),
            ...(aiBom.signature.pqc ? { 'packrai:pqc': aiBom.signature.pqc } : {}),
        };
    }

    cdxBom.properties = [
        ...(cdxBom.properties || []),
        { name: 'packrai:aibom:lineageHead',     value: aiBom.lineageHead },
        { name: 'packrai:aibom:lineageIntact',   value: String(aiBom.lineageVerification?.valid ?? false) },
        { name: 'packrai:aibom:complianceCoverage', value: String(aiBom.compliance?.summary.coveragePct ?? 0) },
        { name: 'packrai:aibom:spec',            value: aiBom.specVersion },
    ];

    return cdxBom;
}

module.exports = {
    buildAIBomDocument,
    verifyAIBomDocument,
    serializeAIBom,
    attachToCycloneDX,
    AIBOM_SPEC,
};
