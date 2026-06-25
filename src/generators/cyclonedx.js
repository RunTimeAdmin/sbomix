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

const CDX_SPEC_VERSION = '1.7';
const CDX_SCHEMA = 'http://cyclonedx.org/schema/bom-1.7.schema.json';

/**
 * Generate a CycloneDX 1.7 (ECMA-424) BOM.
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
        '$schema': CDX_SCHEMA,
        bomFormat: 'CycloneDX',
        specVersion: CDX_SPEC_VERSION,
        serialNumber,
        version: 1,
        metadata: buildMetadata(meta, timestamp),
        components: deduped.map(cdxComponent),
        dependencies: buildDependencies(deduped),
        compositions: buildCompositions(deduped, meta),
    };

    const vulns = buildVulnerabilities(deduped);
    if (vulns.length > 0) bom.vulnerabilities = vulns;

    return bom;
}

/**
 * Completeness declaration (CycloneDX `compositions`) — Pillar 5.
 *
 * Declares how complete the BOM's knowledge is. Library deps from a lock file
 * are a `complete` graph. AI components are inherently `incomplete`: detection
 * finds what is referenced locally, but a model's full training-data lineage
 * and runtime tool set cannot be proven from a static scan — declaring this
 * honestly is exactly what the spec's aggregate field is for.
 */
function buildCompositions(components, meta) {
    const rootRef = meta.name ? undefined : undefined; // root carried via metadata.component
    const libRefs = components.filter((c) => c.ecosystem !== 'ai').map((c) => c.purl);
    const aiRefs  = components.filter((c) => c.ecosystem === 'ai').map((c) => c.purl);

    const compositions = [];
    if (libRefs.length) {
        compositions.push({ aggregate: 'complete', assemblies: libRefs });
    }
    if (aiRefs.length) {
        // AI composition is incomplete: training data + agent tool scope are not
        // fully knowable from a static scan.
        compositions.push({ aggregate: 'incomplete', assemblies: aiRefs });
    }
    if (!compositions.length) {
        compositions.push({ aggregate: 'unknown', assemblies: [] });
    }
    void rootRef;
    return compositions;
}

function buildMetadata(meta, timestamp) {
    return {
        timestamp,
        tools: {
            components: [{
                type: 'application',
                author: 'packrai.xyz',
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
            'bom-ref': `app-${slugify(meta.name)}`,
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

    // CycloneDX 1.7 AI/ML extensions — modelCard for models, properties for any
    // AI component (datasets, MCP servers, prompts carry aiMetadata too).
    if (comp.type === 'machine-learning-model') {
        const card = buildModelCard(comp);
        if (card) c.modelCard = card;
    }
    if (comp.ecosystem === 'ai') {
        const props = buildAIProperties(comp.aiMetadata || {});
        if (props.length > 0) c.properties = props;
    }

    return c;
}

// Map a model architecture class to a CycloneDX modelArchitecture descriptor.
// Only well-known suffixes are mapped — anything else is left unset rather than
// guessed, so the field is trustworthy.
function deriveModelArchitecture(architectures = []) {
    const a = (architectures[0] || '').toLowerCase();
    if (/forcausallm$/.test(a))           return 'Decoder-only LLM';
    if (/formaskedlm$/.test(a))           return 'Encoder-only (masked LM)';
    if (/forconditionalgeneration$/.test(a)) return 'Encoder-decoder (seq2seq)';
    if (/forsequenceclassification$/.test(a)) return 'Encoder classifier';
    if (/(clip|vit|imageclassification)/.test(a)) return 'Vision transformer';
    return null;
}

// Task tag → human-readable task label, matching the modelCard convention.
const TASK_LABELS = {
    'text-generation': 'Text Generation', 'text2text-generation': 'Text-to-Text Generation',
    'fill-mask': 'Masked Language Modeling', 'text-classification': 'Text Classification',
    'token-classification': 'Token Classification', 'question-answering': 'Question Answering',
    'summarization': 'Summarization', 'translation': 'Translation',
    'feature-extraction': 'Feature Extraction / Embeddings', 'sentence-similarity': 'Sentence Similarity',
    'image-classification': 'Image Classification', 'automatic-speech-recognition': 'Speech Recognition',
};

const TEXT_TASKS = new Set(['text-generation', 'text2text-generation', 'summarization',
    'translation', 'question-answering', 'fill-mask', 'text-classification']);

/**
 * Build a CycloneDX 1.7 modelCard from a component's detected metadata.
 *
 * Populates only what a static scan (plus HF Hub enrichment) can establish.
 * Fields that require benchmarking or human judgement — performanceMetrics,
 * ethicalConsiderations, useCases, performanceTradeoffs — are emitted ONLY when
 * present in the component (e.g. carried from an HF model card); they are never
 * fabricated.
 */
function buildModelCard(comp) {
    const m = comp.aiMetadata || {};
    const existing = comp.modelCard || {};
    const task = m.pipeline || existing.modelParameters?.task || null;

    const modelParameters = {};
    if (m.approach || existing.modelParameters?.approach) {
        modelParameters.approach = m.approach || existing.modelParameters.approach;
    }
    if (task) modelParameters.task = TASK_LABELS[task] || task;
    const family = m.architectureFamily
        || (m.architectures?.length || m.modelType ? 'Transformer' : null);
    if (family) modelParameters.architectureFamily = family;
    const arch = deriveModelArchitecture(m.architectures);
    if (arch) modelParameters.modelArchitecture = arch;

    // Datasets embedded with governance (Pillar 2), matching the 1.7 shape.
    const datasets = (m.datasets || []).map((ds) => {
        const id = typeof ds === 'string' ? ds : ds.name;
        const entry = { type: 'dataset', name: id };
        if (typeof id === 'string' && id.includes('/')) {
            entry.contents = { url: `https://huggingface.co/datasets/${id}` };
        }
        return entry;
    });
    if (datasets.length) modelParameters.datasets = datasets;

    // inputs/outputs are determinable for text tasks
    if (task && TEXT_TASKS.has(task)) {
        modelParameters.inputs  = [{ format: 'string', description: 'Input text' }];
        modelParameters.outputs = [{ format: 'string', description: 'Generated text' }];
    }

    const card = {};
    if (Object.keys(modelParameters).length) card.modelParameters = modelParameters;

    // quantitativeAnalysis — only if metrics were carried in (never invented)
    if (existing.quantitativeAnalysis?.performanceMetrics?.length) {
        card.quantitativeAnalysis = existing.quantitativeAnalysis;
    }

    // considerations — derive the context-window limitation (factual); pass through
    // anything supplied by an HF model card.
    const considerations = { ...(existing.considerations || {}) };
    const limitations = [...(considerations.technicalLimitations || [])];
    if (m.contextLength) limitations.push(`Context window limited to ${m.contextLength} tokens`);
    if (m.quantization)  limitations.push(`Quantized (${m.quantization}) — may reduce accuracy vs full precision`);
    if (limitations.length) considerations.technicalLimitations = limitations;
    if (Object.keys(considerations).length) card.considerations = considerations;

    return Object.keys(card).length ? card : null;
}

function slugify(s) {
    return String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

function buildAIProperties(meta) {
    const p = (name, value) =>
        (value !== null && value !== undefined && value !== '')
            ? { name: `packrai:ai:${name}`, value: String(value) }
            : null;
    const a = meta.authority || {};
    // Standard-namespace property (no packrai prefix) — matches the agentic /
    // runtime:fencing convention used by the CycloneDX 1.7 ML-BOM ecosystem.
    const std = (name, value) =>
        (value !== null && value !== undefined && value !== '')
            ? { name, value: String(value) }
            : null;

    const datasetNames = (meta.datasets || [])
        .map((d) => (typeof d === 'string' ? d : d?.name)).filter(Boolean);

    return [
        p('role',          meta.role),
        p('source',        meta.source),
        p('format',        meta.format),
        p('pipeline',      meta.pipeline),
        p('baseModel',     meta.baseModel),
        p('provider',      meta.provider),
        p('sdkPackage',    meta.sdkPackage),
        p('gated',         meta.gated ? 'true' : null),
        p('ggufVersion',   meta.ggufVersion),
        p('fileSizeMB',    meta.fileSizeMB),
        p('referencedIn',  meta.referencedIn),
        p('lastModified',  meta.lastModified),
        // Pillar 1: architecture & parameters
        p('precision',     meta.precision),
        p('quantization',  meta.quantization),
        p('paramCountEstimate', meta.paramCountEstimate),
        p('contextLength', meta.contextLength),
        p('weightFile',    meta.weightFile),
        // Pillar 4: agentic context — standard namespaces from the 1.7 ML-BOM convention
        std('agentic:authority', deriveAgenticAuthority(meta)),
        std('agentic:transport', meta.transport),
        meta.requiresAuth === undefined ? null : std('agentic:requiresAuth', String(meta.requiresAuth)),
        a.unpinnedSource ? std('runtime:fencing:unpinnedSource', 'true') : null,
        a.dangerFlags    ? std('runtime:fencing:bypassConfirmation', 'true') : null,
        a.broadFilesystem ? std('runtime:fencing:filesystemScope', 'broad') : null,
        a.shellAccess    ? std('runtime:fencing:shellExecution', 'true') : null,
        datasetNames.length ? p('datasets', datasetNames.join(', ')) : null,
        meta.architectures?.length ? p('architectures', meta.architectures.join(', ')) : null,
    ].filter(Boolean);
}

// Collapse detected MCP/agent authority into a single coarse scope label, the
// value an enterprise reviewer scans for first (Least Agency Principle).
function deriveAgenticAuthority(meta) {
    if (meta.role !== 'mcp-server') return null;
    const a = meta.authority || {};
    if (a.shellAccess)     return 'shell-execution';
    if (a.broadFilesystem) return 'filesystem-broad';
    if (meta.requiresAuth) return 'scoped';
    return 'unscoped';
}

function buildDependencies(components) {
    // CycloneDX dependencies: { ref: purl, dependsOn: [purl, ...] }
    // Include every component even if it has no deps (explicit empty array = leaf node)
    return components.map((comp) => ({
        ref: comp.purl,
        dependsOn: comp.dependsOn || [],
    }));
}

/**
 * Build CycloneDX 1.6 top-level vulnerabilities array from in-memory components.
 * Each (vuln-id, affected-purl) pair becomes one entry.
 */
function buildVulnerabilities(components) {
    const seen  = new Set();
    const vulns = [];

    for (const comp of components) {
        for (const v of (comp.vulnerabilities || [])) {
            const key = `${v.id}::${comp.purl}`;
            if (seen.has(key)) continue;
            seen.add(key);

            const cveAlias = v.aliases?.find((a) => a.startsWith('CVE-')) || null;
            const entry    = {
                'bom-ref': `vuln-${v.id}`,
                id:         v.id,
                source:     { name: 'OSV', url: v.url },
                affects:    [{ ref: comp.purl }],
                description: v.summary || '',
            };

            if (v.cvss) {
                entry.ratings = [{
                    score:    parseFloat(v.cvss) || null,
                    severity: (v.severity || 'unknown').toLowerCase(),
                    method:   'CVSSv3',
                }];
            }

            if (cveAlias) {
                entry.advisories = [{ url: `https://nvd.nist.gov/vuln/detail/${cveAlias}`, title: cveAlias }];
            }

            vulns.push(entry);
        }
    }

    return vulns;
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

// ── Structural validator ──────────────────────────────────────────────────────
// Lightweight check against CycloneDX 1.x minimum shape.
// Returns { valid: true } or { valid: false, errors: string[] }.
// Used by the pipeline (to assert our own output) and by the API ingest endpoint
// (to reject malformed external payloads before touching the DB).

const SUPPORTED_SPEC_VERSIONS = new Set(['1.4', '1.5', '1.6', '1.7']);

function validateCycloneDX(doc) {
    const errors = [];

    if (!doc || typeof doc !== 'object') {
        return { valid: false, errors: ['document must be an object'] };
    }
    if (doc.bomFormat !== 'CycloneDX') {
        errors.push(`bomFormat must be 'CycloneDX', got '${doc.bomFormat}'`);
    }
    if (!SUPPORTED_SPEC_VERSIONS.has(doc.specVersion)) {
        errors.push(`specVersion must be one of ${[...SUPPORTED_SPEC_VERSIONS].join(', ')}, got '${doc.specVersion}'`);
    }
    if (!Array.isArray(doc.components)) {
        errors.push('components must be an array');
    } else if (doc.components.length > 20000) {
        errors.push(`components exceeds maximum (20000), got ${doc.components.length}`);
    } else {
        // Spot-check first 50 components for minimum required fields
        const sample = doc.components.slice(0, 50);
        for (let i = 0; i < sample.length; i++) {
            const c = sample[i];
            if (!c || typeof c !== 'object') {
                errors.push(`components[${i}] must be an object`); continue;
            }
            if (!c.name)    errors.push(`components[${i}].name is required`);
            if (!c.version) errors.push(`components[${i}].version is required`);
        }
    }
    if (doc.metadata !== undefined && typeof doc.metadata !== 'object') {
        errors.push('metadata must be an object if present');
    }
    if (doc.vulnerabilities !== undefined && !Array.isArray(doc.vulnerabilities)) {
        errors.push('vulnerabilities must be an array if present');
    }

    return errors.length === 0 ? { valid: true } : { valid: false, errors };
}

module.exports = { generateCycloneDX, validateCycloneDX };
