'use strict';

/**
 * AI Bill of Materials (AI BOM) — enrichment and threat assessment.
 *
 * Detects AI/ML components in a project, enriches them with HuggingFace Hub
 * metadata, and assesses supply-chain threats specific to AI pipelines:
 *
 *   AI-001  Unsafe serialization (pickle)          — CRITICAL
 *   AI-002  Unverified model weights               — HIGH
 *   AI-003  Unverified training data               — HIGH
 *   AI-004  Missing model provenance               — MEDIUM
 *   AI-005  Compromised pretrained model import    — HIGH
 *   AI-006  Restrictive model license              — MEDIUM
 *   AI-007  External AI API dependency             — LOW
 *   AI-008  Adversarial retraining risk            — HIGH
 */

const path = require('path');
const {
    detectAIArtifacts,
    parseHFConfig,
    parseGGUFHeader,
    scanPythonFilesForModelIds,
    scanEnvFilesForModels,
    AI_PYTHON_PACKAGES,
} = require('./parsers/aimodel');

const HF_API_BASE = 'https://huggingface.co/api/models';

// Licenses that restrict commercial/derivative use
const RESTRICTED_LICENSES = new Set([
    'llama2', 'llama3', 'llama3.1', 'llama3.2', 'llama3.3',
    'gemma', 'gemma2',
    'cc-by-nc-4.0', 'cc-by-nc-sa-4.0',
    'creativeml-openrail-m', 'bigscience-openrail-m', 'bigscience-bloom-rail-1.0',
    'other',
]);

// ── Threat catalogue ──────────────────────────────────────────────────────────

const THREATS = {
    UNSAFE_PICKLE: {
        id: 'AI-001', severity: 'CRITICAL',
        name: 'Unsafe serialization (pickle)',
        description:
            'PyTorch .pt / pytorch_model.bin files use Python pickle, which can execute ' +
            'arbitrary code at load time. A tampered weights file can fully compromise the host process.',
        mitigations: [
            'Migrate weights to safetensors format (pip install safetensors)',
            'Run Picklescan on every .pt/.bin before loading from external sources',
            'Never load .pt/.bin from untrusted or unverified origins',
        ],
    },
    UNVERIFIED_WEIGHTS: {
        id: 'AI-002', severity: 'HIGH',
        name: 'Model weights without integrity proof',
        description:
            'Local model files have no cryptographic hash recorded in the SBOM. ' +
            'Silently replaced or tampered weights alter model behaviour without ' +
            'triggering any existing vulnerability scanner.',
        mitigations: [
            'Pin the model to a specific commit SHA on HuggingFace Hub',
            'Record SHA-256 of each weights file in your model registry',
            'Use Sigstore / cosign for model artifact signing',
        ],
    },
    DATA_POISONING: {
        id: 'AI-003', severity: 'HIGH',
        name: 'Unverified training data / fine-tuning pipeline',
        description:
            'Training scripts or fine-tuning artifacts were found but no dataset ' +
            'provenance is documented. An adversary who controls any part of the ' +
            'training corpus can implant backdoors via data poisoning.',
        mitigations: [
            'Record dataset source, version, and hash in the model card',
            'Audit training data for poisoning indicators before each fine-tuning run',
            'Apply dataset versioning (DVC, HuggingFace datasets with pinned revision)',
        ],
    },
    NO_PROVENANCE: {
        id: 'AI-004', severity: 'MEDIUM',
        name: 'Missing model provenance',
        description:
            'A model artifact was found but its origin cannot be traced to a published ' +
            'model card or registry entry. Unknown provenance makes supply-chain compromise undetectable.',
        mitigations: [
            'Document the model source, version, and download URL',
            'Link to the official model card or Hub page',
            'Register the model in an internal model registry with lineage tracking',
        ],
    },
    COMPROMISED_PRETRAINED: {
        id: 'AI-005', severity: 'HIGH',
        name: 'Unverified pretrained model import',
        description:
            'The application fetches a pretrained model at runtime (from_pretrained or ' +
            'equivalent). If the upstream model is silently updated, backdoored, or ' +
            'disabled, the change takes effect without any code change or build.',
        mitigations: [
            'Pin the model to a specific revision: from_pretrained("org/model", revision="<sha>")',
            'Mirror approved models to a private registry rather than pulling from Hub at runtime',
            'Audit the model on every dependency update cycle',
        ],
    },
    RESTRICTED_LICENSE: {
        id: 'AI-006', severity: 'MEDIUM',
        name: 'Restrictive model license',
        description:
            'The model is published under a license that restricts commercial use, ' +
            'derivative works, or imposes attribution obligations ' +
            '(RAIL, CC-BY-NC, Llama community license, etc.).',
        mitigations: [
            'Review license terms with legal before production deployment',
            'Evaluate permissively-licensed alternatives (Apache-2.0, MIT)',
        ],
    },
    EXTERNAL_API: {
        id: 'AI-007', severity: 'LOW',
        name: 'External AI API dependency',
        description:
            'Application logic depends on an external AI provider API. ' +
            'Provider outages, pricing changes, policy changes, or supply-chain compromise ' +
            'at the provider directly affect availability and model behaviour.',
        mitigations: [
            'Implement fallback logic for API unavailability',
            'Monitor provider deprecation and breaking-change notices',
            'Evaluate on-premise or self-hosted alternatives for critical inference paths',
        ],
    },
    ADVERSARIAL_RETRAIN: {
        id: 'AI-008', severity: 'HIGH',
        name: 'Adversarial retraining risk',
        description:
            'A custom fine-tuning pipeline was detected. Without audit controls on ' +
            'who can trigger retraining and with what data, an insider threat or ' +
            'CI/CD compromise can retrain the model with poisoned data and redeploy silently.',
        mitigations: [
            'Require approval gates for every fine-tuning run',
            'Log all retraining jobs with dataset provenance in an immutable audit trail',
            'Apply differential privacy during fine-tuning (DP-SGD) to limit memorisation',
        ],
    },
};

// ── HuggingFace Hub metadata fetch ───────────────────────────────────────────

async function fetchHFMeta(modelId, { timeout = 8000 } = {}) {
    if (!modelId || !modelId.includes('/')) return null;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
        const res = await fetch(`${HF_API_BASE}/${encodeURIComponent(modelId)}`, {
            signal:  controller.signal,
            headers: { 'User-Agent': 'packrai-aibom/1.0' },
        });
        if (!res.ok) return null;
        const d = await res.json();
        return {
            modelId:      d.modelId || d.id || modelId,
            sha:          d.sha          || null,
            pipeline:     d.pipeline_tag || null,
            license:      d.cardData?.license || null,
            datasets:     d.cardData?.datasets || [],
            baseModel:    d.cardData?.base_model || null,
            tags:         d.tags || [],
            gated:        !!d.gated,
            disabled:     !!d.disabled,
            author:       modelId.split('/')[0],
            lastModified: d.lastModified || null,
        };
    } catch {
        return null;
    } finally {
        clearTimeout(timer);
    }
}

// ── Component factories ───────────────────────────────────────────────────────

function makeHFComponent(modelId, config) {
    const name    = modelId || config?.modelType || 'unknown-model';
    const version = 'local';
    const purl    = modelId
        ? `pkg:huggingface/${modelId.replace(/^\/+/, '')}@local`
        : `pkg:generic/${encodeURIComponent(name)}@local`;
    return {
        type: 'machine-learning-model', name, version,
        ecosystem: 'ai', purl, scope: 'required',
        licenses: [], hashes: [], dependsOn: [], vulnerabilities: [],
        aiMetadata: {
            role:          'model-weights',
            source:        'local',
            modelType:     config?.modelType     || null,
            architectures: config?.architectures || [],
            torchDtype:    config?.torchDtype    || null,
        },
        modelCard: {
            modelParameters: {
                architectureFamily: config?.architectures?.[0] || config?.modelType || null,
                modelType: 'generative',
            },
        },
    };
}

function makeCodeRefComponent(modelId, sourceFile) {
    const purl = modelId.includes('/')
        ? `pkg:huggingface/${modelId.replace(/^\/+/, '')}@unpinned`
        : `pkg:generic/${encodeURIComponent(modelId)}@unpinned`;
    return {
        type: 'machine-learning-model', name: modelId, version: 'unpinned',
        ecosystem: 'ai', purl, scope: 'required',
        licenses: [], hashes: [], dependsOn: [], vulnerabilities: [],
        aiMetadata: { role: 'code-reference', source: 'code-reference', referencedIn: sourceFile },
        modelCard: { modelParameters: { modelType: 'generative' } },
    };
}

function makeGGUFComponent(filePath, header) {
    const name = path.basename(filePath).replace(/\.(gguf|ggml)$/i, '');
    return {
        type: 'machine-learning-model', name, version: 'local',
        ecosystem: 'ai',
        purl: `pkg:generic/${encodeURIComponent(name)}@local`,
        scope: 'required', licenses: [], hashes: [], dependsOn: [], vulnerabilities: [],
        aiMetadata: {
            role: 'model-weights', format: 'gguf', source: 'local', localPath: filePath,
            ggufVersion:  header?.version      || null,
            fileSizeMB:   header ? Math.round(header.fileSizeBytes / 1_048_576) : null,
        },
        modelCard: { modelParameters: { modelType: 'quantized' } },
    };
}

function makeONNXComponent(filePath) {
    const name = path.basename(filePath).replace(/\.onnx$/i, '');
    return {
        type: 'machine-learning-model', name, version: 'local',
        ecosystem: 'ai',
        purl: `pkg:generic/${encodeURIComponent(name)}@local`,
        scope: 'required', licenses: [], hashes: [], dependsOn: [], vulnerabilities: [],
        aiMetadata: { role: 'model-weights', format: 'onnx', source: 'local', localPath: filePath },
        modelCard: { modelParameters: { modelType: 'inference-optimized' } },
    };
}

function makeAPIComponent(pkg) {
    const labels = {
        openai: 'OpenAI', anthropic: 'Anthropic', google: 'Google Gemini',
        cohere: 'Cohere', mistral: 'Mistral AI', together: 'Together AI',
        groq: 'Groq', aws: 'AWS Bedrock',
    };
    const label = labels[pkg.provider] || pkg.label;
    return {
        type: 'machine-learning-model', name: `${label} API`, version: pkg.version || 'unknown',
        ecosystem: 'ai',
        purl: `pkg:pypi/${encodeURIComponent(pkg.name)}@${pkg.version || 'unknown'}`,
        scope: 'required', licenses: [], hashes: [], dependsOn: [], vulnerabilities: [],
        aiMetadata: { role: 'api-provider', provider: label, sdkPackage: pkg.name, sdkVersion: pkg.version },
        modelCard: { modelParameters: { modelType: 'api-hosted' } },
    };
}

function makeFrameworkComponent(label, role) {
    const slug = label.toLowerCase().replace(/[^a-z0-9]+/g, '-');
    return {
        type: 'machine-learning-model', name: label, version: 'unknown',
        ecosystem: 'ai',
        purl: `pkg:generic/${slug}@unknown`,
        scope: 'required', licenses: [], hashes: [], dependsOn: [], vulnerabilities: [],
        aiMetadata: { role, label },
        modelCard: { modelParameters: { modelType: 'framework' } },
    };
}

// Apply HF Hub metadata to a component in place
function enrichWithHFMeta(comp, meta) {
    if (meta.sha) {
        comp.version = meta.sha.slice(0, 12);
        comp.hashes  = [{ alg: 'SHA-1', content: meta.sha }];
        comp.purl    = comp.purl.replace(/@[^@]*$/, `@${comp.version}`);
    }
    if (meta.license) comp.licenses = [meta.license];
    if (meta.pipeline) comp.modelCard.modelParameters.task      = meta.pipeline;
    if (meta.baseModel) comp.modelCard.modelParameters.baseModel = meta.baseModel;
    Object.assign(comp.aiMetadata, {
        source:       'huggingface',
        sha:          meta.sha,
        pipeline:     meta.pipeline,
        baseModel:    meta.baseModel,
        datasets:     meta.datasets,
        gated:        meta.gated,
        author:       meta.author,
        lastModified: meta.lastModified,
    });
}

// ── Threat helpers ────────────────────────────────────────────────────────────

function threat(template, component, extra = {}) {
    return { ...template, component, ...extra };
}

function deduplicateThreats(threats) {
    const seen = new Set();
    return threats.filter(t => {
        const key = `${t.id}::${t.component}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
}

// ── Local detection (synchronous, filesystem-only, NO network) ────────────────
//
// This is the hot path — it mirrors lock-file parsing: pure local work that
// completes in milliseconds. All network-bound work (HuggingFace Hub lookups)
// is deferred to enrichAIComponents() so it can run in parallel with OSV or be
// skipped entirely on the server's fast scan path.

/**
 * @param {string}   dir              - project root directory
 * @param {object[]} pythonComponents - library components from parsers (ecosystem='pypi')
 * @returns {{ components, threats, enrichTargets, hasLocalWeights, hfModelComps, frameworkCount }}
 */
function detectAILocal(dir, pythonComponents = []) {
    const components = [];
    const threats    = [];

    // ── 1. Classify Python dependencies ──────────────────────────────────────
    const apiPackages    = [];
    const frameworksSeen = new Map(); // label → meta (dedup torch + torchvision → one PyTorch)

    for (const comp of pythonComponents) {
        const meta = AI_PYTHON_PACKAGES[comp.name.toLowerCase()];
        if (!meta) continue;
        if (meta.role === 'api-sdk') {
            apiPackages.push({ ...meta, name: comp.name, version: comp.version });
        } else if (!frameworksSeen.has(meta.label)) {
            frameworksSeen.set(meta.label, meta);
        }
    }

    // ── 2. External API provider components ───────────────────────────────────
    for (const pkg of apiPackages) {
        components.push(makeAPIComponent(pkg));
        threats.push(threat(THREATS.EXTERNAL_API, `${pkg.label} API`));
    }

    // ── 3. AI framework / tooling components ─────────────────────────────────
    const frameworkComponents = [];
    for (const [label, meta] of frameworksSeen) {
        frameworkComponents.push(makeFrameworkComponent(label, meta.role));
    }

    // ── 4. Scan directory for model artifacts (single filesystem walk) ────────
    const artifacts = detectAIArtifacts(dir);

    // 4a. HF config.json → local model weights
    const hfDirs = new Map(); // modelDir → { config, comp }
    for (const { path: cfgPath, dir: modelDir } of artifacts.hfConfigs) {
        if (hfDirs.has(modelDir)) continue;
        const config = parseHFConfig(cfgPath);
        if (!config) continue;
        const comp = makeHFComponent(config.modelId, config);
        hfDirs.set(modelDir, { config, comp });
        components.push(comp);
    }

    // 4b. Python source & .env scanning for model IDs referenced at runtime
    const codeRefs = scanPythonFilesForModelIds(artifacts.pythonFiles);
    const envRefs  = scanEnvFilesForModels(artifacts.envFiles);
    const localIds = new Set(
        [...hfDirs.values()].map(({ config }) => config.modelId).filter(Boolean)
    );

    const uniqueCodeRefs = new Map();
    for (const ref of [...codeRefs, ...envRefs]) {
        if (ref.modelId && !localIds.has(ref.modelId) && !uniqueCodeRefs.has(ref.modelId)) {
            uniqueCodeRefs.set(ref.modelId, ref);
        }
    }
    for (const ref of uniqueCodeRefs.values()) {
        const comp = makeCodeRefComponent(ref.modelId, ref.sourceFile);
        components.push(comp);
        threats.push(threat(THREATS.COMPROMISED_PRETRAINED, ref.modelId));
    }

    // 4c. Standalone GGUF files (dirs without an HF config)
    for (const { path: fp } of artifacts.ggufFiles) {
        if (hfDirs.has(path.dirname(fp))) continue;
        const header = parseGGUFHeader(fp);
        const comp   = makeGGUFComponent(fp, header);
        components.push(comp);
        threats.push(threat(THREATS.UNVERIFIED_WEIGHTS, comp.name));
    }

    // 4d. Standalone ONNX files
    for (const { path: fp } of artifacts.onnxFiles) {
        if (hfDirs.has(path.dirname(fp))) continue;
        const comp = makeONNXComponent(fp);
        components.push(comp);
        threats.push(threat(THREATS.UNVERIFIED_WEIGHTS, comp.name));
    }

    // 4e. PyTorch pickle files → CRITICAL threat regardless of dir
    for (const { path: fp } of artifacts.pytorchBins) {
        const modelDir  = path.dirname(fp);
        const modelName = hfDirs.get(modelDir)?.comp?.name || path.basename(fp);
        threats.push(threat(THREATS.UNSAFE_PICKLE, modelName, { file: fp }));
    }

    // 4f. Training artifacts → data poisoning + adversarial retraining risks
    if (artifacts.trainingArtifacts.length > 0) {
        threats.push(threat(THREATS.DATA_POISONING,       'fine-tuning pipeline'));
        threats.push(threat(THREATS.ADVERSARIAL_RETRAIN,  'fine-tuning pipeline'));
    }

    const allComponents = [...components, ...frameworkComponents];

    // Build the list of Hub-resolvable targets for the async enrichment phase
    const enrichTargets = [
        ...[...hfDirs.values()].map(({ config, comp }) => ({ modelId: config.modelId, comp })),
        ...components
            .filter(c => c.aiMetadata?.source === 'code-reference' && c.name.includes('/'))
            .map(c => ({ modelId: c.name, comp: c })),
    ].filter(({ modelId }) => Boolean(modelId));

    return {
        components:      allComponents,
        threats,
        enrichTargets,
        hasLocalWeights: artifacts.safetensors.length > 0 || artifacts.pytorchBins.length > 0,
        hfModelComps:    [...hfDirs.values()].map(({ comp }) => comp),
        frameworkCount:  frameworkComponents.length,
    };
}

// ── Async enrichment (network: HuggingFace Hub) ───────────────────────────────
//
// Mirrors OSV enrichment: best-effort, parallelizable, never required for a
// usable result. Mutates the target components in place and returns the threats
// that can only be determined from Hub metadata (provenance, restricted license).

/**
 * @param {Array<{ modelId, comp }>} enrichTargets - from detectAILocal()
 * @param {object} [opts] - { timeout }
 * @returns {Promise<{ threats: object[] }>}
 */
async function enrichAIComponents(enrichTargets = [], opts = {}) {
    const extraThreats = [];
    await Promise.all(enrichTargets.map(async ({ modelId, comp }) => {
        const meta = await fetchHFMeta(modelId, opts);
        if (!meta) {
            extraThreats.push(threat(THREATS.NO_PROVENANCE, modelId));
            return;
        }
        enrichWithHFMeta(comp, meta);
        if (meta.license && RESTRICTED_LICENSES.has(meta.license.toLowerCase())) {
            extraThreats.push(threat(THREATS.RESTRICTED_LICENSE, comp.name,
                { description: `${THREATS.RESTRICTED_LICENSE.description} (${meta.license})` }));
        }
    }));
    return { threats: extraThreats };
}

// Assemble the final result from a local detection + (optional) enrichment.
function finalizeAIResult(local) {
    // After enrichment, local HF model dirs still lacking a Hub SHA but with
    // weight files present → flag as unverified weights.
    for (const comp of local.hfModelComps) {
        if (!comp.hashes.length && local.hasLocalWeights) {
            local.threats.push(threat(THREATS.UNVERIFIED_WEIGHTS, comp.name));
        }
    }

    const threats       = deduplicateThreats(local.threats);
    const allComponents = local.components;

    return {
        components: allComponents,
        threats,
        stats: {
            aiModels:        allComponents.filter(c =>
                c.aiMetadata?.role === 'model-weights' || c.aiMetadata?.role === 'code-reference').length,
            apiProviders:    allComponents.filter(c => c.aiMetadata?.role === 'api-provider').length,
            frameworks:      local.frameworkCount,
            aiThreats:       threats.length,
            criticalThreats: threats.filter(t => t.severity === 'CRITICAL').length,
            highThreats:     threats.filter(t => t.severity === 'HIGH').length,
        },
    };
}

// ── Combined entry point (backward-compatible) ────────────────────────────────

/**
 * Detect, classify, and (optionally) enrich all AI components in a project.
 *
 * @param {string}   dir              - project root directory
 * @param {object[]} pythonComponents - library components from parsers (ecosystem='pypi')
 * @param {object}   [opts]           - { enrich=true, timeout }
 * @returns {Promise<{ components, threats, stats }>}
 */
async function detectAIComponents(dir, pythonComponents = [], opts = {}) {
    const local = detectAILocal(dir, pythonComponents);
    if (opts.enrich !== false) {
        const { threats } = await enrichAIComponents(local.enrichTargets, opts);
        local.threats.push(...threats);
    }
    return finalizeAIResult(local);
}

module.exports = {
    detectAIComponents,   // combined (CLI default)
    detectAILocal,        // sync, fast, no network
    enrichAIComponents,   // async, network (HF Hub)
    finalizeAIResult,
    fetchHFMeta,
    THREATS,
};
