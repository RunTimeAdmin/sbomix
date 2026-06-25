'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs   = require('node:fs');
const os   = require('node:os');
const path = require('node:path');

const { detectAILocal, finalizeAIResult } = require('../src/aibom');
const { parseMCPConfig } = require('../src/parsers/agentic');
const { hashWeightFile, parseHFConfig } = require('../src/parsers/aimodel');
const { generateCycloneDX, validateCycloneDX } = require('../src/generators/cyclonedx');
const { assessCompliance } = require('../src/ai/compliance');

let root;

before(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'packrai-aibom-'));
    const snap = path.join(root, 'models', 'llama', 'snap');
    fs.mkdirSync(snap, { recursive: true });
    fs.mkdirSync(path.join(root, '.cursor'), { recursive: true });
    fs.mkdirSync(path.join(root, 'prompts'), { recursive: true });

    fs.writeFileSync(path.join(snap, 'config.json'), JSON.stringify({
        _name_or_path: 'meta-llama/Llama-3.1-8B', model_type: 'llama',
        architectures: ['LlamaForCausalLM'], torch_dtype: 'bfloat16',
        hidden_size: 4096, num_hidden_layers: 32, vocab_size: 128256,
        max_position_embeddings: 8192, datasets: ['allenai/c4', 'tiiuae/falcon-refinedweb'],
    }));
    fs.writeFileSync(path.join(snap, 'model.safetensors'), Buffer.alloc(4096, 7));
    fs.writeFileSync(path.join(root, '.cursor', 'mcp.json'), JSON.stringify({
        mcpServers: {
            filesystem: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] },
            shell:      { command: 'bash', args: ['-c', 'x'] },
            remote:     { url: 'https://api.example.com/mcp', type: 'sse' },
            github:     { command: 'npx', args: ['@modelcontextprotocol/server-github@1.2.0'], env: { GITHUB_TOKEN: 'x' } },
        },
    }));
    fs.writeFileSync(path.join(root, 'prompts', 'system.prompt'), 'You are an agent.');
    fs.writeFileSync(path.join(root, 'CLAUDE.md'), '# rules');
});

after(() => { try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* ignore */ } });

// ── Pillar 1: weight hashing + architecture/params ────────────────────────────

test('hashWeightFile returns a SHA-256 over file contents', () => {
    const f = path.join(root, 'models', 'llama', 'snap', 'model.safetensors');
    const h = hashWeightFile(f);
    assert.strictEqual(h.alg, 'SHA-256');
    assert.match(h.content, /^[0-9a-f]{64}$/);
    assert.strictEqual(h.sizeBytes, 4096);
});

test('hashWeightFile skips files over the size cap', () => {
    const f = path.join(root, 'models', 'llama', 'snap', 'model.safetensors');
    const h = hashWeightFile(f, 100);
    assert.strictEqual(h.skipped, true);
});

test('parseHFConfig extracts architecture, params, datasets', () => {
    const cfg = parseHFConfig(path.join(root, 'models', 'llama', 'snap', 'config.json'));
    assert.deepStrictEqual(cfg.architectures, ['LlamaForCausalLM']);
    assert.ok(cfg.paramCountEstimate > 0);
    assert.strictEqual(cfg.contextLength, 8192);
    assert.deepStrictEqual(cfg.datasets, ['allenai/c4', 'tiiuae/falcon-refinedweb']);
});

test('detectAILocal attaches a SHA-256 weight hash to the model component', () => {
    const res = finalizeAIResult(detectAILocal(root, []));
    const model = res.components.find(c => c.aiMetadata.role === 'model-weights');
    assert.ok(model.hashes.some(h => h.alg === 'SHA-256'));
});

// ── Pillar 2: datasets as PURLs ───────────────────────────────────────────────

test('datasets become data components with huggingface PURLs', () => {
    const res = finalizeAIResult(detectAILocal(root, []));
    const datasets = res.components.filter(c => c.aiMetadata.role === 'dataset');
    assert.strictEqual(datasets.length, 2);
    assert.ok(datasets.every(d => d.type === 'data'));
    assert.ok(datasets.some(d => d.purl === 'pkg:huggingface/dataset/allenai/c4@unknown'));
});

// ── Pillar 3: framework versions ──────────────────────────────────────────────

test('framework components carry the detected version', () => {
    const res = finalizeAIResult(detectAILocal(root, [{ name: 'torch', version: '2.4.1' }]));
    const torch = res.components.find(c => c.name === 'PyTorch');
    assert.strictEqual(torch.version, '2.4.1');
    assert.strictEqual(torch.purl, 'pkg:generic/pytorch@2.4.1');
});

// ── Pillar 4: agentic detection ───────────────────────────────────────────────

test('parseMCPConfig flags shell, broad-fs, unpinned, and remote authority', () => {
    const servers = parseMCPConfig(path.join(root, '.cursor', 'mcp.json'));
    const byName = Object.fromEntries(servers.map(s => [s.name, s]));
    assert.strictEqual(byName.shell.authority.shellAccess, true);
    assert.strictEqual(byName.filesystem.authority.broadFilesystem, true);
    assert.strictEqual(byName.filesystem.authority.unpinnedSource, true);
    assert.strictEqual(byName.github.authority.unpinnedSource, false); // pinned @1.2.0
    assert.strictEqual(byName.remote.transport, 'sse');
    assert.strictEqual(byName.github.requiresAuth, true);
});

test('detectAILocal emits agentic threats and a Least Agency score', () => {
    const res = finalizeAIResult(detectAILocal(root, []));
    const ids = new Set(res.threats.map(t => t.id));
    assert.ok(ids.has('AI-009'), 'excessive agency');   // shell + broad fs
    assert.ok(ids.has('AI-010'), 'unpinned MCP');
    assert.ok(ids.has('AI-011'), 'unauthenticated remote');
    assert.ok(ids.has('AI-012'), 'prompt tampering');
    assert.ok(res.stats.leastAgencyScore < 100);
    assert.strictEqual(res.stats.mcpServers, 4);
    assert.strictEqual(res.stats.prompts, 2);
});

test('prompt components carry a SHA-256 of the prompt file', () => {
    const res = finalizeAIResult(detectAILocal(root, []));
    const prompt = res.components.find(c => c.aiMetadata.role === 'prompt');
    assert.ok(prompt.hashes.some(h => h.alg === 'SHA-256'));
});

// ── Pillar 5: completeness + Article 53 ───────────────────────────────────────

test('CycloneDX output includes a completeness composition', () => {
    const res = finalizeAIResult(detectAILocal(root, [{ name: 'torch', version: '2.4.1' }]));
    const cdx = generateCycloneDX(res.components, { name: 'app', version: '1.0' });
    assert.strictEqual(validateCycloneDX(cdx).valid, true);
    assert.ok(Array.isArray(cdx.compositions));
    assert.ok(cdx.compositions.some(c => c.aggregate === 'incomplete')); // AI components
});

// ── CycloneDX 1.7 ML-BOM structure ────────────────────────────────────────────

test('generator emits CycloneDX 1.7 with metadata bom-ref and tool author', () => {
    const res = finalizeAIResult(detectAILocal(root, [{ name: 'torch', version: '2.4.1' }]));
    const cdx = generateCycloneDX(res.components, { name: 'My-Agent-App', version: '2.1.0' });
    assert.strictEqual(cdx.specVersion, '1.7');
    assert.strictEqual(cdx.metadata.component['bom-ref'], 'app-my-agent-app');
    assert.strictEqual(cdx.metadata.tools.components[0].author, 'packrai.xyz');
});

test('model component gets a rich 1.7 modelCard (derived fields only)', () => {
    const res = finalizeAIResult(detectAILocal(root, []));
    const cdx = generateCycloneDX(res.components, { name: 'app', version: '1.0' });
    const model = cdx.components.find(c => c.type === 'machine-learning-model' && c.modelCard?.modelParameters?.architectureFamily);
    const mp = model.modelCard.modelParameters;
    assert.strictEqual(mp.architectureFamily, 'Transformer');
    assert.strictEqual(mp.modelArchitecture, 'Decoder-only LLM');   // LlamaForCausalLM
    assert.ok(Array.isArray(mp.datasets) && mp.datasets[0].type === 'dataset');
    assert.ok(mp.datasets.some(d => d.contents?.url?.includes('huggingface.co/datasets/')));
    // Context-window limitation is derived (factual), never a fabricated metric
    assert.ok(model.modelCard.considerations.technicalLimitations
        .some(l => /Context window limited to 8192 tokens/.test(l)));
    // No fabricated benchmark numbers
    assert.strictEqual(model.modelCard.quantitativeAnalysis, undefined);
});

test('MCP component carries a standard agentic:authority property', () => {
    const res = finalizeAIResult(detectAILocal(root, []));
    const cdx = generateCycloneDX(res.components, { name: 'app', version: '1.0' });
    const shell = cdx.components.find(c => c.name === 'mcp:shell');
    const authority = shell.properties.find(p => p.name === 'agentic:authority');
    assert.strictEqual(authority.value, 'shell-execution');
    assert.ok(shell.properties.some(p => p.name === 'runtime:fencing:shellExecution'));
});

test('assessCompliance maps EU AI Act Article 53 controls', () => {
    const res = finalizeAIResult(detectAILocal(root, []));
    const out = assessCompliance({
        aiComponents: res.components, threats: res.threats,
        lineage: [], lineageVerify: { valid: true }, signature: { value: 'x', algorithm: 'Ed25519' },
        agentic: res.agentic,
    });
    const art53 = out.controls.filter(c => c.control.includes('Art53'));
    assert.strictEqual(art53.length, 3);
    // architecture detail present → 53.1a satisfied; datasets inventoried → 53.1d satisfied
    assert.strictEqual(art53.find(c => c.control === 'EUAIACT:Art53.1a').status, 'satisfied');
    assert.strictEqual(art53.find(c => c.control === 'EUAIACT:Art53.1d').status, 'satisfied');
});
