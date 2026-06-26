'use strict';

const { test } = require('node:test');
const assert   = require('node:assert');

const { canonicalize, canonicalHash } = require('../src/ai/canonical');
const { buildLineage, verifyLineage, chainHead } = require('../src/ai/lineage');
const { generateClassicalKeyPair, signDocument, verifyDocument, capabilities } = require('../src/ai/sign');
const { buildAIBomDocument, verifyAIBomDocument, serializeAIBom, attachToCycloneDX } = require('../src/ai/document');
const { assessCompliance } = require('../src/ai/compliance');
const { exportAIBom } = require('../src/ai/exporters');

// ── Canonicalization (RFC 8785) ───────────────────────────────────────────────

test('canonicalize sorts object keys deterministically', () => {
    const a = canonicalize({ b: 1, a: 2, c: { z: 1, y: 2 } });
    const b = canonicalize({ a: 2, c: { y: 2, z: 1 }, b: 1 });
    assert.strictEqual(a, b);
    assert.strictEqual(a, '{"a":2,"b":1,"c":{"y":2,"z":1}}');
});

test('canonicalize drops undefined-valued keys', () => {
    assert.strictEqual(canonicalize({ a: 1, b: undefined }), '{"a":1}');
});

test('canonicalHash is stable across key order', () => {
    assert.strictEqual(canonicalHash({ x: 1, y: 2 }), canonicalHash({ y: 2, x: 1 }));
});

// ── Lineage hash chain ────────────────────────────────────────────────────────

const sampleEntries = [
    { stage: 'base-model', artifact: { name: 'base' }, actor: 'hub' },
    { stage: 'fine-tune',  artifact: { name: 'ft' }, inputs: ['base'], actor: 'me' },
    { stage: 'deploy',     artifact: { name: 'app' }, inputs: ['ft'], actor: 'ci' },
];

test('buildLineage links records by prevHash', () => {
    const chain = buildLineage(sampleEntries);
    assert.strictEqual(chain.length, 3);
    assert.strictEqual(chain[0].prevHash, '0'.repeat(64));
    assert.strictEqual(chain[1].prevHash, chain[0].recordHash);
    assert.strictEqual(chain[2].prevHash, chain[1].recordHash);
});

test('verifyLineage accepts an intact chain', () => {
    const chain = buildLineage(sampleEntries);
    assert.strictEqual(verifyLineage(chain).valid, true);
});

test('verifyLineage detects tampering at the broken record', () => {
    const chain = buildLineage(sampleEntries);
    chain[1].actor = 'attacker';
    const res = verifyLineage(chain);
    assert.strictEqual(res.valid, false);
    assert.strictEqual(res.brokenAt, 1);
});

test('buildLineage rejects unknown stages', () => {
    assert.throws(() => buildLineage([{ stage: 'nonsense', artifact: {} }]), /unknown stage/);
});

// ── Signing & verification ────────────────────────────────────────────────────

test('capabilities reports ed25519 as always available', () => {
    assert.strictEqual(capabilities().classical, 'ed25519');
});

test('signDocument + verifyDocument round-trips', () => {
    const keys = generateClassicalKeyPair();
    const doc  = { hello: 'world', n: 42 };
    const sig  = signDocument(doc, { classicalPrivateKey: keys.privateKey, classicalPublicKey: keys.publicKey });
    const res  = verifyDocument(doc, sig);
    assert.strictEqual(res.valid, true);
    assert.strictEqual(res.classical, true);
});

test('verifyDocument rejects a modified document', () => {
    const keys = generateClassicalKeyPair();
    const doc  = { hello: 'world' };
    const sig  = signDocument(doc, { classicalPrivateKey: keys.privateKey, classicalPublicKey: keys.publicKey });
    assert.strictEqual(verifyDocument({ hello: 'tampered' }, sig).valid, false);
});

test('signDocument records PQC as unavailable honestly on OpenSSL 3.0', () => {
    const keys = generateClassicalKeyPair();
    const sig  = signDocument({ a: 1 }, { classicalPrivateKey: keys.privateKey });
    // Either a real PQC sig (3.5+ / external) or an explicit unavailable marker — never silently missing
    assert.ok(sig.pqc.status === 'unavailable' || sig.pqc.value, 'pqc slot must be present');
});

// ── Compliance mapping ────────────────────────────────────────────────────────

test('assessCompliance maps both regimes and computes coverage', () => {
    const chain = buildLineage(sampleEntries);
    const res = assessCompliance({
        aiComponents: [{ aiMetadata: { source: 'huggingface', role: 'model-weights' } }],
        threats: [{ id: 'AI-001' }, { id: 'AI-005' }],
        lineage: chain,
        lineageVerify: { valid: true },
        signature: { value: 'x', algorithm: 'Ed25519' },
    });
    assert.ok(res.regimes.includes('ISO/IEC 42001:2023'));
    assert.ok(res.regimes.some(r => r.startsWith('EU AI Act')));
    assert.ok(res.summary.coveragePct >= 0 && res.summary.coveragePct <= 100);
    assert.strictEqual(res.summary.total, res.controls.length);
});

// ── Full document + exporters ─────────────────────────────────────────────────

const aiComponents = [
    { name: 'meta-llama/Llama-3.1-8B', version: 'abc', purl: 'pkg:huggingface/meta-llama/Llama-3.1-8B@abc',
      type: 'machine-learning-model', licenses: ['llama3.1'], hashes: [{ alg: 'SHA-1', content: 'abc' }],
      aiMetadata: { role: 'model-weights', source: 'huggingface', baseModel: 'meta-llama/Meta-Llama-3-8B' } },
];
const threats = [{ id: 'AI-001', severity: 'CRITICAL', name: 'pickle', component: 'm', description: 'd', mitigations: [] }];

test('buildAIBomDocument produces a verifiable signed attestation', () => {
    const keys = generateClassicalKeyPair();
    const doc  = buildAIBomDocument({
        aiComponents, threats, meta: { name: 'app', version: '1.0' },
        keys: { classicalPrivateKey: keys.privateKey, classicalPublicKey: keys.publicKey },
    });
    const v = verifyAIBomDocument(doc);
    assert.strictEqual(v.lineage.valid, true);
    assert.strictEqual(v.signature.valid, true);
});

test('tampering an assembled AI BOM breaks lineage and signature', () => {
    const keys = generateClassicalKeyPair();
    const doc  = buildAIBomDocument({
        aiComponents, threats, meta: { name: 'app', version: '1.0' },
        keys: { classicalPrivateKey: keys.privateKey, classicalPublicKey: keys.publicKey },
    });
    doc.lineage[0].actor = 'attacker';
    const v = verifyAIBomDocument(doc);
    assert.strictEqual(v.lineage.valid, false);
    assert.strictEqual(v.signature.valid, false);
});

test('serializeAIBom emits valid JSON and YAML', () => {
    const doc = buildAIBomDocument({ aiComponents, threats, meta: { name: 'app', version: '1.0' } });
    assert.doesNotThrow(() => JSON.parse(serializeAIBom(doc, 'json')));
    const yaml = serializeAIBom(doc, 'yaml');
    assert.ok(yaml.includes('bomFormat: SBOMix-AIBOM'));
});

test('attachToCycloneDX adds signature and lineage properties', () => {
    const keys = generateClassicalKeyPair();
    const doc  = buildAIBomDocument({
        aiComponents, threats, meta: { name: 'app', version: '1.0' },
        keys: { classicalPrivateKey: keys.privateKey, classicalPublicKey: keys.publicKey },
    });
    const cdx = { bomFormat: 'CycloneDX', components: [] };
    attachToCycloneDX(cdx, doc);
    assert.strictEqual(cdx.signature.algorithm, 'Ed25519');
    assert.ok(cdx.properties.some(p => p.name === 'sbomix:aibom:lineageHead'));
});

test('all four exporters format without error', () => {
    const doc = buildAIBomDocument({ aiComponents, threats, meta: { name: 'app', version: '1.0' } });
    for (const target of ['mlflow', 'wandb', 'truera', 'snowflake']) {
        const out = exportAIBom(doc, target);
        assert.strictEqual(out.target, target);
    }
});

test('exportAIBom rejects unknown targets', () => {
    const doc = buildAIBomDocument({ aiComponents, threats, meta: { name: 'app', version: '1.0' } });
    assert.throws(() => exportAIBom(doc, 'bogus'), /Unknown export target/);
});
