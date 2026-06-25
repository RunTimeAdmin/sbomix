'use strict';

/**
 * Model lineage as a tamper-evident hash chain.
 *
 * Each lifecycle stage (base model → fine-tune → quantize → package → deploy)
 * becomes a record whose hash incorporates the previous record's hash. Altering
 * any earlier record breaks every hash downstream, so a single signature over
 * the chain head attests to the integrity of the entire lineage — the same
 * property a Merkle/append-only log gives you, scoped to one model's life.
 *
 * This is what backs the AI BOM's "end-to-end provenance" claim: you can prove
 * the deployed weights descend from a known base model through a known, audited
 * sequence of transformations, with no silent substitution in between.
 */

const { canonicalize, sha256 } = require('./canonical');

const GENESIS_PREV = '0'.repeat(64);

const STAGES = new Set([
    'base-model',     // original pretrained model pulled from a registry
    'dataset',        // training / fine-tuning corpus
    'fine-tune',      // a fine-tuning or continued-pretraining run
    'quantize',       // quantization / distillation / pruning
    'evaluation',     // benchmark or red-team evaluation pass
    'package',        // serialization into deployable artifact (safetensors, gguf, onnx)
    'deploy',         // promotion into a serving environment
]);

/**
 * Compute the deterministic hash of a single record.
 * Excludes `recordHash` and `signature` so the hash covers content only.
 */
function hashRecord(record) {
    // Hash covers content only — exclude the hash and signature fields themselves.
    // eslint-disable-next-line no-unused-vars
    const { recordHash, signature, ...content } = record;
    return sha256(canonicalize(content));
}

/**
 * Build a hash-linked lineage chain from an ordered list of stage entries.
 *
 * @param {object[]} entries - each: { stage, artifact, inputs?, properties?, actor?, timestamp? }
 * @returns {object[]} records with index, prevHash, recordHash populated
 */
function buildLineage(entries) {
    const records = [];
    let prevHash = GENESIS_PREV;

    entries.forEach((entry, i) => {
        if (!STAGES.has(entry.stage)) {
            throw new Error(`buildLineage: unknown stage '${entry.stage}'. Valid: ${[...STAGES].join(', ')}`);
        }
        const record = {
            index:     i,
            stage:     entry.stage,
            artifact:  entry.artifact,                       // { name, purl?, sha256?, sizeBytes? }
            inputs:    entry.inputs || [],                   // refs to earlier artifacts / datasets
            actor:     entry.actor || 'unknown',             // who/what produced this stage
            properties: entry.properties || {},              // hyperparameters, dataset hash, etc.
            timestamp: entry.timestamp || new Date().toISOString(),
            prevHash,
        };
        record.recordHash = hashRecord(record);
        prevHash = record.recordHash;
        records.push(record);
    });

    return records;
}

/**
 * Derive a lineage chain from a pipeline result's AI components.
 * Produces a best-effort chain from whatever provenance was detected.
 *
 * @param {object[]} aiComponents - components with ecosystem==='ai'
 * @param {object}   meta         - { name, version }
 */
function lineageFromComponents(aiComponents, meta = {}) {
    const entries = [];

    // Base models first (anything with a resolved HF base or model-weights role)
    const models = aiComponents.filter((c) =>
        c.aiMetadata?.role === 'model-weights' || c.aiMetadata?.role === 'code-reference');

    for (const m of models) {
        const sha = m.hashes?.find((h) => /SHA/i.test(h.alg))?.content;
        if (m.aiMetadata?.baseModel) {
            entries.push({
                stage: 'base-model',
                artifact: { name: m.aiMetadata.baseModel, purl: `pkg:huggingface/${m.aiMetadata.baseModel}` },
                actor: 'huggingface-hub',
            });
            entries.push({
                stage: 'fine-tune',
                artifact: { name: m.name, purl: m.purl, sha256: sha || null },
                inputs: [m.aiMetadata.baseModel],
                actor: m.aiMetadata.author || 'unknown',
                properties: { source: m.aiMetadata.source, datasets: m.aiMetadata.datasets || [] },
            });
        } else {
            entries.push({
                stage: 'base-model',
                artifact: { name: m.name, purl: m.purl, sha256: sha || null },
                actor: m.aiMetadata?.author || m.aiMetadata?.source || 'unknown',
                properties: { pipeline: m.aiMetadata?.pipeline, datasets: m.aiMetadata?.datasets || [] },
            });
        }

        if (m.aiMetadata?.format) {
            entries.push({
                stage: 'package',
                artifact: { name: m.name, purl: m.purl, sha256: sha || null },
                inputs: [m.name],
                actor: 'packrai-detect',
                properties: { format: m.aiMetadata.format },
            });
        }
    }

    // Final deploy stage representing the scanned application
    if (entries.length) {
        entries.push({
            stage: 'deploy',
            artifact: { name: meta.name || 'application', version: meta.version || 'unknown' },
            inputs: models.map((m) => m.name),
            actor: 'packrai-scan',
        });
    }

    return buildLineage(entries);
}

/**
 * Verify the structural integrity of a lineage chain (independent of signature).
 * @returns {{ valid: boolean, brokenAt?: number, reason?: string }}
 */
function verifyLineage(records) {
    let prevHash = GENESIS_PREV;
    for (const r of records) {
        if (r.prevHash !== prevHash) {
            return { valid: false, brokenAt: r.index, reason: 'prevHash does not match preceding recordHash' };
        }
        if (hashRecord(r) !== r.recordHash) {
            return { valid: false, brokenAt: r.index, reason: 'recordHash does not match record content (tampered)' };
        }
        prevHash = r.recordHash;
    }
    return { valid: true };
}

/** The chain head hash — the single value a signature commits to. */
function chainHead(records) {
    return records.length ? records[records.length - 1].recordHash : GENESIS_PREV;
}

module.exports = { buildLineage, lineageFromComponents, verifyLineage, chainHead, STAGES, GENESIS_PREV };
