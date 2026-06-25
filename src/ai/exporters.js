'use strict';

/**
 * Export adapters that push the AI BOM into existing MLOps / AI governance tools.
 *
 * Each adapter has two parts kept deliberately separate:
 *   • format(aiBom)  — pure, offline transform into the target tool's schema.
 *                      Always available, no network, unit-testable.
 *   • push(payload, cfg) — best-effort network call to the tool's ingestion API.
 *                      Requires credentials; returns { ok, detail } and never throws
 *                      into the caller's pipeline.
 *
 * Supported targets:
 *   mlflow    — logs lineage + threats as params/tags/artifact on an MLflow run
 *   wandb     — emits a W&B Artifact manifest (lineage as artifact, threats as metadata)
 *   truera    — TruEra/TruLens model-metadata record for governance dashboards
 *   snowflake — Snowflake AI Defense / model-registry row payload
 */

// ── MLflow ────────────────────────────────────────────────────────────────────
// Maps to the MLflow Tracking REST API shape (params, tags, and a logged JSON artifact).
function formatMLflow(aiBom) {
    const params = {
        'aibom.ai_models':     aiBom.summary.aiModels,
        'aibom.api_providers': aiBom.summary.apiProviders,
        'aibom.frameworks':    aiBom.summary.frameworks,
        'aibom.lineage_stages': aiBom.lineage.length,
    };
    const tags = {
        'aibom.spec':              aiBom.bomFormat,
        'aibom.lineage_intact':    String(aiBom.lineageVerification?.valid ?? false),
        'aibom.signature':         aiBom.signature?.algorithm || 'unsigned',
        'aibom.pqc':               aiBom.signature?.pqc?.algorithm || aiBom.signature?.pqc?.status || 'none',
        'aibom.critical_threats':  String(aiBom.summary.criticalThreats),
        'aibom.high_threats':      String(aiBom.summary.highThreats),
        'aibom.compliance_pct':    String(aiBom.compliance?.summary.coveragePct ?? 0),
    };
    return {
        target: 'mlflow',
        params,
        tags,
        artifact: { path: 'aibom.json', content: aiBom },
    };
}

async function pushMLflow(payload, cfg) {
    // cfg: { trackingUri, runId, token? }
    if (!cfg?.trackingUri || !cfg?.runId) return { ok: false, detail: 'trackingUri and runId required' };
    const headers = { 'Content-Type': 'application/json', ...(cfg.token ? { Authorization: `Bearer ${cfg.token}` } : {}) };
    try {
        // Batch params + tags in one call (MLflow log-batch endpoint)
        const body = {
            run_id: cfg.runId,
            params: Object.entries(payload.params).map(([key, value]) => ({ key, value: String(value) })),
            tags:   Object.entries(payload.tags).map(([key, value]) => ({ key, value: String(value) })),
        };
        const r = await fetch(`${cfg.trackingUri.replace(/\/$/, '')}/api/2.0/mlflow/runs/log-batch`, {
            method: 'POST', headers, body: JSON.stringify(body),
        });
        return { ok: r.ok, detail: r.ok ? 'logged params + tags' : `HTTP ${r.status}` };
    } catch (e) {
        return { ok: false, detail: e.message };
    }
}

// ── Weights & Biases ──────────────────────────────────────────────────────────
// W&B Artifact manifest — lineage becomes an artifact, threats/compliance become metadata.
function formatWandB(aiBom) {
    return {
        target: 'wandb',
        artifact: {
            name: `aibom-${aiBom.subject.name}`,
            type: 'ai-bom',
            metadata: {
                models:           aiBom.summary.aiModels,
                lineage_stages:   aiBom.lineage.length,
                lineage_intact:   aiBom.lineageVerification?.valid ?? false,
                signature:        aiBom.signature?.algorithm || 'unsigned',
                pqc:              aiBom.signature?.pqc?.algorithm || aiBom.signature?.pqc?.status || 'none',
                critical_threats: aiBom.summary.criticalThreats,
                high_threats:     aiBom.summary.highThreats,
                compliance_pct:   aiBom.compliance?.summary.coveragePct ?? 0,
            },
            // W&B lineage edges: each stage input → output forms a dependency edge
            files: { 'aibom.json': aiBom },
        },
    };
}

async function pushWandB(payload, cfg) {
    // W&B artifact upload is a multi-step GraphQL + file flow; we surface the manifest
    // and let the caller's `wandb` Python/CLI run consume it. Document, don't fake.
    if (!cfg?.apiKey) return { ok: false, detail: 'W&B push requires the wandb SDK; manifest emitted for `wandb artifact put`' };
    return { ok: false, detail: 'use the emitted manifest with the wandb SDK/CLI (no direct REST upload)' };
}

// ── TruEra / TruLens ──────────────────────────────────────────────────────────
function formatTruEra(aiBom) {
    return {
        target: 'truera',
        model_metadata: {
            model_name:    aiBom.subject.name,
            model_version: aiBom.subject.version,
            provenance: aiBom.lineage.map((r) => ({
                stage:     r.stage,
                artifact:  r.artifact?.name,
                record_hash: r.recordHash,
                actor:     r.actor,
                timestamp: r.timestamp,
            })),
            governance: {
                signed:          !!aiBom.signature?.value,
                signature_alg:   aiBom.signature?.algorithm || null,
                pqc:             aiBom.signature?.pqc?.algorithm || aiBom.signature?.pqc?.status || 'none',
                lineage_intact:  aiBom.lineageVerification?.valid ?? false,
                risk_findings:   aiBom.threats.map((t) => ({ id: t.id, severity: t.severity, name: t.name })),
                compliance:      aiBom.compliance?.summary || null,
            },
        },
    };
}

async function pushTruEra(payload, cfg) {
    if (!cfg?.connectionString || !cfg?.token) return { ok: false, detail: 'connectionString and token required' };
    try {
        const r = await fetch(`${cfg.connectionString.replace(/\/$/, '')}/api/v1/models/metadata`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${cfg.token}` },
            body: JSON.stringify(payload.model_metadata),
        });
        return { ok: r.ok, detail: r.ok ? 'metadata posted' : `HTTP ${r.status}` };
    } catch (e) {
        return { ok: false, detail: e.message };
    }
}

// ── Snowflake AI Defense / Model Registry ─────────────────────────────────────
// Emits a row payload suitable for INSERT into a governance table or the
// Snowflake Model Registry's metadata, plus the SQL to land it.
function formatSnowflake(aiBom) {
    const row = {
        MODEL_NAME:       aiBom.subject.name,
        MODEL_VERSION:    aiBom.subject.version,
        SCANNED_AT:       aiBom.generatedAt,
        LINEAGE_HEAD:     aiBom.lineageHead,
        LINEAGE_INTACT:   aiBom.lineageVerification?.valid ?? false,
        SIGNED:           !!aiBom.signature?.value,
        SIGNATURE_ALG:    aiBom.signature?.algorithm || null,
        PQC_ALG:          aiBom.signature?.pqc?.algorithm || aiBom.signature?.pqc?.status || null,
        CRITICAL_THREATS: aiBom.summary.criticalThreats,
        HIGH_THREATS:     aiBom.summary.highThreats,
        COMPLIANCE_PCT:   aiBom.compliance?.summary.coveragePct ?? 0,
        AIBOM:            aiBom,                     // landed as VARIANT
    };
    const sql =
        'INSERT INTO AI_GOVERNANCE.PUBLIC.AI_BOM\n' +
        '  (MODEL_NAME, MODEL_VERSION, SCANNED_AT, LINEAGE_HEAD, LINEAGE_INTACT,\n' +
        '   SIGNED, SIGNATURE_ALG, PQC_ALG, CRITICAL_THREATS, HIGH_THREATS, COMPLIANCE_PCT, AIBOM)\n' +
        'SELECT ?,?,?,?,?,?,?,?,?,?,?, PARSE_JSON(?);';
    return { target: 'snowflake', row, sql };
}

async function pushSnowflake(payload, cfg) {
    // Snowflake ingestion goes through the SQL API or a connector; we provide the
    // bound statement and row. Direct push needs the snowflake-sdk + key-pair auth.
    if (!cfg?.account) return { ok: false, detail: 'use the emitted SQL + row with snowflake-sdk (key-pair auth)' };
    return { ok: false, detail: 'emitted bound SQL; execute via snowflake-sdk or Snowpipe' };
}

// ── Registry ──────────────────────────────────────────────────────────────────
const ADAPTERS = {
    mlflow:    { format: formatMLflow,    push: pushMLflow    },
    wandb:     { format: formatWandB,     push: pushWandB     },
    truera:    { format: formatTruEra,    push: pushTruEra    },
    snowflake: { format: formatSnowflake, push: pushSnowflake },
};

function exportAIBom(aiBom, target) {
    const adapter = ADAPTERS[target];
    if (!adapter) throw new Error(`Unknown export target '${target}'. Valid: ${Object.keys(ADAPTERS).join(', ')}`);
    return adapter.format(aiBom);
}

async function pushAIBom(aiBom, target, cfg) {
    const adapter = ADAPTERS[target];
    if (!adapter) throw new Error(`Unknown export target '${target}'`);
    return adapter.push(adapter.format(aiBom), cfg || {});
}

module.exports = { exportAIBom, pushAIBom, ADAPTERS };
