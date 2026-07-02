'use strict';

/**
 * Integration tests: ingest service + scan queue against a live Postgres DB.
 *
 * Requires DATABASE_URL env var pointing to a test database.
 * Skipped automatically when no DB is reachable.
 */

const { test, before, after } = require('node:test');
const assert = require('node:assert');

let db;
let dbAvailable = false;

before(async () => {
    try {
        db = require('../src/api/db');
        await db.query('SELECT 1');
        dbAvailable = true;
    } catch {
        return;
    }

    await db.query(`DELETE FROM scan_jobs WHERE repo LIKE 'sbomix-test/%'`);
    await db.query(`DELETE FROM sboms WHERE org_id IN (
        SELECT id FROM organizations WHERE email LIKE 'integration-test%@sbomix.test'
    )`);
    await db.query(`DELETE FROM organizations WHERE email LIKE 'integration-test%@sbomix.test'`);
});

after(async () => {
    if (!db) return;
    try {
        if (dbAvailable) {
            await db.query(`DELETE FROM scan_jobs WHERE repo LIKE 'sbomix-test/%'`);
            await db.query(`DELETE FROM organizations WHERE email LIKE 'integration-test%@sbomix.test'`);
        }
    } finally {
        await db.pool.end().catch(() => {});
    }
});

async function createTestOrg() {
    const crypto = require('crypto');
    const hmacSecret = process.env.HMAC_SECRET || 'test-secret';
    const key  = crypto.randomBytes(20).toString('hex');
    const hash = crypto.createHmac('sha256', hmacSecret).update(key).digest('hex');

    // Unique email per call — organizations.email is UNIQUE, and multiple tests
    // each create their own org, so a fixed address would collide.
    const email = `integration-test-${crypto.randomBytes(6).toString('hex')}@sbomix.test`;
    const { rows: [org] } = await db.query(
        `INSERT INTO organizations (name, email, api_key)
         VALUES ('Integration Test Org', $2, $1)
         RETURNING id`,
        [hash, email]
    );
    return { orgId: org.id, apiKey: key };
}

// ── Scan queue ────────────────────────────────────────────────────────────────

test('scan queue: enqueue + claim + done lifecycle', async (t) => {
    if (!dbAvailable) return t.skip('Postgres unavailable');
    const { enqueueScanJob, claimNextScanJob, markScanDone, countActiveScansForOrg }
        = require('../src/api/services/scanQueue');
    const { orgId } = await createTestOrg();

    const jobId = await enqueueScanJob(orgId, 'sbomix-test/lifecycle', 'main');
    assert.ok(jobId, 'job id returned');

    assert.strictEqual(await countActiveScansForOrg(orgId), 1, 'pending counts as active');

    const job = await claimNextScanJob('test-worker-1');
    assert.ok(job, 'job claimed');
    assert.strictEqual(job.repo, 'sbomix-test/lifecycle');

    assert.strictEqual(await countActiveScansForOrg(orgId), 1, 'running counts as active');

    await markScanDone(job.id, 'sbomix-test', null);
    assert.strictEqual(await countActiveScansForOrg(orgId), 0, 'done not counted as active');
});

test('scan queue: timed_out status persisted correctly', async (t) => {
    if (!dbAvailable) return t.skip('Postgres unavailable');
    const { enqueueScanJob, claimNextScanJob, markScanFailed, countActiveScansForOrg }
        = require('../src/api/services/scanQueue');
    const { orgId } = await createTestOrg();

    await enqueueScanJob(orgId, 'sbomix-test/timeout', 'main');
    const job = await claimNextScanJob('test-worker-2');
    assert.ok(job);

    await markScanFailed(job.id, 'Scan timed out', 'timed_out');

    const { rows: [row] } = await db.query(
        'SELECT status FROM scan_jobs WHERE id = $1', [job.id]
    );
    assert.strictEqual(row.status, 'timed_out');
    assert.strictEqual(await countActiveScansForOrg(orgId), 0, 'timed_out not counted as active');
});

test('scan queue: stale job recovery respects max_attempts', async (t) => {
    if (!dbAvailable) return t.skip('Postgres unavailable');
    const { recoverStaleJobs } = require('../src/api/services/scanQueue');
    const { orgId } = await createTestOrg();

    await db.query(
        `INSERT INTO scan_jobs (org_id, repo, ref, status, locked_by, locked_at, attempts, max_attempts)
         VALUES ($1, 'sbomix-test/stale-retry', 'main', 'running',
                 'dead-worker', NOW() - INTERVAL '10 minutes', 1, 2)`,
        [orgId]
    );
    await db.query(
        `INSERT INTO scan_jobs (org_id, repo, ref, status, locked_by, locked_at, attempts, max_attempts)
         VALUES ($1, 'sbomix-test/stale-fail', 'main', 'running',
                 'dead-worker', NOW() - INTERVAL '10 minutes', 2, 2)`,
        [orgId]
    );

    await recoverStaleJobs(5 * 60 * 1000);

    const { rows } = await db.query(
        `SELECT repo, status FROM scan_jobs WHERE org_id = $1 ORDER BY repo`,
        [orgId]
    );
    const byRepo = Object.fromEntries(rows.map((r) => [r.repo, r.status]));
    assert.strictEqual(byRepo['sbomix-test/stale-retry'], 'pending', 'retried job → pending');
    assert.strictEqual(byRepo['sbomix-test/stale-fail'],  'failed',  'exhausted job → failed');
});

// ── Ingest service ────────────────────────────────────────────────────────────

test('ingest: stores SBOM and returns sbomId', async (t) => {
    if (!dbAvailable) return t.skip('Postgres unavailable');
    const { orgId } = await createTestOrg();
    const { executeIngestTx } = require('../src/api/services/ingestService');

    const cyclonedx = {
        bomFormat: 'CycloneDX', specVersion: '1.6', version: 1,
        components: [
            { type: 'library', name: 'express', version: '4.18.2',
              purl: 'pkg:npm/express@4.18.2', hashes: [] },
        ],
        vulnerabilities: [],
    };

    const client = await db.pool.connect();
    try {
        await client.query('BEGIN');
        const { sbomId } = await executeIngestTx(client, orgId, 'ingest-test-app', {
            version: '1.0.0', commit: 'abc1234', branch: 'main',
            cyclonedx, spdx: null, aibom: null,
            stats: { totalComponents: 1, vulnerabilities: 0, critical: 0,
                     qualityScore: 75, ecosystems: ['npm'] },
        });
        await client.query('COMMIT');

        assert.ok(sbomId, 'sbomId returned');
        const { rows: [sbom] } = await db.query(
            'SELECT component_count, aibom FROM sboms WHERE id = $1', [sbomId]
        );
        assert.strictEqual(sbom.component_count, 1);
        assert.strictEqual(sbom.aibom, null);
    } catch (e) {
        await client.query('ROLLBACK');
        throw e;
    } finally {
        client.release();
    }
});

test('ingest: stores AI-BOM as JSONB object, not string', async (t) => {
    if (!dbAvailable) return t.skip('Postgres unavailable');
    const { orgId } = await createTestOrg();
    const { executeIngestTx } = require('../src/api/services/ingestService');

    const cyclonedx = {
        bomFormat: 'CycloneDX', specVersion: '1.6', version: 1,
        components: [], vulnerabilities: [],
    };
    const aibom = {
        schemaVersion: '1.0',
        components: [{ type: 'ml-model', name: 'bert-base-uncased' }],
        threats: [],
    };

    const client = await db.pool.connect();
    try {
        await client.query('BEGIN');
        const { sbomId } = await executeIngestTx(client, orgId, 'aibom-test-app', {
            version: '1.0.0', commit: null, branch: null,
            cyclonedx, spdx: null, aibom,
            stats: { totalComponents: 0, vulnerabilities: 0, critical: 0,
                     qualityScore: 0, ecosystems: [], aiModels: 1, aiThreats: 0, aiCritical: 0 },
        });
        await client.query('COMMIT');

        const { rows: [sbom] } = await db.query(
            'SELECT aibom, ai_models FROM sboms WHERE id = $1', [sbomId]
        );
        assert.strictEqual(typeof sbom.aibom, 'object', 'aibom stored as object, not string');
        assert.ok(sbom.aibom !== null);
        assert.deepStrictEqual(sbom.aibom.components[0].name, 'bert-base-uncased');
    } catch (e) {
        await client.query('ROLLBACK');
        throw e;
    } finally {
        client.release();
    }
});

test('ingest: duplicate app name reuses same app row', async (t) => {
    if (!dbAvailable) return t.skip('Postgres unavailable');
    const { orgId } = await createTestOrg();
    const { executeIngestTx } = require('../src/api/services/ingestService');

    const base = {
        cyclonedx: { bomFormat: 'CycloneDX', specVersion: '1.6', version: 1,
                     components: [], vulnerabilities: [] },
        spdx: null, aibom: null,
        stats: { totalComponents: 0, vulnerabilities: 0, critical: 0,
                 qualityScore: 0, ecosystems: [] },
    };

    const c1 = await db.pool.connect();
    const c2 = await db.pool.connect();
    let appId1, appId2;
    try {
        await c1.query('BEGIN');
        ({ appId: appId1 } = await executeIngestTx(c1, orgId, 'same-app', { ...base, version: '1.0' }));
        await c1.query('COMMIT');

        await c2.query('BEGIN');
        ({ appId: appId2 } = await executeIngestTx(c2, orgId, 'same-app', { ...base, version: '2.0' }));
        await c2.query('COMMIT');
    } catch (e) {
        await c1.query('ROLLBACK').catch(() => {});
        await c2.query('ROLLBACK').catch(() => {});
        throw e;
    } finally {
        c1.release();
        c2.release();
    }

    assert.strictEqual(appId1, appId2, 'same app name reuses same app row');
});
