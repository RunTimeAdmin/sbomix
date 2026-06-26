'use strict';

const db = require('../db');

async function enqueueScanJob(orgId, repo, ref) {
    const { rows } = await db.query(
        `INSERT INTO scan_jobs (org_id, repo, ref, timeout_at)
         VALUES ($1, $2, $3, NOW() + INTERVAL '3 minutes')
         RETURNING id`,
        [orgId, repo, ref]
    );
    return rows[0].id;
}

async function countActiveScansForOrg(orgId) {
    const { rows } = await db.query(
        `SELECT COUNT(*) AS cnt FROM scan_jobs WHERE org_id = $1 AND status IN ('pending', 'running')`,
        [orgId]
    );
    return Number(rows[0].cnt);
}

async function claimNextScanJob(workerId) {
    const { rows } = await db.query(
        `UPDATE scan_jobs
         SET status = 'running', locked_by = $1, locked_at = NOW(),
             started_at = NOW(), attempts = attempts + 1, updated_at = NOW()
         WHERE id = (
             SELECT id FROM scan_jobs
             WHERE status = 'pending' AND attempts < max_attempts
             ORDER BY priority ASC, created_at ASC
             LIMIT 1
             FOR UPDATE SKIP LOCKED
         )
         RETURNING id, org_id, repo, ref, token_ref`,
        [workerId]
    );
    return rows[0] || null;
}

async function markScanDone(jobId, appName, sbomId) {
    await db.query(
        `UPDATE scan_jobs
         SET status = 'done', app_name = $2, sbom_id = $3,
             finished_at = NOW(), updated_at = NOW()
         WHERE id = $1`,
        [jobId, appName, sbomId]
    );
}

async function markScanFailed(jobId, error) {
    await db.query(
        `UPDATE scan_jobs
         SET status = 'failed', error = $2,
             finished_at = NOW(), updated_at = NOW()
         WHERE id = $1`,
        [jobId, (error || '').toString().slice(0, 500)]
    );
}

async function recoverStaleJobs(timeoutMs) {
    const timeoutSecs = Math.ceil(timeoutMs / 1000);

    // Reset jobs that still have retries left
    await db.query(
        `UPDATE scan_jobs
         SET status = 'pending', locked_by = NULL, locked_at = NULL,
             updated_at = NOW(), error = 'Recovered from stale worker lock'
         WHERE status = 'running'
           AND locked_at < NOW() - ($1 || ' seconds')::interval
           AND attempts < max_attempts`,
        [timeoutSecs]
    );

    // Permanently fail jobs that have exhausted attempts
    await db.query(
        `UPDATE scan_jobs
         SET status = 'failed', finished_at = NOW(), updated_at = NOW(),
             error = COALESCE(error, 'Max attempts exceeded')
         WHERE status = 'running'
           AND locked_at < NOW() - ($1 || ' seconds')::interval
           AND attempts >= max_attempts`,
        [timeoutSecs]
    );
}

module.exports = {
    enqueueScanJob,
    countActiveScansForOrg,
    claimNextScanJob,
    markScanDone,
    markScanFailed,
    recoverStaleJobs,
};
