'use strict';

async function listForOrg(db, orgId, limit = 20) {
    const { rows } = await db.query(
        `SELECT id, repo, ref, status, error, app_name, created_at, updated_at
         FROM scan_jobs WHERE org_id = $1 ORDER BY created_at DESC LIMIT $2`,
        [orgId, limit]
    );
    return rows;
}

async function findById(db, orgId, jobId) {
    const { rows } = await db.query(
        `SELECT j.id, j.repo, j.ref, j.status, j.error, j.app_name, j.sbom_id,
                j.created_at, j.updated_at,
                s.ai_models, s.ai_threats, s.ai_critical, s.least_agency_score
         FROM scan_jobs j
         LEFT JOIN sboms s ON s.id = j.sbom_id
         WHERE j.id = $1 AND j.org_id = $2`,
        [jobId, orgId]
    );
    return rows[0] || null;
}

module.exports = { listForOrg, findById };
