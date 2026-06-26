'use strict';

async function getRecentTwo(db, appId) {
    const { rows } = await db.query(
        `SELECT id, version, created_at FROM sboms WHERE app_id = $1 ORDER BY created_at DESC LIMIT 2`,
        [appId]
    );
    return rows;
}

async function getMeta(db, sbomId) {
    const { rows } = await db.query(
        `SELECT id, version, created_at FROM sboms WHERE id = $1`,
        [sbomId]
    );
    return rows[0] || null;
}

async function getComponents(db, sbomId) {
    const { rows } = await db.query(
        `SELECT c.purl, c.name, c.version, c.ecosystem
         FROM sbom_components sc
         JOIN components c ON c.id = sc.component_id
         WHERE sc.sbom_id = $1`,
        [sbomId]
    );
    return rows;
}

async function getVulns(db, sbomId, orgId) {
    const { rows } = await db.query(
        `SELECT v.osv_id, v.cve_id, v.severity, c.purl AS component_purl, c.name AS component_name
         FROM vulnerabilities v
         JOIN components c       ON c.id = v.component_id
         JOIN sbom_components sc ON sc.component_id = c.id
         WHERE sc.sbom_id = $1 AND v.org_id = $2`,
        [sbomId, orgId]
    );
    return rows;
}

module.exports = { getRecentTwo, getMeta, getComponents, getVulns };
