'use strict';

async function listApps(db, orgId) {
    const { rows } = await db.query(
        `SELECT a.id, a.name, a.repo_url,
                COUNT(s.id)             AS sbom_count,
                ls.created_at           AS last_scanned,
                ls.critical_count,
                ls.vulnerability_count,
                ls.component_count,
                ls.quality_score,
                ls.ecosystems
         FROM applications a
         LEFT JOIN sboms s             ON s.app_id = a.id
         LEFT JOIN app_latest_sboms ls ON ls.app_id = a.id
         WHERE a.org_id = $1
         GROUP BY a.id, a.name, a.repo_url, ls.created_at, ls.critical_count,
                  ls.vulnerability_count, ls.component_count, ls.quality_score, ls.ecosystems
         ORDER BY ls.critical_count DESC NULLS LAST, a.name`,
        [orgId]
    );
    return rows;
}

async function findByName(db, orgId, name) {
    const { rows } = await db.query(
        `SELECT id FROM applications WHERE org_id = $1 AND name = $2`,
        [orgId, name]
    );
    return rows[0] || null;
}

async function getLatestSbomMeta(db, orgId, appName) {
    const { rows } = await db.query(
        `SELECT s.id, s.version, s.commit_sha, s.branch, s.component_count,
                s.vulnerability_count, s.critical_count, s.quality_score,
                s.ecosystems, s.elapsed_ms, s.created_at,
                s.ai_models, s.ai_threats, s.ai_critical, s.least_agency_score
         FROM sboms s
         JOIN applications a ON a.id = s.app_id
         WHERE a.org_id = $1 AND a.name = $2
         ORDER BY s.created_at DESC LIMIT 1`,
        [orgId, appName]
    );
    return rows[0] || null;
}

async function getLatestSbomForDownload(db, orgId, appName) {
    const { rows } = await db.query(
        `SELECT s.cyclonedx, s.spdx, s.version, s.created_at
         FROM sboms s
         JOIN applications a ON a.id = s.app_id
         WHERE a.org_id = $1 AND a.name = $2
         ORDER BY s.created_at DESC LIMIT 1`,
        [orgId, appName]
    );
    return rows[0] || null;
}

async function getVulns(db, orgId, appId) {
    const { rows } = await db.query(
        `SELECT v.osv_id, v.cve_id, v.severity, v.cvss_score,
                v.fixed_version, v.title, v.kev,
                c.id AS component_id, c.name AS component,
                c.version AS component_version, c.ecosystem, c.purl
         FROM app_latest_sboms ls
         JOIN sbom_components sc     ON sc.sbom_id = ls.sbom_id
         JOIN components c           ON c.id = sc.component_id
         JOIN vulnerabilities v      ON v.component_id = c.id AND v.org_id = $1
         LEFT JOIN vex_statements vx ON vx.component_id = c.id
                                    AND vx.osv_id = v.osv_id AND vx.org_id = $1
         WHERE ls.app_id = $2
           AND (vx.status IS NULL OR vx.status != 'not_affected')
         ORDER BY v.cvss_score DESC NULLS LAST, v.severity, c.name`,
        [orgId, appId]
    );
    return rows;
}

async function getComponents(db, orgId, appId) {
    const { rows } = await db.query(
        `SELECT c.name, c.version, c.ecosystem, c.purl,
                COUNT(v.id) FILTER (WHERE vx.status IS NULL OR vx.status != 'not_affected') AS vuln_count,
                MAX(v.severity) AS max_severity
         FROM app_latest_sboms ls
         JOIN sbom_components sc    ON sc.sbom_id = ls.sbom_id
         JOIN components c          ON c.id = sc.component_id
         LEFT JOIN vulnerabilities v  ON v.component_id = c.id AND v.org_id = $1
         LEFT JOIN vex_statements vx  ON vx.component_id = c.id
                                     AND vx.osv_id = v.osv_id AND vx.org_id = $1
         WHERE ls.app_id = $2
         GROUP BY c.name, c.version, c.ecosystem, c.purl
         ORDER BY vuln_count DESC, c.name`,
        [orgId, appId]
    );
    return rows;
}

async function getVulnsForExplain(db, orgId, appId) {
    const { rows } = await db.query(
        `SELECT c.name, c.version, c.ecosystem,
                v.osv_id, v.cve_id, v.severity, v.cvss_score, v.fixed_version, v.title, v.kev
         FROM app_latest_sboms ls
         JOIN sbom_components sc ON sc.sbom_id = ls.sbom_id
         JOIN components c       ON c.id = sc.component_id
         JOIN vulnerabilities v  ON v.component_id = c.id AND v.org_id = $1
         LEFT JOIN vex_statements vx
                ON vx.component_id = c.id AND vx.osv_id = v.osv_id AND vx.org_id = $1
         WHERE ls.app_id = $2 AND (vx.status IS NULL OR vx.status != 'not_affected')
         ORDER BY v.severity DESC NULLS LAST`,
        [orgId, appId]
    );
    return rows;
}

async function searchByCveOrOsv(db, orgId, id) {
    const { rows } = await db.query(
        `SELECT
           a.name              AS app,
           s.version           AS app_version,
           ls.created_at       AS last_scanned,
           c.purl,
           c.name              AS component,
           c.version           AS component_version,
           v.osv_id, v.cve_id, v.severity, v.cvss_score, v.fixed_version, v.title,
           vx.status           AS vex_status,
           vx.justification    AS vex_justification
         FROM vulnerabilities v
         JOIN components c          ON c.id = v.component_id
         JOIN sbom_components sc    ON sc.component_id = c.id
         JOIN app_latest_sboms ls   ON ls.sbom_id = sc.sbom_id
         JOIN sboms s               ON s.id = ls.sbom_id
         JOIN applications a        ON a.id = ls.app_id
         LEFT JOIN vex_statements vx ON vx.component_id = c.id
                                    AND vx.osv_id = v.osv_id
                                    AND vx.org_id = v.org_id
         WHERE v.org_id = $1 AND (v.cve_id = $2 OR v.osv_id = $2)
         ORDER BY v.cvss_score DESC NULLS LAST, a.name`,
        [orgId, id]
    );
    return rows;
}

async function getReport(db, orgId) {
    const [topVulns, topApps, summary] = await Promise.all([
        db.query(
            `SELECT v.cve_id, v.osv_id, v.severity, v.cvss_score, v.title,
                    COUNT(DISTINCT a.id) AS apps_affected
             FROM vulnerabilities v
             JOIN components c          ON c.id = v.component_id
             JOIN sbom_components sc    ON sc.component_id = c.id
             JOIN app_latest_sboms ls   ON ls.sbom_id = sc.sbom_id
             JOIN applications a        ON a.id = ls.app_id
             WHERE v.org_id = $1 AND v.severity IN ('CRITICAL','HIGH')
               AND NOT EXISTS (
                 SELECT 1 FROM vex_statements vx
                 WHERE vx.component_id = v.component_id
                   AND vx.osv_id = v.osv_id
                   AND vx.org_id = v.org_id
                   AND vx.status = 'not_affected'
               )
             GROUP BY v.cve_id, v.osv_id, v.severity, v.cvss_score, v.title
             ORDER BY v.cvss_score DESC NULLS LAST, apps_affected DESC
             LIMIT 10`,
            [orgId]
        ),
        db.query(
            `SELECT a.name, ls.critical_count, ls.vulnerability_count,
                    ls.component_count, ls.quality_score, ls.created_at
             FROM app_latest_sboms ls
             JOIN applications a ON a.id = ls.app_id
             WHERE ls.org_id = $1
             ORDER BY ls.critical_count DESC, ls.vulnerability_count DESC
             LIMIT 10`,
            [orgId]
        ),
        db.query(
            `SELECT
               COUNT(DISTINCT a.id)  AS total_apps,
               COUNT(DISTINCT c.id)  AS unique_components,
               COUNT(DISTINCT v.id)  AS total_vulnerabilities,
               SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical,
               SUM(CASE WHEN v.severity = 'HIGH'     THEN 1 ELSE 0 END) AS high
             FROM applications a
             LEFT JOIN app_latest_sboms ls  ON ls.app_id = a.id
             LEFT JOIN sbom_components sc   ON sc.sbom_id = ls.sbom_id
             LEFT JOIN components c         ON c.id = sc.component_id
             LEFT JOIN vulnerabilities v    ON v.component_id = c.id
             WHERE a.org_id = $1`,
            [orgId]
        ),
    ]);
    return { summary: summary.rows[0], topVulns: topVulns.rows, topApps: topApps.rows };
}

module.exports = {
    listApps,
    findByName,
    getLatestSbomMeta,
    getLatestSbomForDownload,
    getVulns,
    getComponents,
    getVulnsForExplain,
    searchByCveOrOsv,
    getReport,
};
