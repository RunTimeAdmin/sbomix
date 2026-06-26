'use strict';

const express = require('express');
const db      = require('../db');
const { requireScope }    = require('../middleware/auth');
const { diffComponents, diffVulns } = require('../../diff');
const { explainVulnRows }           = require('../../explain');

const router = express.Router();

router.get('/api/v1/apps', requireScope('sbom:read'), async (req, res) => {
    try {
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
            [req.org.id]
        );
        res.json({ apps: rows });
    } catch (err) {
        console.error('[apps]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/api/v1/apps/:name/vulns', requireScope('sbom:read'), async (req, res) => {
    try {
        const appRes = await db.query(
            `SELECT a.id FROM applications a WHERE a.org_id = $1 AND a.name = $2`,
            [req.org.id, req.params.name]
        );
        if (!appRes.rows.length) return res.status(404).json({ error: 'App not found' });
        const appId = appRes.rows[0].id;

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
            [req.org.id, appId]
        );
        res.json({ vulnerabilities: rows });
    } catch (err) {
        console.error('[apps/vulns]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/api/v1/apps/:name/sbom', requireScope('sbom:read'), async (req, res) => {
    try {
        const { rows } = await db.query(
            `SELECT s.id, s.version, s.commit_sha, s.branch, s.component_count,
                    s.vulnerability_count, s.critical_count, s.quality_score,
                    s.ecosystems, s.elapsed_ms, s.created_at,
                    s.ai_models, s.ai_threats, s.ai_critical, s.least_agency_score
             FROM sboms s
             JOIN applications a ON a.id = s.app_id
             WHERE a.org_id = $1 AND a.name = $2
             ORDER BY s.created_at DESC LIMIT 1`,
            [req.org.id, req.params.name]
        );
        if (!rows.length) return res.status(404).json({ error: 'App not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('[apps/sbom]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/api/v1/apps/:name/components', requireScope('sbom:read'), async (req, res) => {
    try {
        const appRes = await db.query(
            `SELECT a.id FROM applications a WHERE a.org_id = $1 AND a.name = $2`,
            [req.org.id, req.params.name]
        );
        if (!appRes.rows.length) return res.status(404).json({ error: 'App not found' });
        const appId = appRes.rows[0].id;

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
            [req.org.id, appId]
        );
        res.json({ components: rows });
    } catch (err) {
        console.error('[apps/components]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/api/v1/apps/:name/sbom/download', requireScope('sbom:read'), async (req, res) => {
    const format = (req.query.format || 'cyclonedx').toLowerCase();
    if (!['cyclonedx', 'spdx'].includes(format)) {
        return res.status(400).json({ error: 'format must be cyclonedx or spdx' });
    }
    try {
        const { rows } = await db.query(
            `SELECT s.cyclonedx, s.spdx, s.version, s.created_at
             FROM sboms s
             JOIN applications a ON a.id = s.app_id
             WHERE a.org_id = $1 AND a.name = $2
             ORDER BY s.created_at DESC LIMIT 1`,
            [req.org.id, req.params.name]
        );
        if (!rows.length) return res.status(404).json({ error: 'App not found' });

        const row = rows[0];
        if (format === 'spdx') {
            if (!row.spdx) return res.status(404).json({ error: 'No SPDX document stored for this app' });
            const filename = `${req.params.name}-sbom.spdx.json`;
            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            return res.json(row.spdx);
        }

        const filename = `${req.params.name}-sbom.cdx.json`;
        res.setHeader('Content-Type', 'application/vnd.cyclonedx+json');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.json(row.cyclonedx);
    } catch (err) {
        console.error('[sbom/download]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/api/v1/apps/:name/diff', requireScope('sbom:read'), async (req, res) => {
    try {
        const appRes = await db.query(
            `SELECT id FROM applications WHERE org_id = $1 AND name = $2`,
            [req.org.id, req.params.name]
        );
        if (!appRes.rows.length) return res.status(404).json({ error: 'App not found' });
        const appId = appRes.rows[0].id;

        let fromId = req.query.from;
        let toId   = req.query.to;

        if (!fromId || !toId) {
            const recent = await db.query(
                `SELECT id, version, created_at
                 FROM sboms WHERE app_id = $1 ORDER BY created_at DESC LIMIT 2`,
                [appId]
            );
            if (recent.rows.length < 2) {
                return res.status(409).json({ error: 'Need at least two SBOMs to diff' });
            }
            toId   = toId   || recent.rows[0].id;
            fromId = fromId || recent.rows[1].id;
        }

        const compQuery = `
            SELECT c.purl, c.name, c.version, c.ecosystem
            FROM sbom_components sc
            JOIN components c ON c.id = sc.component_id
            WHERE sc.sbom_id = $1`;

        const vulnQuery = `
            SELECT v.osv_id, v.cve_id, v.severity, c.purl AS component_purl, c.name AS component_name
            FROM vulnerabilities v
            JOIN components c       ON c.id = v.component_id
            JOIN sbom_components sc ON sc.component_id = c.id
            WHERE sc.sbom_id = $1 AND v.org_id = $2`;

        const [fromComps, toComps, fromVulns, toVulns, fromMeta, toMeta] = await Promise.all([
            db.query(compQuery, [fromId]),
            db.query(compQuery, [toId]),
            db.query(vulnQuery, [fromId, req.org.id]),
            db.query(vulnQuery, [toId,   req.org.id]),
            db.query(`SELECT id, version, created_at FROM sboms WHERE id = $1`, [fromId]),
            db.query(`SELECT id, version, created_at FROM sboms WHERE id = $1`, [toId]),
        ]);

        const compDiff = diffComponents(fromComps.rows, toComps.rows);
        const vulnDiff = diffVulns(fromVulns.rows, toVulns.rows);

        res.json({
            from:    fromMeta.rows[0],
            to:      toMeta.rows[0],
            summary: {
                ...compDiff.summary,
                newVulnerabilities:      vulnDiff.introduced.length,
                resolvedVulnerabilities: vulnDiff.resolved.length,
            },
            added:                   compDiff.added,
            removed:                 compDiff.removed,
            updated:                 compDiff.updated,
            newVulnerabilities:      vulnDiff.introduced,
            resolvedVulnerabilities: vulnDiff.resolved,
        });
    } catch (err) {
        console.error('[diff]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.post('/api/v1/apps/:name/explain', requireScope('sbom:read'), async (req, res) => {
    if (!process.env.DEEPSEEK_API_KEY) {
        return res.status(501).json({ error: 'AI explain is not configured on this server (DEEPSEEK_API_KEY not set)' });
    }
    try {
        const appRes = await db.query(
            `SELECT id FROM applications WHERE org_id = $1 AND name = $2`,
            [req.org.id, req.params.name]
        );
        if (!appRes.rows.length) return res.status(404).json({ error: 'App not found' });
        const appId = appRes.rows[0].id;

        const { rows: vulnRows } = await db.query(
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
            [req.org.id, appId]
        );

        if (!vulnRows.length) {
            return res.json({ explanation: 'No active vulnerabilities found for this app.' });
        }

        const explanation = await explainVulnRows(vulnRows, req.params.name);
        res.json({ explanation, vulnerabilityCount: vulnRows.length });
    } catch (err) {
        console.error('[explain]', err.message);
        res.status(500).json({ error: 'Explain failed' });
    }
});

router.get('/api/v1/search', requireScope('sbom:read'), async (req, res) => {
    const { cve, osv } = req.query;
    const id = cve || osv;
    if (!id) return res.status(400).json({ error: 'Provide ?cve= or ?osv= parameter' });

    try {
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
            [req.org.id, id]
        );
        res.json({ query: id, exposedApps: rows.length, results: rows });
    } catch (err) {
        console.error('[search]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/api/v1/report', requireScope('sbom:read'), async (req, res) => {
    try {
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
                [req.org.id]
            ),
            db.query(
                `SELECT a.name, ls.critical_count, ls.vulnerability_count,
                        ls.component_count, ls.quality_score, ls.created_at
                 FROM app_latest_sboms ls
                 JOIN applications a ON a.id = ls.app_id
                 WHERE ls.org_id = $1
                 ORDER BY ls.critical_count DESC, ls.vulnerability_count DESC
                 LIMIT 10`,
                [req.org.id]
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
                [req.org.id]
            ),
        ]);

        res.json({
            summary:            summary.rows[0],
            topVulnerabilities: topVulns.rows,
            mostExposedApps:    topApps.rows,
        });
    } catch (err) {
        console.error('[report]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;
