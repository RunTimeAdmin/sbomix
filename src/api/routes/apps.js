'use strict';

const express   = require('express');
const db        = require('../db');
const { requireScope }              = require('../middleware/auth');
const { diffComponents, diffVulns } = require('../../diff');
const { explainVulnRows }           = require('../../explain');
const appsRepo  = require('../repositories/appsRepo');
const sbomsRepo = require('../repositories/sbomsRepo');

const router = express.Router();

router.get('/api/v1/apps', requireScope('sbom:read'), async (req, res) => {
    try {
        const apps = await appsRepo.listApps(db, req.org.id);
        res.json({ apps });
    } catch (err) {
        console.error('[apps]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/api/v1/apps/:name/vulns', requireScope('sbom:read'), async (req, res) => {
    try {
        const app = await appsRepo.findByName(db, req.org.id, req.params.name);
        if (!app) return res.status(404).json({ error: 'App not found' });
        const vulnerabilities = await appsRepo.getVulns(db, req.org.id, app.id);
        res.json({ vulnerabilities });
    } catch (err) {
        console.error('[apps/vulns]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/api/v1/apps/:name/sbom', requireScope('sbom:read'), async (req, res) => {
    try {
        const sbom = await appsRepo.getLatestSbomMeta(db, req.org.id, req.params.name);
        if (!sbom) return res.status(404).json({ error: 'App not found' });
        res.json(sbom);
    } catch (err) {
        console.error('[apps/sbom]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/api/v1/apps/:name/components', requireScope('sbom:read'), async (req, res) => {
    try {
        const app = await appsRepo.findByName(db, req.org.id, req.params.name);
        if (!app) return res.status(404).json({ error: 'App not found' });
        const components = await appsRepo.getComponents(db, req.org.id, app.id);
        res.json({ components });
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
        const row = await appsRepo.getLatestSbomForDownload(db, req.org.id, req.params.name);
        if (!row) return res.status(404).json({ error: 'App not found' });

        if (format === 'spdx') {
            if (!row.spdx) return res.status(404).json({ error: 'No SPDX document stored for this app' });
            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Content-Disposition', `attachment; filename="${req.params.name}-sbom.spdx.json"`);
            return res.json(row.spdx);
        }

        res.setHeader('Content-Type', 'application/vnd.cyclonedx+json');
        res.setHeader('Content-Disposition', `attachment; filename="${req.params.name}-sbom.cdx.json"`);
        res.json(row.cyclonedx);
    } catch (err) {
        console.error('[sbom/download]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/api/v1/apps/:name/diff', requireScope('sbom:read'), async (req, res) => {
    try {
        const app = await appsRepo.findByName(db, req.org.id, req.params.name);
        if (!app) return res.status(404).json({ error: 'App not found' });

        let fromId = req.query.from;
        let toId   = req.query.to;

        if (!fromId || !toId) {
            const recent = await sbomsRepo.getRecentTwo(db, app.id);
            if (recent.length < 2) {
                return res.status(409).json({ error: 'Need at least two SBOMs to diff' });
            }
            toId   = toId   || recent[0].id;
            fromId = fromId || recent[1].id;
        }

        const [fromComps, toComps, fromVulns, toVulns, fromMeta, toMeta] = await Promise.all([
            sbomsRepo.getComponents(db, fromId),
            sbomsRepo.getComponents(db, toId),
            sbomsRepo.getVulns(db, fromId, req.org.id),
            sbomsRepo.getVulns(db, toId,   req.org.id),
            sbomsRepo.getMeta(db, fromId),
            sbomsRepo.getMeta(db, toId),
        ]);

        const compDiff = diffComponents(fromComps, toComps);
        const vulnDiff = diffVulns(fromVulns, toVulns);

        res.json({
            from:    fromMeta,
            to:      toMeta,
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
        const app = await appsRepo.findByName(db, req.org.id, req.params.name);
        if (!app) return res.status(404).json({ error: 'App not found' });

        const vulnRows = await appsRepo.getVulnsForExplain(db, req.org.id, app.id);
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
        const results = await appsRepo.searchByCveOrOsv(db, req.org.id, id);
        res.json({ query: id, exposedApps: results.length, results });
    } catch (err) {
        console.error('[search]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/api/v1/report', requireScope('sbom:read'), async (req, res) => {
    try {
        const { summary, topVulns, topApps } = await appsRepo.getReport(db, req.org.id);
        res.json({ summary, topVulnerabilities: topVulns, mostExposedApps: topApps });
    } catch (err) {
        console.error('[report]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;
