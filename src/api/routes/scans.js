'use strict';

const express = require('express');
const db      = require('../db');
const { requireScope }         = require('../middleware/auth');
const { scanLimiter }          = require('../middleware/rateLimits');
const { enqueueScanJob, countActiveScansForOrg } = require('../services/scanQueue');
const { parseGitHubTarget }    = require('../../github');

const router = express.Router();

router.post('/api/v1/scan', scanLimiter, requireScope('sbom:ingest'), async (req, res) => {
    const { repo, ref, token } = req.body;

    if (!repo || typeof repo !== 'string' || !repo.trim()) {
        return res.status(400).json({ error: 'repo is required (e.g. "owner/repo")' });
    }
    const cleanRepo = repo.trim();
    const cleanRef  = (ref && typeof ref === 'string' && ref.trim()) ? ref.trim() : null;

    if (!parseGitHubTarget(cleanRepo)) {
        return res.status(400).json({ error: 'Invalid repo format. Use owner/repo or owner/repo@branch.' });
    }
    if (token !== undefined && typeof token !== 'string') {
        return res.status(400).json({ error: 'token must be a string' });
    }

    try {
        const active = await countActiveScansForOrg(req.org.id);
        if (active >= 2) {
            return res.status(429).json({ error: 'You already have active scans running. Wait for them to complete.' });
        }

        const jobId = await enqueueScanJob(req.org.id, cleanRepo, cleanRef);
        res.status(202).json({ jobId });
    } catch (err) {
        console.error('[scan/create]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/api/v1/scan', requireScope('sbom:read'), async (req, res) => {
    try {
        const { rows } = await db.query(
            `SELECT id, repo, ref, status, error, app_name, created_at, updated_at
             FROM scan_jobs WHERE org_id = $1 ORDER BY created_at DESC LIMIT 20`,
            [req.org.id]
        );
        res.json({ jobs: rows });
    } catch (err) {
        console.error('[scan/list]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/api/v1/scan/:jobId', requireScope('sbom:read'), async (req, res) => {
    try {
        const { rows } = await db.query(
            `SELECT j.id, j.repo, j.ref, j.status, j.error, j.app_name, j.sbom_id,
                    j.created_at, j.updated_at,
                    s.ai_models, s.ai_threats, s.ai_critical, s.least_agency_score
             FROM scan_jobs j
             LEFT JOIN sboms s ON s.id = j.sbom_id
             WHERE j.id = $1 AND j.org_id = $2`,
            [req.params.jobId, req.org.id]
        );
        if (!rows.length) return res.status(404).json({ error: 'Job not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('[scan/get]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;
