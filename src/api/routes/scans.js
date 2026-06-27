'use strict';

const express = require('express');
const db      = require('../db');
const { requireScope }         = require('../middleware/auth');
const { scanLimiter }          = require('../middleware/rateLimits');
const { enqueueScanJob, countActiveScansForOrg } = require('../services/scanQueue');
const { parseGitHubTarget }    = require('../../github');
const scanJobsRepo             = require('../repositories/scanJobsRepo');
const { PLAN_LIMITS, resolveEffectivePlan } = require('../stripe');

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
    if (token !== undefined) {
        return res.status(501).json({ error: 'Private repository scanning is not supported via the hosted API. Use the sbomix CLI locally instead.' });
    }

    try {
        const { rows: orgRows } = await db.query(
            `SELECT plan, trial_ends_at FROM organizations WHERE id = $1`, [req.org.id]
        );
        const plan   = resolveEffectivePlan(orgRows[0]?.plan, orgRows[0]?.trial_ends_at);
        const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.free;

        const { rows: scanRows } = await db.query(
            `SELECT COUNT(*) AS cnt FROM scan_jobs WHERE org_id = $1 AND created_at >= date_trunc('month', NOW())`,
            [req.org.id]
        );
        if (Number(scanRows[0].cnt) >= limits.scansPerMonth) {
            return res.status(402).json({
                error: `Monthly scan limit reached (${limits.scansPerMonth.toLocaleString()} for ${plan} plan). Upgrade or wait until next month.`,
                upgrade: true,
            });
        }

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
        const jobs = await scanJobsRepo.listForOrg(db, req.org.id);
        res.json({ jobs });
    } catch (err) {
        console.error('[scan/list]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/api/v1/scan/:jobId', requireScope('sbom:read'), async (req, res) => {
    try {
        const job = await scanJobsRepo.findById(db, req.org.id, req.params.jobId);
        if (!job) return res.status(404).json({ error: 'Job not found' });
        res.json(job);
    } catch (err) {
        console.error('[scan/get]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;
