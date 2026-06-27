'use strict';

const express = require('express');
const db      = require('../db');
const { requireScope }         = require('../middleware/auth');
const { ingestLimiter }        = require('../middleware/rateLimits');
const { executeIngestTx }      = require('../services/ingestService');
const { osvEnrichAsync }       = require('../services/postIngestAnalysis');
const { sendVulnAlertIfNew }   = require('../services/emailService');
const { validateCycloneDX }    = require('../../generators/cyclonedx');
const { applyKEVAfterIngest }  = require('../../kev');
const { PLAN_LIMITS, resolveEffectivePlan } = require('../stripe');

const router = express.Router();

router.post('/api/v1/ingest', ingestLimiter, requireScope('sbom:ingest'), async (req, res) => {
    const { app: appName, version, commit, branch, cyclonedx, spdx, stats, aibom } = req.body;

    try {
        const { rows: orgRows } = await db.query(
            `SELECT plan, subscription_status, trial_ends_at FROM organizations WHERE id = $1`, [req.org.id]
        );
        const plan   = resolveEffectivePlan(orgRows[0]?.plan, orgRows[0]?.trial_ends_at);
        const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.free;

        const { rows: appRows } = await db.query(
            `SELECT COUNT(*) AS cnt FROM applications WHERE org_id = $1`, [req.org.id]
        );
        const existingApp = await db.query(
            `SELECT id FROM applications WHERE org_id = $1 AND name = $2`, [req.org.id, appName]
        );
        const isNewApp = existingApp.rows.length === 0;
        if (isNewApp && Number(appRows[0].cnt) >= limits.apps) {
            return res.status(402).json({
                error: `Your ${plan} plan supports up to ${limits.apps} app${limits.apps === 1 ? '' : 's'}. Upgrade to add more.`,
                upgrade: true,
            });
        }

        const { rows: scanRows } = await db.query(
            `SELECT COUNT(*) AS cnt FROM sboms
             WHERE org_id = $1 AND created_at >= date_trunc('month', NOW())`, [req.org.id]
        );
        if (Number(scanRows[0].cnt) >= limits.scansPerMonth) {
            return res.status(402).json({
                error: `Monthly scan limit reached (${limits.scansPerMonth.toLocaleString()} for ${plan} plan). Upgrade or wait until next month.`,
                upgrade: true,
            });
        }
    } catch (limitErr) {
        console.error('[ingest/plan-check]', limitErr.message);
        return res.status(500).json({ error: 'Internal server error' });
    }

    if (!appName || typeof appName !== 'string') {
        return res.status(400).json({ error: 'app must be a non-empty string' });
    }
    if (appName.length > 200) {
        return res.status(400).json({ error: 'app name must be 200 characters or fewer' });
    }
    if (!cyclonedx || typeof cyclonedx !== 'object') {
        return res.status(400).json({ error: 'cyclonedx must be an object' });
    }
    const cdxCheck = validateCycloneDX(cyclonedx);
    if (!cdxCheck.valid) {
        return res.status(400).json({ error: 'Invalid CycloneDX document', details: cdxCheck.errors });
    }
    const MAX_COMPONENTS = 10_000;
    if ((cyclonedx.components?.length ?? 0) > MAX_COMPONENTS) {
        return res.status(400).json({ error: `SBOM may not contain more than ${MAX_COMPONENTS} components` });
    }
    if (version  !== undefined && (typeof version  !== 'string' || version.length  > 100)) {
        return res.status(400).json({ error: 'version must be a string ≤ 100 characters' });
    }
    if (commit   !== undefined && (typeof commit   !== 'string' || commit.length   > 64)) {
        return res.status(400).json({ error: 'commit must be a string ≤ 64 characters' });
    }
    if (branch   !== undefined && (typeof branch   !== 'string' || branch.length   > 250)) {
        return res.status(400).json({ error: 'branch must be a string ≤ 250 characters' });
    }
    if (stats !== undefined) {
        if (typeof stats !== 'object' || Array.isArray(stats)) {
            return res.status(400).json({ error: 'stats must be an object' });
        }
        if (stats.totalComponents !== undefined && (typeof stats.totalComponents !== 'number' || stats.totalComponents < 0)) {
            return res.status(400).json({ error: 'stats.totalComponents must be a non-negative number' });
        }
        if (stats.critical !== undefined && (typeof stats.critical !== 'number' || stats.critical < 0)) {
            return res.status(400).json({ error: 'stats.critical must be a non-negative number' });
        }
    }

    try {
        const { sbomId, purlToCompId, appId } = await db.tx((client) =>
            executeIngestTx(client, req.org.id, appName, { version, commit, branch, cyclonedx, spdx, stats, aibom })
        );

        res.status(201).json({
            sbomId,
            aiModels:         stats?.aiModels         ?? 0,
            aiThreats:        stats?.aiThreats         ?? 0,
            aiCritical:       stats?.aiCritical        ?? 0,
            leastAgencyScore: stats?.leastAgencyScore  ?? null,
        });

        if (!cyclonedx.vulnerabilities?.length && purlToCompId.size > 0) {
            osvEnrichAsync(req.org.id, cyclonedx.components.filter(c => c.purl), purlToCompId, sbomId)
                .then(() => {
                    applyKEVAfterIngest(req.org.id);
                    return sendVulnAlertIfNew(req.org.id, appId, appName);
                })
                .catch(err => console.error('[osv-enrich]', err.message));
        } else {
            applyKEVAfterIngest(req.org.id);
            sendVulnAlertIfNew(req.org.id, appId, appName)
                .catch(err => console.error('[vuln-alert]', err.message));
        }
    } catch (err) {
        console.error('[ingest]', err.message);
        res.status(500).json({ error: 'Ingest failed' });
    }
});

module.exports = router;
