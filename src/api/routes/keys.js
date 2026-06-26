'use strict';

const express = require('express');
const db      = require('../db');
const { requireScope, hashApiKey, generateApiKey } = require('../middleware/auth');

const router = express.Router();

router.get('/api/v1/me', requireScope('sbom:read'), async (req, res) => {
    try {
        const { rows } = await db.query(
            'SELECT vuln_alerts, plan, subscription_status, current_period_end FROM organizations WHERE id = $1',
            [req.org.id]
        );
        const r = rows[0] || {};
        res.json({
            org:                 req.org.name,
            scopes:              req.scopes || [],
            vuln_alerts:         r.vuln_alerts ?? true,
            plan:                r.plan || 'free',
            subscription_status: r.subscription_status || null,
            current_period_end:  r.current_period_end || null,
        });
    } catch {
        res.json({ org: req.org.name, scopes: req.scopes || [], vuln_alerts: true, plan: 'free' });
    }
});

router.patch('/api/v1/account/settings', requireScope('org:admin'), async (req, res) => {
    const { vuln_alerts } = req.body;
    if (typeof vuln_alerts !== 'boolean') {
        return res.status(400).json({ error: 'vuln_alerts must be a boolean' });
    }
    try {
        await db.query('UPDATE organizations SET vuln_alerts = $1 WHERE id = $2', [vuln_alerts, req.org.id]);
        res.json({ vuln_alerts });
    } catch (err) {
        console.error('[settings]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.post('/api/v1/keys', requireScope('org:admin'), async (req, res) => {
    const VALID_SCOPES = new Set(['sbom:ingest', 'sbom:read', 'org:admin']);
    const rawName = req.body.name;
    const name    = (typeof rawName === 'string' && rawName.trim()) ? rawName.trim() : 'default';
    const scopes  = req.body.scopes ?? ['sbom:ingest', 'sbom:read'];

    if (rawName !== undefined && (typeof rawName !== 'string' || rawName.length > 100)) {
        return res.status(400).json({ error: 'name must be a string ≤ 100 characters' });
    }
    if (!Array.isArray(scopes) || scopes.length === 0 || !scopes.every(s => VALID_SCOPES.has(s))) {
        return res.status(400).json({ error: 'Invalid scopes', valid: [...VALID_SCOPES] });
    }

    try {
        const apiKey  = generateApiKey();
        const keyHash = hashApiKey(apiKey);

        const { rows } = await db.query(
            `INSERT INTO api_keys (org_id, name, key_hash, scopes)
             VALUES ($1, $2, $3, $4)
             RETURNING id, name, scopes, created_at`,
            [req.org.id, name, keyHash, scopes]
        );
        res.status(201).json({ ...rows[0], api_key: apiKey });
    } catch (err) {
        console.error('[keys/create]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/api/v1/keys', requireScope('org:admin'), async (req, res) => {
    try {
        const { rows } = await db.query(
            `SELECT id, name, scopes, created_at, last_used_at
             FROM api_keys
             WHERE org_id = $1 AND revoked_at IS NULL
             ORDER BY created_at`,
            [req.org.id]
        );
        res.json({ keys: rows });
    } catch (err) {
        console.error('[keys/list]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.delete('/api/v1/keys/:id', requireScope('org:admin'), async (req, res) => {
    try {
        const { rowCount } = await db.query(
            `UPDATE api_keys SET revoked_at = NOW()
             WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL`,
            [req.params.id, req.org.id]
        );
        if (!rowCount) return res.status(404).json({ error: 'Key not found' });
        res.json({ revoked: true });
    } catch (err) {
        console.error('[keys/revoke]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.delete('/api/v1/account', requireScope('org:admin'), async (req, res) => {
    if (req.body.confirm !== 'delete my account') {
        return res.status(400).json({ error: 'Set confirm to "delete my account" to proceed' });
    }
    try {
        await db.query('DELETE FROM organizations WHERE id = $1', [req.org.id]);
        res.status(204).end();
    } catch (err) {
        console.error('[account/delete]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;
