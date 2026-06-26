'use strict';

const express = require('express');
const db      = require('../db');
const { requireScope } = require('../middleware/auth');

const router = express.Router();

const VEX_STATUSES       = new Set(['not_affected', 'affected', 'fixed', 'under_investigation']);
const VEX_JUSTIFICATIONS = new Set([
    'component_not_present', 'vulnerable_code_not_present',
    'vulnerable_code_not_in_execute_path',
    'vulnerable_code_cannot_be_controlled_by_adversary',
    'inline_mitigations_already_exist',
]);

router.post('/api/v1/vex', requireScope('sbom:ingest'), async (req, res) => {
    const { component_id, osv_id, status, justification, impact_statement } = req.body;

    if (!component_id || typeof component_id !== 'string') {
        return res.status(400).json({ error: 'component_id must be a UUID string' });
    }
    if (!osv_id || typeof osv_id !== 'string') {
        return res.status(400).json({ error: 'osv_id must be a non-empty string' });
    }
    if (!VEX_STATUSES.has(status)) {
        return res.status(400).json({ error: 'status must be one of: ' + [...VEX_STATUSES].join(', ') });
    }
    if (status === 'not_affected' && !justification) {
        return res.status(400).json({ error: 'justification is required when status is not_affected' });
    }
    if (justification && !VEX_JUSTIFICATIONS.has(justification)) {
        return res.status(400).json({ error: 'invalid justification value' });
    }
    if (impact_statement !== undefined && typeof impact_statement !== 'string') {
        return res.status(400).json({ error: 'impact_statement must be a string' });
    }

    try {
        const compCheck = await db.query(
            `SELECT id FROM components WHERE id = $1 AND org_id = $2`,
            [component_id, req.org.id]
        );
        if (!compCheck.rows.length) {
            return res.status(404).json({ error: 'Component not found' });
        }

        const { rows } = await db.query(
            `INSERT INTO vex_statements
               (org_id, component_id, osv_id, status, justification, impact_statement, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,NOW())
             ON CONFLICT (org_id, component_id, osv_id) DO UPDATE
               SET status           = EXCLUDED.status,
                   justification    = EXCLUDED.justification,
                   impact_statement = EXCLUDED.impact_statement,
                   updated_at       = NOW()
             RETURNING *`,
            [req.org.id, component_id, osv_id, status,
             justification || null, impact_statement || null]
        );
        res.status(201).json(rows[0]);
    } catch (err) {
        console.error('[vex:post]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/api/v1/vex', requireScope('sbom:read'), async (req, res) => {
    const { osv_id, component_id } = req.query;
    try {
        const conditions = ['vx.org_id = $1'];
        const params     = [req.org.id];
        if (osv_id) {
            params.push(osv_id);
            conditions.push(`vx.osv_id = $${params.length}`);
        }
        if (component_id) {
            params.push(component_id);
            conditions.push(`vx.component_id = $${params.length}`);
        }

        const { rows } = await db.query(
            `SELECT vx.id, vx.component_id, c.purl, c.name AS component_name, c.version,
                    vx.osv_id, vx.status, vx.justification, vx.impact_statement,
                    vx.created_at, vx.updated_at
             FROM vex_statements vx
             JOIN components c ON c.id = vx.component_id
             WHERE ${conditions.join(' AND ')}
             ORDER BY vx.updated_at DESC`,
            params
        );
        res.json({ statements: rows });
    } catch (err) {
        console.error('[vex:get]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.delete('/api/v1/vex/:id', requireScope('sbom:ingest'), async (req, res) => {
    try {
        const { rowCount } = await db.query(
            `DELETE FROM vex_statements WHERE id = $1 AND org_id = $2`,
            [req.params.id, req.org.id]
        );
        if (!rowCount) return res.status(404).json({ error: 'VEX statement not found' });
        res.status(204).end();
    } catch (err) {
        console.error('[vex:delete]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;
