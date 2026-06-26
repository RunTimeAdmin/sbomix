'use strict';

const express = require('express');
const { requireScope }   = require('../middleware/auth');
const componentsRepo     = require('../repositories/componentsRepo');
const vexRepo            = require('../repositories/vexRepo');
const db                 = require('../db');

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
        const owned = await componentsRepo.verifyOwnership(db, req.org.id, component_id);
        if (!owned) return res.status(404).json({ error: 'Component not found' });

        const statement = await vexRepo.upsertStatement(
            db, req.org.id, component_id, osv_id, status, justification, impact_statement
        );
        res.status(201).json(statement);
    } catch (err) {
        console.error('[vex:post]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/api/v1/vex', requireScope('sbom:read'), async (req, res) => {
    try {
        const statements = await vexRepo.listStatements(db, req.org.id, {
            osvId:       req.query.osv_id,
            componentId: req.query.component_id,
        });
        res.json({ statements });
    } catch (err) {
        console.error('[vex:get]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.delete('/api/v1/vex/:id', requireScope('sbom:ingest'), async (req, res) => {
    try {
        const deleted = await vexRepo.deleteStatement(db, req.org.id, req.params.id);
        if (!deleted) return res.status(404).json({ error: 'VEX statement not found' });
        res.status(204).end();
    } catch (err) {
        console.error('[vex:delete]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;
