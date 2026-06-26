'use strict';

const express = require('express');
const db      = require('../db');
const { hashApiKey, generateApiKey } = require('../middleware/auth');

const router = express.Router();

router.post('/api/v1/orgs', async (req, res) => {
    if (!process.env.ENABLE_ADMIN_API) {
        return res.status(404).json({ error: 'Not found' });
    }
    const adminKey = req.headers['x-admin-key'];
    if (!adminKey || adminKey !== process.env.ADMIN_KEY) {
        return res.status(403).json({ error: 'Forbidden' });
    }

    const { name } = req.body;
    if (!name || typeof name !== 'string' || !name.trim()) {
        return res.status(400).json({ error: 'name must be a non-empty string' });
    }
    if (name.length > 200) {
        return res.status(400).json({ error: 'name must be 200 characters or fewer' });
    }

    try {
        const apiKey     = generateApiKey();
        const apiKeyHash = hashApiKey(apiKey);

        const { rows } = await db.query(
            'INSERT INTO organizations (name, api_key) VALUES ($1, $2) RETURNING id, name',
            [name, apiKeyHash]
        );
        res.status(201).json({ ...rows[0], api_key: apiKey });
    } catch (err) {
        console.error('[orgs]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;
