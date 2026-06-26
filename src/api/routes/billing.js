'use strict';

const express = require('express');
const db      = require('../db');
const { requireScope }         = require('../middleware/auth');
const { stripe, priceIdToPlan, PLAN_LIMITS } = require('../stripe');

const router = express.Router();

router.get('/api/v1/billing', requireScope('org:admin'), async (req, res) => {
    try {
        const { rows } = await db.query(
            `SELECT plan, subscription_status, current_period_end, stripe_customer_id
             FROM organizations WHERE id = $1`,
            [req.org.id]
        );
        const org = rows[0];
        res.json({
            plan:               org.plan || 'free',
            status:             org.subscription_status || null,
            current_period_end: org.current_period_end || null,
            has_payment_method: !!org.stripe_customer_id,
            limits:             PLAN_LIMITS[org.plan] || PLAN_LIMITS.free,
        });
    } catch (err) {
        console.error('[billing/get]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/api/v1/billing/prices', (_req, res) => {
    res.json({
        starter_monthly:  process.env.STRIPE_PRICE_STARTER_MONTHLY  || null,
        starter_annual:   process.env.STRIPE_PRICE_STARTER_ANNUAL   || null,
        team_monthly:     process.env.STRIPE_PRICE_TEAM_MONTHLY     || null,
        team_annual:      process.env.STRIPE_PRICE_TEAM_ANNUAL      || null,
        business_monthly: process.env.STRIPE_PRICE_BUSINESS_MONTHLY || null,
        business_annual:  process.env.STRIPE_PRICE_BUSINESS_ANNUAL  || null,
    });
});

router.post('/api/v1/billing/checkout', requireScope('org:admin'), async (req, res) => {
    if (!process.env.STRIPE_SECRET_KEY) {
        return res.status(503).json({ error: 'Billing not configured' });
    }

    const { priceId } = req.body;
    if (!priceId || typeof priceId !== 'string') {
        return res.status(400).json({ error: 'priceId is required' });
    }
    if (!priceIdToPlan(priceId)) {
        return res.status(400).json({ error: 'Unknown price ID' });
    }

    try {
        const { rows } = await db.query(
            `SELECT email, stripe_customer_id FROM organizations WHERE id = $1`,
            [req.org.id]
        );
        const org    = rows[0];
        const appUrl = process.env.APP_URL || 'https://api.packrai.xyz';

        const session = await stripe.checkout.sessions.create({
            ...(org.stripe_customer_id
                ? { customer: org.stripe_customer_id }
                : { customer_email: org.email || undefined }),
            mode: 'subscription',
            line_items: [{ price: priceId, quantity: 1 }],
            subscription_data: {
                trial_period_days: 14,
                metadata: { org_id: req.org.id },
            },
            metadata:    { org_id: req.org.id },
            success_url: `${appUrl}/dashboard?upgraded=1`,
            cancel_url:  `${appUrl}/pricing`,
            allow_promotion_codes: true,
        });

        res.json({ url: session.url });
    } catch (err) {
        console.error('[billing/checkout]', err.message);
        res.status(500).json({ error: 'Failed to create checkout session' });
    }
});

router.post('/api/v1/billing/portal', requireScope('org:admin'), async (req, res) => {
    if (!process.env.STRIPE_SECRET_KEY) {
        return res.status(503).json({ error: 'Billing not configured' });
    }

    try {
        const { rows } = await db.query(
            `SELECT stripe_customer_id FROM organizations WHERE id = $1`,
            [req.org.id]
        );
        const customerId = rows[0]?.stripe_customer_id;
        if (!customerId) {
            return res.status(400).json({ error: 'No billing account found' });
        }

        const appUrl  = process.env.APP_URL || 'https://api.packrai.xyz';
        const session = await stripe.billingPortal.sessions.create({
            customer:   customerId,
            return_url: `${appUrl}/dashboard`,
        });
        res.json({ url: session.url });
    } catch (err) {
        console.error('[billing/portal]', err.message);
        res.status(500).json({ error: 'Failed to create portal session' });
    }
});

module.exports = router;
