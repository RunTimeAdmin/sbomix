'use strict';

const express = require('express');
const db      = require('../db');
const { stripe, priceIdToPlan } = require('../stripe');
const { sendEmail } = require('../services/emailService');

const router = express.Router();

router.post('/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig    = req.headers['stripe-signature'];
    const secret = process.env.STRIPE_WEBHOOK_SECRET;

    if (!secret) return res.status(500).json({ error: 'Webhook secret not configured' });

    let event;
    try {
        event = stripe.webhooks.constructEvent(req.body, sig, secret);
    } catch (err) {
        console.error('[stripe/webhook] signature failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
        switch (event.type) {

            case 'checkout.session.completed': {
                const session = event.data.object;
                if (session.mode !== 'subscription') break;
                const orgId  = session.metadata?.org_id;
                const subId  = session.subscription;
                const custId = session.customer;
                if (!orgId || !subId) break;

                const sub  = await stripe.subscriptions.retrieve(subId);
                const plan = priceIdToPlan(sub.items.data[0]?.price?.id) || 'starter';

                await db.query(
                    `UPDATE organizations
                     SET plan = $1, stripe_customer_id = $2, stripe_subscription_id = $3,
                         subscription_status = $4, current_period_end = to_timestamp($5)
                     WHERE id = $6`,
                    [plan, custId, subId, sub.status, sub.current_period_end, orgId]
                );
                console.log(`[stripe] checkout.completed org=${orgId} plan=${plan}`);
                break;
            }

            case 'customer.subscription.updated': {
                const sub  = event.data.object;
                const plan = priceIdToPlan(sub.items.data[0]?.price?.id);
                const { rows } = await db.query(
                    `SELECT id FROM organizations WHERE stripe_subscription_id = $1`, [sub.id]
                );
                if (!rows.length) break;
                await db.query(
                    `UPDATE organizations
                     SET plan = COALESCE($1, plan), subscription_status = $2,
                         current_period_end = to_timestamp($3)
                     WHERE stripe_subscription_id = $4`,
                    [plan, sub.status, sub.current_period_end, sub.id]
                );
                console.log(`[stripe] subscription.updated sub=${sub.id} plan=${plan} status=${sub.status}`);
                break;
            }

            case 'customer.subscription.deleted': {
                const sub = event.data.object;
                await db.query(
                    `UPDATE organizations
                     SET plan = 'free', subscription_status = 'canceled',
                         stripe_subscription_id = NULL, current_period_end = NULL
                     WHERE stripe_subscription_id = $1`,
                    [sub.id]
                );
                console.log(`[stripe] subscription.deleted sub=${sub.id}`);
                break;
            }

            case 'customer.subscription.trial_will_end': {
                const sub = event.data.object;
                const { rows } = await db.query(
                    `SELECT name, email, plan FROM organizations WHERE stripe_subscription_id = $1`,
                    [sub.id]
                );
                if (!rows.length || !rows[0].email) break;
                const { name, email, plan } = rows[0];
                const endsAt = sub.trial_end
                    ? new Date(sub.trial_end * 1000).toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })
                    : 'in 3 days';
                await sendEmail({
                    to: email,
                    subject: 'Your PackrAI trial ends in 3 days',
                    html: `
<!DOCTYPE html><html><body style="background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:40px;max-width:560px;margin:0 auto">
<h1 style="font-size:22px;font-weight:700;margin-bottom:6px">Your <span style="color:#3fb950">PackrAI</span> trial ends ${endsAt}</h1>
<p style="color:#8b949e;margin-bottom:24px">Hi <strong style="color:#e6edf3">${name}</strong> — your ${plan || 'trial'} plan trial is wrapping up. Keep your central dashboard, CVE blast-radius search, and SBOM history by confirming your plan.</p>
<a href="https://api.packrai.xyz/dashboard" style="display:inline-block;background:#238636;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;font-size:15px;margin-bottom:24px">Manage billing &rarr;</a>
<p style="color:#8b949e;font-size:13px">No action needed if your card is on file — your subscription continues automatically. Questions? Just reply to this email.</p>
</body></html>`,
                });
                console.log(`[stripe] trial_will_end sub=${sub.id} org=${name} ends=${endsAt}`);
                break;
            }

            case 'invoice.payment_succeeded': {
                const inv = event.data.object;
                if (inv.subscription) {
                    await db.query(
                        `UPDATE organizations SET subscription_status = 'active'
                         WHERE stripe_subscription_id = $1`,
                        [inv.subscription]
                    );
                }
                break;
            }

            case 'invoice.payment_failed': {
                const inv = event.data.object;
                if (inv.subscription) {
                    await db.query(
                        `UPDATE organizations SET subscription_status = 'past_due'
                         WHERE stripe_subscription_id = $1`,
                        [inv.subscription]
                    );
                }
                console.log(`[stripe] payment_failed sub=${inv.subscription}`);
                break;
            }
        }
    } catch (err) {
        console.error('[stripe/webhook] handler error:', err.message);
    }

    res.json({ received: true });
});

module.exports = router;
