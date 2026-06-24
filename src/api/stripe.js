'use strict';

const Stripe = require('stripe');

const stripe = Stripe(process.env.STRIPE_SECRET_KEY || '', {
    apiVersion: '2024-06-20',
});

// Price ID → plan name. Set each as an env var in docker-compose.
// Example: STRIPE_PRICE_TEAM_MONTHLY=price_1Abc...
function priceIdToPlan(priceId) {
    if (!priceId) return null;
    const map = {
        [process.env.STRIPE_PRICE_STARTER_MONTHLY]: 'starter',
        [process.env.STRIPE_PRICE_STARTER_ANNUAL]:  'starter',
        [process.env.STRIPE_PRICE_TEAM_MONTHLY]:    'team',
        [process.env.STRIPE_PRICE_TEAM_ANNUAL]:     'team',
        [process.env.STRIPE_PRICE_BUSINESS_MONTHLY]:'business',
        [process.env.STRIPE_PRICE_BUSINESS_ANNUAL]: 'business',
    };
    return map[priceId] || null;
}

const PLAN_LIMITS = {
    free:       { apps: 1,        scansPerMonth: 50,     seats: 1,        retentionDays: 7   },
    starter:    { apps: 10,       scansPerMonth: 500,    seats: 1,        retentionDays: 30  },
    team:       { apps: 50,       scansPerMonth: 5000,   seats: 5,        retentionDays: 180 },
    business:   { apps: 250,      scansPerMonth: 25000,  seats: 20,       retentionDays: 365 },
    enterprise: { apps: Infinity, scansPerMonth: Infinity, seats: Infinity, retentionDays: Infinity },
};

module.exports = { stripe, priceIdToPlan, PLAN_LIMITS };
