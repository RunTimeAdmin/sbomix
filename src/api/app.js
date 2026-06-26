'use strict';

const express = require('express');
const cors    = require('cors');
const helmet  = require('helmet');
const { apiLimiter } = require('./middleware/rateLimits');

const app = express();

app.set('trust proxy', 1);

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc:  ["'self'"],
            scriptSrc:   ["'self'", "'unsafe-inline'"],
            styleSrc:    ["'self'", "'unsafe-inline'"],
            connectSrc:  ["'self'"],
            imgSrc:      ["'self'", 'data:'],
            fontSrc:     ["'self'"],
            objectSrc:   ["'none'"],
            frameSrc:    ["'none'"],
        },
    },
}));
app.disable('x-powered-by');

if (process.env.CORS_ORIGIN) {
    app.use(cors({
        origin: process.env.CORS_ORIGIN,
        methods: ['GET', 'POST', 'DELETE', 'PATCH'],
        allowedHeaders: ['Authorization', 'Content-Type'],
        credentials: true,
    }));
}

// Stripe webhook must come before express.json() — needs raw body
app.use(require('./routes/webhooks'));

app.use(express.json({ limit: '10mb' }));

app.use('/api/', apiLimiter);

// Routes
app.use(require('./routes/staticPages'));
app.use(require('./routes/registration'));
app.use(require('./routes/apps'));
app.use(require('./routes/ingest'));
app.use(require('./routes/scans'));
app.use(require('./routes/vex'));
app.use(require('./routes/keys'));
app.use(require('./routes/billing'));
app.use(require('./routes/admin'));

module.exports = app;
