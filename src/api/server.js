'use strict';

require('dotenv').config();
const crypto    = require('crypto');
const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const path      = require('path');
const db        = require('./db');
const { validateCycloneDX } = require('../generators/cyclonedx');
const { enrichWithOSV }     = require('../osv');
const { diffComponents, diffVulns } = require('../diff');
const { explainVulnRows }         = require('../explain');
const { startKEVRefresh, applyKEVAfterIngest } = require('../kev');
const { parseGitHubTarget, cloneRepoAsync }   = require('../github');
const { generateFromDirectory }               = require('../pipeline');
const { stripe, priceIdToPlan, PLAN_LIMITS }  = require('./stripe');

// ── Startup guard ─────────────────────────────────────────────────────────────
if (!process.env.HMAC_SECRET) {
    console.error('[packrai] HMAC_SECRET env var is required. Generate one with:\n' +
        '  node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
    process.exit(1);
}

const app = express();

// Deployed behind nginx; trust the first proxy so express-rate-limit
// uses the real client IP from X-Forwarded-For rather than throwing.
app.set('trust proxy', 1);

// ── Security headers ──────────────────────────────────────────────────────────
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc:  ["'self'"],
            scriptSrc:   ["'self'", "'unsafe-inline'"],   // dashboard inline scripts
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

// ── CORS ──────────────────────────────────────────────────────────────────────
// Only enabled when CORS_ORIGIN is explicitly set (browser dashboard use).
// Server-to-server calls (CI, CLI) do not need CORS headers.
if (process.env.CORS_ORIGIN) {
    app.use(cors({
        origin: process.env.CORS_ORIGIN,
        methods: ['GET', 'POST', 'DELETE'],
        allowedHeaders: ['Authorization', 'Content-Type'],
        credentials: true,
    }));
}

// ── Stripe webhook (raw body — MUST come before express.json) ─────────────────
// Stripe signature verification requires the raw unparsed body.
app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
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

                // Retrieve subscription to get price and period
                const sub  = await stripe.subscriptions.retrieve(subId);
                const plan = priceIdToPlan(sub.items.data[0]?.price?.id) || 'starter';

                await db.query(
                    `UPDATE organizations
                     SET plan = $1, stripe_customer_id = $2, stripe_subscription_id = $3,
                         subscription_status = $4, current_period_end = to_timestamp($5)
                     WHERE id = $6`,
                    [plan, custId, subId, sub.status,
                     sub.current_period_end, orgId]
                );
                console.log(`[stripe] checkout.completed org=${orgId} plan=${plan}`);
                break;
            }

            case 'customer.subscription.updated': {
                const sub    = event.data.object;
                const plan   = priceIdToPlan(sub.items.data[0]?.price?.id);
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
        // Still return 200 so Stripe doesn't retry indefinitely
    }

    res.json({ received: true });
});

// ── Body parser ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));

// ── Rate limiting ─────────────────────────────────────────────────────────────
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests' },
});
const ingestLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Ingest rate limit exceeded' },
});
const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many registration attempts — try again in an hour' },
});
const resendKeyLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests — try again in an hour' },
});
const scanLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Scan rate limit exceeded — try again in an hour' },
});

// Scan job constants
const SCAN_TIMEOUT_MS   = 3 * 60 * 1000; // 3 minutes total per job
const activeScanCounts  = new Map();      // orgId → number of in-flight scans

app.use('/api/', apiLimiter);

// ── Email helper (Resend) ─────────────────────────────────────────────────────
async function sendEmail({ to, subject, html }) {
    const key = process.env.RESEND_API_KEY;
    if (!key) { console.warn('[resend] RESEND_API_KEY not set — skipping email'); return; }
    const from = process.env.RESEND_FROM || 'PackrAI <noreply@packrai.xyz>';
    const r = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ from, to, subject, html }),
    });
    if (!r.ok) {
        const body = await r.text();
        console.error('[resend] send failed:', r.status, body);
    }
}

// ── Vulnerability alert emails ────────────────────────────────────────────────
// Called fire-and-forget after each ingest. Sends an email if new critical
// vulns appeared since the previous SBOM scan.
async function sendVulnAlertIfNew(orgId, appId, appName) {
    try {
        const orgRes = await db.query('SELECT email, vuln_alerts FROM organizations WHERE id = $1', [orgId]);
        const email  = orgRes.rows[0]?.email;
        if (!email || orgRes.rows[0]?.vuln_alerts === false) return;

        const sbomRes = await db.query(
            `SELECT id, critical_count FROM sboms WHERE app_id = $1 ORDER BY created_at DESC LIMIT 2`,
            [appId]
        );
        if (sbomRes.rows.length < 2) return; // first scan — no baseline

        const [current, previous] = sbomRes.rows;
        if (current.critical_count <= (previous.critical_count || 0)) return;

        // Find critical vulns present in current SBOM's components but not in previous
        const { rows: newCrits } = await db.query(
            `SELECT v.osv_id, v.cve_id, v.title, v.cvss_score, c.name AS component, c.version
             FROM sbom_components sc
             JOIN components c      ON c.id = sc.component_id
             JOIN vulnerabilities v ON v.component_id = c.id AND v.org_id = $1
             WHERE sc.sbom_id = $2 AND v.severity = 'CRITICAL'
               AND NOT EXISTS (
                 SELECT 1 FROM sbom_components sc2
                 WHERE sc2.sbom_id = $3 AND sc2.component_id = sc.component_id
               )
             ORDER BY v.cvss_score DESC NULLS LAST LIMIT 10`,
            [orgId, current.id, previous.id]
        );
        if (!newCrits.length) return;

        const tableRows = newCrits.map(v =>
            `<tr><td style="padding:6px 12px;border-bottom:1px solid #30363d">${v.cve_id || v.osv_id}</td>` +
            `<td style="padding:6px 12px;border-bottom:1px solid #30363d">${v.component} ${v.version}</td>` +
            `<td style="padding:6px 12px;border-bottom:1px solid #30363d">${v.cvss_score ?? '—'}</td>` +
            `<td style="padding:6px 12px;border-bottom:1px solid #30363d;color:#8b949e;font-size:12px">${v.title ? v.title.slice(0, 80) : '—'}</td></tr>`
        ).join('');

        await sendEmail({
            to: email,
            subject: `[PackrAI] ${newCrits.length} new critical vuln${newCrits.length > 1 ? 's' : ''} in ${appName}`,
            html: `
<!DOCTYPE html><html><body style="background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:40px;max-width:640px;margin:0 auto">
<h1 style="font-size:20px;font-weight:700;margin-bottom:4px">New critical vulnerabilities detected</h1>
<p style="color:#8b949e;margin-bottom:24px"><strong style="color:#e6edf3">${appName}</strong> has ${newCrits.length} new critical finding${newCrits.length > 1 ? 's' : ''} since its last scan.</p>
<table style="width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden">
<thead><tr style="background:#21262d">
  <th style="padding:8px 12px;text-align:left;font-size:12px;color:#8b949e">CVE / ID</th>
  <th style="padding:8px 12px;text-align:left;font-size:12px;color:#8b949e">Component</th>
  <th style="padding:8px 12px;text-align:left;font-size:12px;color:#8b949e">CVSS</th>
  <th style="padding:8px 12px;text-align:left;font-size:12px;color:#8b949e">Summary</th>
</tr></thead>
<tbody>${tableRows}</tbody>
</table>
<p style="margin-top:20px"><a href="https://api.packrai.xyz/dashboard" style="background:#da3633;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:600;font-size:14px">View in Dashboard</a></p>
<p style="margin-top:24px;color:#8b949e;font-size:12px">You receive these alerts because your org has an email on file. <a href="https://api.packrai.xyz/dashboard" style="color:#58a6ff">Manage →</a></p>
</body></html>`,
        });
    } catch (err) {
        console.error('[vuln-alert]', err.message);
    }
}

// ── API key helpers ───────────────────────────────────────────────────────────
function hashApiKey(key) {
    return crypto.createHmac('sha256', process.env.HMAC_SECRET).update(key).digest('hex');
}

function generateApiKey() {
    return crypto.randomBytes(32).toString('hex');
}

// Throttle last_used_at writes — one DB write per key per 5 minutes max
const lastUsedCache = new Map();
const LAST_USED_TTL = 5 * 60 * 1000;

function maybeUpdateLastUsed(keyHash) {
    const now = Date.now();
    if (now - (lastUsedCache.get(keyHash) || 0) < LAST_USED_TTL) return;
    lastUsedCache.set(keyHash, now);
    db.query('UPDATE api_keys SET last_used_at = NOW() WHERE key_hash = $1', [keyHash])
        .catch(() => {});
}

// ── Auth middleware factory ───────────────────────────────────────────────────
// requireScope(scope) returns an Express middleware that:
//   1. Checks the api_keys table (scoped, rotatable keys)
//   2. Falls back to organizations.api_key (legacy org:admin key)
//   3. Enforces the required scope unless the key has org:admin
//
// Scopes:
//   sbom:ingest  — POST /api/v1/ingest
//   sbom:read    — GET  apps, search, report
//   org:admin    — all of the above + key management
function requireScope(scope) {
    return async (req, res, next) => {
        const header = req.headers.authorization || '';
        const key = header.startsWith('Bearer ') ? header.slice(7) : null;
        if (!key) return res.status(401).json({ error: 'Missing Authorization header' });

        try {
            const keyHash = hashApiKey(key);

            // 1. Check scoped api_keys table
            const { rows: keyRows } = await db.query(
                `SELECT k.org_id, k.scopes, o.name AS org_name
                 FROM api_keys k
                 JOIN organizations o ON o.id = k.org_id
                 WHERE k.key_hash = $1 AND k.revoked_at IS NULL`,
                [keyHash]
            );

            if (keyRows.length) {
                const { org_id, scopes, org_name } = keyRows[0];
                if (!scopes.includes(scope) && !scopes.includes('org:admin')) {
                    return res.status(403).json({
                        error: `Scope '${scope}' required`,
                        hint: `This key has scopes: ${scopes.join(', ')}`,
                    });
                }
                req.org    = { id: org_id, name: org_name };
                req.scopes = scopes;
                maybeUpdateLastUsed(keyHash);
                return next();
            }

            // 2. Legacy fallback: organizations.api_key (treated as org:admin)
            const { rows: orgRows } = await db.query(
                'SELECT id, name FROM organizations WHERE api_key = $1',
                [keyHash]
            );
            if (orgRows.length) {
                req.org    = orgRows[0];
                req.scopes = ['org:admin'];
                return next();
            }

            return res.status(401).json({ error: 'Invalid API key' });
        } catch (err) {
            console.error('[auth]', err.message);
            res.status(500).json({ error: 'Internal server error' });
        }
    };
}

// ── OSV auto-enrichment ───────────────────────────────────────────────────────
// Called async after ingest when the payload contained no vulnerability data.
// Queries OSV for every component purl and stores results without blocking
// the ingest response.
async function osvEnrichAsync(orgId, cdxComponents, purlToCompId) {
    const components = cdxComponents.map(c => ({
        name:      c.name,
        version:   c.version || 'unknown',
        purl:      c.purl,
        ecosystem: c.purl.split(':')[1]?.split('/')[0] ?? 'unknown',
    }));

    await enrichWithOSV(components, { timeout: 20000 });

    const vulnRows = [];
    for (const comp of components) {
        if (!comp.vulnerabilities?.length) continue;
        const compId = purlToCompId.get(comp.purl);
        if (!compId) continue;
        for (const v of comp.vulnerabilities) {
            vulnRows.push({
                compId,
                osvId:        v.id,
                cveId:        v.aliases?.find(a => a.startsWith('CVE-')) ?? null,
                severity:     v.severity === 'UNKNOWN' ? null : v.severity,
                cvssScore:    (v.cvss && !isNaN(parseFloat(v.cvss))) ? parseFloat(v.cvss) : null,
                fixedVersion: v.fixedIn?.[0] ?? null,
                title:        v.summary || null,
            });
        }
    }

    if (vulnRows.length) {
        await db.query(
            `INSERT INTO vulnerabilities
               (component_id, org_id, osv_id, cve_id, severity, cvss_score, fixed_version, title)
             SELECT t.comp_id, $1, t.osv_id, t.cve_id, t.severity, t.cvss_score, t.fixed_version, t.title
             FROM UNNEST($2::uuid[], $3::text[], $4::text[], $5::text[], $6::numeric[], $7::text[], $8::text[])
                  AS t(comp_id, osv_id, cve_id, severity, cvss_score, fixed_version, title)
             ON CONFLICT (component_id, osv_id) DO UPDATE
               SET severity      = EXCLUDED.severity,
                   cvss_score    = COALESCE(EXCLUDED.cvss_score, vulnerabilities.cvss_score),
                   fixed_version = COALESCE(EXCLUDED.fixed_version, vulnerabilities.fixed_version),
                   last_checked  = NOW()`,
            [orgId,
             vulnRows.map(r => r.compId),
             vulnRows.map(r => r.osvId),
             vulnRows.map(r => r.cveId),
             vulnRows.map(r => r.severity),
             vulnRows.map(r => r.cvssScore),
             vulnRows.map(r => r.fixedVersion),
             vulnRows.map(r => r.title)]
        );
    }
}

// ── Root → register ───────────────────────────────────────────────────────────
app.get('/', (_req, res) => res.redirect('/register'));

// ── Dashboard ─────────────────────────────────────────────────────────────────
app.get('/dashboard', (_req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});
app.get('/register', (_req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});
app.get('/terms', (_req, res) => {
    res.sendFile(path.join(__dirname, 'terms.html'));
});
app.get('/privacy', (_req, res) => {
    res.sendFile(path.join(__dirname, 'privacy.html'));
});
app.get('/docs', (_req, res) => {
    res.sendFile(path.join(__dirname, 'docs.html'));
});
app.get('/pricing', (_req, res) => {
    res.sendFile(path.join(__dirname, 'pricing.html'));
});

// ── Key recovery page ─────────────────────────────────────────────────────────
app.get('/recover', (_req, res) => {
    res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Recover API Key — PackrAI</title>
<style>*{box-sizing:border-box}body{background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px}
.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:40px;max-width:440px;width:100%}
h1{font-size:22px;margin:0 0 6px}p{color:#8b949e;margin:0 0 20px}
input{width:100%;background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:10px 12px;color:#e6edf3;font-size:14px;outline:none}
input:focus{border-color:#58a6ff}
.btn{width:100%;background:#238636;color:#fff;padding:10px;border-radius:6px;font-weight:600;font-size:14px;border:none;cursor:pointer;margin-top:12px}
.msg{margin-top:14px;padding:10px 14px;border-radius:6px;font-size:13px;display:none}
.ok{background:#1f4722;color:#3fb950;display:block}.err{background:#4a1919;color:#f85149;display:block}
a{color:#58a6ff;text-decoration:none}</style></head>
<body><div class="card">
<h1>Recover API Key</h1>
<p>Enter your registered email and we'll send a new API key.</p>
<input type="email" id="email" placeholder="you@example.com" autocomplete="email">
<button class="btn" id="btn">Send key</button>
<div class="msg" id="msg"></div>
<p style="margin-top:24px;font-size:13px"><a href="/register">Create a new account</a> &nbsp;·&nbsp; <a href="/dashboard">Dashboard</a></p>
</div>
<script>
document.getElementById('btn').addEventListener('click', async () => {
  const email = document.getElementById('email').value.trim();
  const msg = document.getElementById('msg');
  const btn = document.getElementById('btn');
  msg.className = 'msg'; msg.textContent = '';
  if (!email) { msg.className = 'msg err'; msg.textContent = 'Please enter your email.'; return; }
  btn.disabled = true; btn.textContent = 'Sending…';
  try {
    const r = await fetch('/api/v1/resend-key', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email }) });
    const j = await r.json();
    if (r.ok) { msg.className = 'msg ok'; msg.textContent = j.message; }
    else { msg.className = 'msg err'; msg.textContent = j.error || 'Request failed.'; }
  } catch { msg.className = 'msg err'; msg.textContent = 'Network error — please try again.'; }
  btn.disabled = false; btn.textContent = 'Send key';
});
</script></body></html>`);
});

// ── Email verification ────────────────────────────────────────────────────────
// GET /verify?token=…  — clicked from verification email
app.get('/verify', async (req, res) => {
    const { token } = req.query;

    const page = (title, body) =>
        `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${title} — PackrAI</title>` +
        `<style>*{box-sizing:border-box}body{background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px}` +
        `.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:40px;max-width:560px;width:100%}` +
        `h1{font-size:22px;margin:0 0 12px}p{color:#8b949e;margin:0 0 16px}` +
        `.key{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:14px;font-family:monospace;font-size:13px;word-break:break-all;color:#3fb950;margin-bottom:6px;cursor:pointer;user-select:all}` +
        `.btn{display:inline-block;background:#238636;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:600;font-size:14px}` +
        `.warn{font-size:12px;color:#f0883e}a{color:#58a6ff}</style></head>` +
        `<body><div class="card">${body}</div></body></html>`;

    if (!token || typeof token !== 'string') {
        return res.status(400).send(page('Invalid link', '<h1>Invalid link</h1><p>This verification link is missing or malformed.</p>'));
    }

    try {
        const { rows } = await db.query(
            `SELECT email, org_name FROM email_verifications WHERE token = $1 AND expires_at > NOW()`,
            [token]
        );
        if (!rows.length) {
            return res.status(410).send(page('Link expired',
                '<h1>Link expired</h1><p>This verification link has expired or already been used.</p>' +
                '<p><a href="/register">Register again →</a></p>'));
        }

        const { email, org_name } = rows[0];

        // Handle double-click: org already created
        const existing = await db.query('SELECT id FROM organizations WHERE email = $1', [email]);
        if (existing.rows.length) {
            await db.query('DELETE FROM email_verifications WHERE token = $1', [token]);
            return res.send(page('Already verified',
                '<h1>Already verified</h1><p>This email was already verified. Check your inbox for your API key, or ' +
                '<a href="/recover">request a new key</a>.</p><br><a href="/dashboard" class="btn">Go to dashboard</a>'));
        }

        // Create org + key atomically, delete token
        const apiKey  = generateApiKey();
        const keyHash = hashApiKey(apiKey);
        await db.tx(async (client) => {
            await client.query(
                'INSERT INTO organizations (name, email, api_key) VALUES ($1, $2, $3)',
                [org_name, email, keyHash]
            );
            await client.query('DELETE FROM email_verifications WHERE token = $1', [token]);
        });

        // Also email the key for safekeeping
        await sendEmail({
            to: email,
            subject: 'Your PackrAI API Key',
            html: `
<!DOCTYPE html><html><body style="background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:40px;max-width:560px;margin:0 auto">
<h1 style="font-size:22px;font-weight:700;margin-bottom:6px">Welcome to <span style="color:#3fb950">PackrAI</span></h1>
<p style="color:#8b949e;margin-bottom:28px">Your org <strong style="color:#e6edf3">${org_name}</strong> is ready.</p>
<p style="margin-bottom:10px;font-weight:600">Your API key</p>
<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;font-family:monospace;font-size:13px;word-break:break-all;color:#3fb950;margin-bottom:6px">${apiKey}</div>
<p style="color:#8b949e;font-size:12px;margin-bottom:28px">⚠ Save this key — it won't be shown again.</p>
<h2 style="font-size:15px;font-weight:600;margin-bottom:12px">Quick start</h2>
<pre style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;font-size:12px;overflow-x:auto;color:#e6edf3">npm install -g packrai
packrai owner/repo --push --api-key ${apiKey}
open https://api.packrai.xyz/dashboard</pre>
<p style="margin-top:28px;color:#8b949e;font-size:13px">Need help? Reply to this email or visit <a href="https://packrai.xyz" style="color:#58a6ff">packrai.xyz</a>.</p>
</body></html>`,
        });

        return res.send(page('Email verified',
            `<h1 style="color:#3fb950">✓ Email verified!</h1>` +
            `<p>Welcome, <strong style="color:#e6edf3">${org_name}</strong>. Your API key is below and has been emailed to <strong style="color:#e6edf3">${email}</strong>.</p>` +
            `<p style="color:#e6edf3;font-weight:600;margin-bottom:8px">Your API key</p>` +
            `<div class="key" id="key" title="Click to copy">${apiKey}</div>` +
            `<p class="warn" style="margin-bottom:24px">⚠ Save this key — it won't be shown again after you leave this page.</p>` +
            `<a href="/dashboard" class="btn">Open dashboard</a>` +
            `<script>document.getElementById('key').addEventListener('click',function(){navigator.clipboard.writeText(this.textContent).then(()=>{this.style.borderColor='#3fb950';setTimeout(()=>this.style.borderColor='',1500)})});<\/script>`
        ));
    } catch (err) {
        console.error('[verify]', err.message);
        return res.status(500).send(page('Error',
            '<h1>Something went wrong</h1><p>Please try registering again.</p><a href="/register">← Register</a>'));
    }
});

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => res.json({ ok: true }));

// ── Me ────────────────────────────────────────────────────────────────────────
app.get('/api/v1/me', requireScope('sbom:read'), async (req, res) => {
    try {
        const { rows } = await db.query(
            'SELECT vuln_alerts, plan, subscription_status, current_period_end FROM organizations WHERE id = $1',
            [req.org.id]
        );
        const r = rows[0] || {};
        res.json({
            org:                req.org.name,
            scopes:             req.scopes || [],
            vuln_alerts:        r.vuln_alerts ?? true,
            plan:               r.plan || 'free',
            subscription_status: r.subscription_status || null,
            current_period_end: r.current_period_end || null,
        });
    } catch {
        res.json({ org: req.org.name, scopes: req.scopes || [], vuln_alerts: true, plan: 'free' });
    }
});

// PATCH /api/v1/account/settings  body: { vuln_alerts: bool }
app.patch('/api/v1/account/settings', requireScope('org:admin'), async (req, res) => {
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

// ── Self-service registration ─────────────────────────────────────────────────
// POST /api/v1/register  body: { email, orgName }
// Sends an email verification link. Org + key are created at GET /verify.
app.post('/api/v1/register', registerLimiter, async (req, res) => {
    const { email, orgName } = req.body;

    if (!email || typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
        return res.status(400).json({ error: 'A valid email address is required' });
    }
    if (!orgName || typeof orgName !== 'string' || !orgName.trim()) {
        return res.status(400).json({ error: 'orgName is required' });
    }
    if (orgName.trim().length > 100) {
        return res.status(400).json({ error: 'orgName must be 100 characters or fewer' });
    }

    const cleanEmail   = email.trim().toLowerCase();
    const cleanOrgName = orgName.trim();

    try {
        // Already registered — return success silently to avoid leaking
        const existing = await db.query(
            'SELECT id FROM organizations WHERE email = $1',
            [cleanEmail]
        );
        if (existing.rows.length) {
            return res.json({ message: 'Check your email for a verification link.' });
        }

        // Upsert a pending verification token (24h expiry; overwrites stale tokens)
        const token     = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
        await db.query(
            `INSERT INTO email_verifications (email, org_name, token, expires_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (email) DO UPDATE
               SET org_name   = EXCLUDED.org_name,
                   token      = EXCLUDED.token,
                   expires_at = EXCLUDED.expires_at,
                   created_at = NOW()`,
            [cleanEmail, cleanOrgName, token, expiresAt]
        );

        const verifyUrl = `https://api.packrai.xyz/verify?token=${token}`;
        await sendEmail({
            to: cleanEmail,
            subject: 'Verify your PackrAI email',
            html: `
<!DOCTYPE html><html><body style="background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:40px;max-width:560px;margin:0 auto">
<h1 style="font-size:22px;font-weight:700;margin-bottom:6px">Verify your <span style="color:#3fb950">PackrAI</span> email</h1>
<p style="color:#8b949e;margin-bottom:28px">One click to activate <strong style="color:#e6edf3">${cleanOrgName}</strong>. This link expires in 24 hours.</p>
<a href="${verifyUrl}" style="display:inline-block;background:#238636;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;font-size:15px;margin-bottom:28px">Verify email &amp; get API key</a>
<p style="color:#8b949e;font-size:12px;margin-bottom:4px">Or copy this URL into your browser:</p>
<div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px;font-family:monospace;font-size:11px;word-break:break-all;color:#58a6ff">${verifyUrl}</div>
<p style="margin-top:28px;color:#8b949e;font-size:12px">If you didn't sign up for PackrAI, you can safely ignore this email.</p>
</body></html>`,
        });

        res.json({ message: 'Check your email for a verification link.' });
    } catch (err) {
        console.error('[register]', err.message);
        res.status(500).json({ error: 'Registration failed — please try again' });
    }
});

// ── Key recovery ──────────────────────────────────────────────────────────────
// POST /api/v1/resend-key  body: { email }
// Issues a new org:admin key for an existing account, emailed to the address.
app.post('/api/v1/resend-key', resendKeyLimiter, async (req, res) => {
    const { email } = req.body;

    if (!email || typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
        return res.status(400).json({ error: 'A valid email address is required' });
    }

    const cleanEmail = email.trim().toLowerCase();

    try {
        const { rows } = await db.query(
            'SELECT id, name FROM organizations WHERE email = $1',
            [cleanEmail]
        );

        if (rows.length) {
            const { id: orgId, name: orgName } = rows[0];
            const apiKey  = generateApiKey();
            const keyHash = hashApiKey(apiKey);

            await db.query(
                `INSERT INTO api_keys (org_id, name, key_hash, scopes)
                 VALUES ($1, 'recovery', $2, '{org:admin}')`,
                [orgId, keyHash]
            );

            await sendEmail({
                to: cleanEmail,
                subject: 'Your PackrAI API Key (recovery)',
                html: `
<!DOCTYPE html><html><body style="background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:40px;max-width:560px;margin:0 auto">
<h1 style="font-size:22px;font-weight:700;margin-bottom:6px"><span style="color:#3fb950">PackrAI</span> — API key recovery</h1>
<p style="color:#8b949e;margin-bottom:28px">Here is a new API key for <strong style="color:#e6edf3">${orgName}</strong>. This key has <strong>org:admin</strong> access.</p>
<p style="margin-bottom:10px;font-weight:600">New API key</p>
<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;font-family:monospace;font-size:13px;word-break:break-all;color:#3fb950;margin-bottom:6px">${apiKey}</div>
<p style="color:#8b949e;font-size:12px;margin-bottom:28px">⚠ Save this key — it won't be shown again.</p>
<p style="color:#8b949e;font-size:13px">If you didn't request this, you can ignore it — your existing keys remain active.</p>
<p style="margin-top:16px"><a href="https://api.packrai.xyz/dashboard" style="color:#58a6ff">Open dashboard →</a></p>
</body></html>`,
            });
        }

        res.json({ message: 'If that email is registered, a new API key has been sent.' });
    } catch (err) {
        console.error('[resend-key]', err.message);
        res.status(500).json({ error: 'Request failed — please try again' });
    }
});

// ── Shared ingest transaction ─────────────────────────────────────────────────
// Called from both the HTTP ingest route and the server-side scan job runner.
async function executeIngestTx(client, orgId, appName, { version, commit, branch, cyclonedx, spdx, stats, aibom }) {
    const appRes = await client.query(
        `INSERT INTO applications (org_id, name)
         VALUES ($1, $2)
         ON CONFLICT (org_id, name) DO UPDATE SET name = EXCLUDED.name
         RETURNING id`,
        [orgId, appName]
    );
    const appId = appRes.rows[0].id;

    const sbomRes = await client.query(
        `INSERT INTO sboms
           (app_id, org_id, version, commit_sha, branch, cyclonedx, spdx, aibom,
            component_count, vulnerability_count, critical_count,
            quality_score, ecosystems, elapsed_ms,
            ai_models, ai_threats, ai_critical, least_agency_score, generated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,NOW())
         RETURNING id`,
        [
            appId, orgId, version, commit, branch,
            cyclonedx, spdx || null, aibom ? JSON.stringify(aibom) : null,
            stats?.totalComponents ?? 0,
            stats?.vulnerabilities ?? 0,
            stats?.critical ?? 0,
            stats?.qualityScore ?? null,
            stats?.ecosystems ?? [],
            stats?.elapsedMs ?? null,
            stats?.aiModels    ?? 0,
            stats?.aiThreats   ?? 0,
            stats?.aiCritical  ?? 0,
            stats?.leastAgencyScore ?? null,
        ]
    );
    const sbomId = sbomRes.rows[0].id;

    await client.query(
        `INSERT INTO app_latest_sboms
           (app_id, org_id, sbom_id, created_at,
            component_count, vulnerability_count, critical_count, quality_score, ecosystems)
         VALUES ($1,$2,$3,NOW(),$4,$5,$6,$7,$8)
         ON CONFLICT (app_id) DO UPDATE
           SET sbom_id             = EXCLUDED.sbom_id,
               created_at          = EXCLUDED.created_at,
               component_count     = EXCLUDED.component_count,
               vulnerability_count = EXCLUDED.vulnerability_count,
               critical_count      = EXCLUDED.critical_count,
               quality_score       = EXCLUDED.quality_score,
               ecosystems          = EXCLUDED.ecosystems
         WHERE app_latest_sboms.created_at <= EXCLUDED.created_at`,
        [
            appId, orgId, sbomId,
            stats?.totalComponents ?? 0,
            stats?.vulnerabilities ?? 0,
            stats?.critical ?? 0,
            stats?.qualityScore ?? null,
            stats?.ecosystems ?? [],
        ]
    );

    const rootPurl    = cyclonedx.metadata?.component?.purl;
    const directPurls = new Set(
        cyclonedx.dependencies?.find(d => d.ref === rootPurl)?.dependsOn ?? []
    );

    const components = cyclonedx.components.filter(c => c.purl);
    if (!components.length) return { sbomId, purlToCompId: new Map(), appId };

    const purls      = components.map(c => c.purl);
    const names      = components.map(c => c.name);
    const versions   = components.map(c => c.version);
    const ecosystems = components.map(c => c.purl.split(':')[1]?.split('/')[0] ?? 'unknown');
    const licenses   = components.map(c =>
        c.licenses?.[0]?.license?.id || c.licenses?.[0]?.license?.name || null);

    const { rows: compRows } = await client.query(
        `INSERT INTO components (org_id, purl, name, version, ecosystem, license)
         SELECT $1, t.purl, t.name, t.version, t.ecosystem, t.license
         FROM UNNEST($2::text[], $3::text[], $4::text[], $5::text[], $6::text[])
              AS t(purl, name, version, ecosystem, license)
         ON CONFLICT (org_id, purl) DO UPDATE
           SET license = COALESCE(EXCLUDED.license, components.license)
         RETURNING purl, id`,
        [orgId, purls, names, versions, ecosystems, licenses]
    );

    const purlToCompId = new Map(compRows.map(r => [r.purl, r.id]));

    const linkRows = components
        .map(c => ({ id: purlToCompId.get(c.purl), scope: c.scope ?? 'required', direct: directPurls.has(c.purl) }))
        .filter(r => r.id);

    if (linkRows.length) {
        await client.query(
            `INSERT INTO sbom_components (sbom_id, component_id, scope, is_direct)
             SELECT $1, t.comp_id, t.scope, t.is_direct
             FROM UNNEST($2::uuid[], $3::text[], $4::boolean[])
                  AS t(comp_id, scope, is_direct)
             ON CONFLICT DO NOTHING`,
            [sbomId, linkRows.map(r => r.id), linkRows.map(r => r.scope), linkRows.map(r => r.direct)]
        );
    }

    const vulnRows = [];
    for (const v of (cyclonedx.vulnerabilities || [])) {
        const osvId  = v.id;
        const cveId  = v.advisories?.find(a => a.title?.startsWith('CVE-'))?.title
                    || (osvId?.startsWith('CVE-') ? osvId : null);
        const rating = v.ratings?.[0];
        for (const affected of (v.affects || [])) {
            const compId = purlToCompId.get(affected.ref);
            if (!compId) continue;
            vulnRows.push({
                compId, osvId, cveId,
                severity:  rating?.severity?.toUpperCase() ?? null,
                cvssScore: rating?.score ?? null,
                title:     v.description || null,
            });
        }
    }
    if (vulnRows.length) {
        await client.query(
            `INSERT INTO vulnerabilities
               (component_id, org_id, osv_id, cve_id, severity, cvss_score, fixed_version, title)
             SELECT t.comp_id, $1, t.osv_id, t.cve_id, t.severity, t.cvss_score, NULL, t.title
             FROM UNNEST($2::uuid[], $3::text[], $4::text[], $5::text[], $6::numeric[], $7::text[])
                  AS t(comp_id, osv_id, cve_id, severity, cvss_score, title)
             ON CONFLICT (component_id, osv_id) DO UPDATE
               SET severity     = EXCLUDED.severity,
                   cvss_score   = EXCLUDED.cvss_score,
                   last_checked = NOW()`,
            [orgId,
             vulnRows.map(r => r.compId), vulnRows.map(r => r.osvId),
             vulnRows.map(r => r.cveId),  vulnRows.map(r => r.severity),
             vulnRows.map(r => r.cvssScore), vulnRows.map(r => r.title)]
        );
    }

    return { sbomId, purlToCompId, appId };
}

// ── Server-side scan job runner ───────────────────────────────────────────────
async function runScanJob(jobId, orgId, repo, ref, token) {
    let cleanup  = null;
    let aborted  = false;

    const timeoutHandle = setTimeout(() => {
        aborted = true;
        if (cleanup) { try { cleanup(); cleanup = null; } catch {} }
    }, SCAN_TIMEOUT_MS);

    try {
        await db.query(`UPDATE scan_jobs SET status='running', updated_at=NOW() WHERE id=$1`, [jobId]);

        const target = parseGitHubTarget(repo + (ref ? `@${ref}` : ''));
        if (!target) throw new Error('Invalid repository format. Use owner/repo or owner/repo@branch.');

        const cloned = await cloneRepoAsync(target, { token: token || undefined });
        cleanup = cloned.cleanup;
        if (aborted) throw new Error('Scan timed out during clone — repository may be too large. Use the CLI.');

        let result;
        try {
            result = await generateFromDirectory(cloned.dir, {
                name:      target.repo,
                version:   ref || cloned.commitSha?.slice(0, 7) || 'unknown',
                vulns:     false,   // OSV fires async after ingest
                licenses:  false,   // skipped for speed on server scans
                recursive: true,
            });
        } catch (pipeErr) {
            // "No lock files found" and similar — surface a clean message
            throw new Error(pipeErr.message.split('\n')[0]);
        }

        if (aborted) throw new Error('Scan timed out during analysis.');

        cleanup();
        cleanup = null;

        const appName = target.repo;
        const { sbomId, purlToCompId, appId } = await db.tx((client) =>
            executeIngestTx(client, orgId, appName, {
                version:   ref || cloned.commitSha?.slice(0, 7) || 'unknown',
                commit:    cloned.commitSha,
                branch:    ref || null,
                cyclonedx: result.cyclonedx,
                spdx:      result.spdx,
                stats:     result.stats,
                aibom:     result.aiBom || null,
            })
        );

        await db.query(
            `UPDATE scan_jobs SET status='done', app_name=$2, sbom_id=$3, updated_at=NOW() WHERE id=$1`,
            [jobId, appName, sbomId]
        );

        // Fire OSV enrichment + alerts async (same as normal ingest)
        if (purlToCompId.size > 0) {
            osvEnrichAsync(orgId, result.cyclonedx.components.filter(c => c.purl), purlToCompId)
                .then(() => {
                    applyKEVAfterIngest(orgId);
                    return sendVulnAlertIfNew(orgId, appId, appName);
                })
                .catch(err => console.error('[scan-osv]', err.message));
        }

    } catch (err) {
        if (cleanup) { try { cleanup(); } catch {} }
        const msg = aborted
            ? 'Scan timed out — repository may be too large. Use the CLI for large repos.'
            : err.message;
        await db.query(
            `UPDATE scan_jobs SET status='failed', error=$2, updated_at=NOW() WHERE id=$1`,
            [jobId, msg.slice(0, 500)]
        ).catch(() => {});
    } finally {
        clearTimeout(timeoutHandle);
        activeScanCounts.set(orgId, Math.max(0, (activeScanCounts.get(orgId) || 0) - 1));
    }
}

// ── Ingest ────────────────────────────────────────────────────────────────────
// POST /api/v1/ingest
// Body: { app, version, commit, branch, cyclonedx, spdx, stats }
app.post('/api/v1/ingest', ingestLimiter, requireScope('sbom:ingest'), async (req, res) => {
    const { app: appName, version, commit, branch, cyclonedx, spdx, stats, aibom } = req.body;

    // ── Plan limit check ──────────────────────────────────────────────────────
    try {
        const { rows: orgRows } = await db.query(
            `SELECT plan, subscription_status FROM organizations WHERE id = $1`, [req.org.id]
        );
        const plan   = orgRows[0]?.plan || 'free';
        const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.free;

        // App count: is this a new app?
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

        // Monthly scan count
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
        // Non-fatal — don't block ingest on a DB error in the limit check
    }

    // ── Input validation ──────────────────────────────────────────────────────
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

        res.status(201).json({ sbomId });

        // Fire-and-forget OSV enrichment when payload had no vulnerability data
        if (!cyclonedx.vulnerabilities?.length && purlToCompId.size > 0) {
            osvEnrichAsync(req.org.id, cyclonedx.components.filter(c => c.purl), purlToCompId)
                .then(() => {
                    applyKEVAfterIngest(req.org.id);
                    return sendVulnAlertIfNew(req.org.id, appId, appName);
                })
                .catch(err => console.error('[osv-enrich]', err.message));
        } else {
            // Vulns came from the CycloneDX payload — cross-reference KEV immediately
            applyKEVAfterIngest(req.org.id);
            sendVulnAlertIfNew(req.org.id, appId, appName)
                .catch(err => console.error('[vuln-alert]', err.message));
        }
    } catch (err) {
        console.error('[ingest]', err.message);
        res.status(500).json({ error: 'Ingest failed' });
    }
});

// ── Apps ──────────────────────────────────────────────────────────────────────
app.get('/api/v1/apps', requireScope('sbom:read'), async (req, res) => {
    try {
        const { rows } = await db.query(
            `SELECT a.id, a.name, a.repo_url,
                    COUNT(s.id)             AS sbom_count,
                    ls.created_at           AS last_scanned,
                    ls.critical_count,
                    ls.vulnerability_count,
                    ls.component_count,
                    ls.quality_score,
                    ls.ecosystems
             FROM applications a
             LEFT JOIN sboms s             ON s.app_id = a.id
             LEFT JOIN app_latest_sboms ls ON ls.app_id = a.id
             WHERE a.org_id = $1
             GROUP BY a.id, a.name, a.repo_url, ls.created_at, ls.critical_count,
                      ls.vulnerability_count, ls.component_count, ls.quality_score, ls.ecosystems
             ORDER BY ls.critical_count DESC NULLS LAST, a.name`,
            [req.org.id]
        );
        res.json({ apps: rows });
    } catch (err) {
        console.error('[apps]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/v1/apps/:name/vulns
// Vulnerability list for the latest SBOM of an app, excluding VEX not_affected.
app.get('/api/v1/apps/:name/vulns', requireScope('sbom:read'), async (req, res) => {
    try {
        const appRes = await db.query(
            `SELECT a.id FROM applications a
             WHERE a.org_id = $1 AND a.name = $2`,
            [req.org.id, req.params.name]
        );
        if (!appRes.rows.length) return res.status(404).json({ error: 'App not found' });
        const appId = appRes.rows[0].id;

        const { rows } = await db.query(
            `SELECT v.osv_id, v.cve_id, v.severity, v.cvss_score,
                    v.fixed_version, v.title, v.kev,
                    c.id AS component_id, c.name AS component,
                    c.version AS component_version, c.ecosystem, c.purl
             FROM app_latest_sboms ls
             JOIN sbom_components sc     ON sc.sbom_id = ls.sbom_id
             JOIN components c           ON c.id = sc.component_id
             JOIN vulnerabilities v      ON v.component_id = c.id AND v.org_id = $1
             LEFT JOIN vex_statements vx ON vx.component_id = c.id
                                        AND vx.osv_id = v.osv_id AND vx.org_id = $1
             WHERE ls.app_id = $2
               AND (vx.status IS NULL OR vx.status != 'not_affected')
             ORDER BY v.cvss_score DESC NULLS LAST, v.severity, c.name`,
            [req.org.id, appId]
        );
        res.json({ vulnerabilities: rows });
    } catch (err) {
        console.error('[apps/vulns]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/v1/apps/:name/sbom', requireScope('sbom:read'), async (req, res) => {
    try {
        const { rows } = await db.query(
            `SELECT s.id, s.version, s.commit_sha, s.branch, s.component_count,
                    s.vulnerability_count, s.critical_count, s.quality_score,
                    s.ecosystems, s.elapsed_ms, s.created_at
             FROM sboms s
             JOIN applications a ON a.id = s.app_id
             WHERE a.org_id = $1 AND a.name = $2
             ORDER BY s.created_at DESC LIMIT 1`,
            [req.org.id, req.params.name]
        );
        if (!rows.length) return res.status(404).json({ error: 'App not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('[apps/sbom]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/v1/apps/:name/components
app.get('/api/v1/apps/:name/components', requireScope('sbom:read'), async (req, res) => {
    try {
        const appRes = await db.query(
            `SELECT a.id FROM applications a WHERE a.org_id = $1 AND a.name = $2`,
            [req.org.id, req.params.name]
        );
        if (!appRes.rows.length) return res.status(404).json({ error: 'App not found' });
        const appId = appRes.rows[0].id;

        const { rows } = await db.query(
            `SELECT c.name, c.version, c.ecosystem, c.purl,
                    COUNT(v.id) FILTER (WHERE vx.status IS NULL OR vx.status != 'not_affected') AS vuln_count,
                    MAX(v.severity) AS max_severity
             FROM app_latest_sboms ls
             JOIN sbom_components sc    ON sc.sbom_id = ls.sbom_id
             JOIN components c          ON c.id = sc.component_id
             LEFT JOIN vulnerabilities v  ON v.component_id = c.id AND v.org_id = $1
             LEFT JOIN vex_statements vx  ON vx.component_id = c.id
                                         AND vx.osv_id = v.osv_id AND vx.org_id = $1
             WHERE ls.app_id = $2
             GROUP BY c.name, c.version, c.ecosystem, c.purl
             ORDER BY vuln_count DESC, c.name`,
            [req.org.id, appId]
        );
        res.json({ components: rows });
    } catch (err) {
        console.error('[apps/components]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/v1/apps/:name/sbom/download?format=cyclonedx|spdx
app.get('/api/v1/apps/:name/sbom/download', requireScope('sbom:read'), async (req, res) => {
    const format = (req.query.format || 'cyclonedx').toLowerCase();
    if (!['cyclonedx', 'spdx'].includes(format)) {
        return res.status(400).json({ error: 'format must be cyclonedx or spdx' });
    }
    try {
        const { rows } = await db.query(
            `SELECT s.cyclonedx, s.spdx, s.version, s.created_at
             FROM sboms s
             JOIN applications a ON a.id = s.app_id
             WHERE a.org_id = $1 AND a.name = $2
             ORDER BY s.created_at DESC LIMIT 1`,
            [req.org.id, req.params.name]
        );
        if (!rows.length) return res.status(404).json({ error: 'App not found' });

        const row = rows[0];
        if (format === 'spdx') {
            if (!row.spdx) return res.status(404).json({ error: 'No SPDX document stored for this app' });
            const filename = `${req.params.name}-sbom.spdx.json`;
            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            return res.json(row.spdx);
        }

        // CycloneDX (always present)
        const filename = `${req.params.name}-sbom.cdx.json`;
        res.setHeader('Content-Type', 'application/vnd.cyclonedx+json');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.json(row.cyclonedx);
    } catch (err) {
        console.error('[sbom/download]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ── CVE Search ────────────────────────────────────────────────────────────────
app.get('/api/v1/search', requireScope('sbom:read'), async (req, res) => {
    const { cve, osv } = req.query;
    const id = cve || osv;
    if (!id) return res.status(400).json({ error: 'Provide ?cve= or ?osv= parameter' });

    try {
        const { rows } = await db.query(
            `SELECT
               a.name              AS app,
               s.version           AS app_version,
               ls.created_at       AS last_scanned,
               c.purl,
               c.name              AS component,
               c.version           AS component_version,
               v.osv_id, v.cve_id, v.severity, v.cvss_score, v.fixed_version, v.title,
               vx.status           AS vex_status,
               vx.justification    AS vex_justification
             FROM vulnerabilities v
             JOIN components c          ON c.id = v.component_id
             JOIN sbom_components sc    ON sc.component_id = c.id
             JOIN app_latest_sboms ls   ON ls.sbom_id = sc.sbom_id
             JOIN sboms s               ON s.id = ls.sbom_id
             JOIN applications a        ON a.id = ls.app_id
             LEFT JOIN vex_statements vx ON vx.component_id = c.id
                                        AND vx.osv_id = v.osv_id
                                        AND vx.org_id = v.org_id
             WHERE v.org_id = $1 AND (v.cve_id = $2 OR v.osv_id = $2)
             ORDER BY v.cvss_score DESC NULLS LAST, a.name`,
            [req.org.id, id]
        );
        res.json({ query: id, exposedApps: rows.length, results: rows });
    } catch (err) {
        console.error('[search]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ── Risk Report ───────────────────────────────────────────────────────────────
app.get('/api/v1/report', requireScope('sbom:read'), async (req, res) => {
    try {
        const [topVulns, topApps, summary] = await Promise.all([
            db.query(
                `SELECT v.cve_id, v.osv_id, v.severity, v.cvss_score, v.title,
                        COUNT(DISTINCT a.id) AS apps_affected
                 FROM vulnerabilities v
                 JOIN components c          ON c.id = v.component_id
                 JOIN sbom_components sc    ON sc.component_id = c.id
                 JOIN app_latest_sboms ls   ON ls.sbom_id = sc.sbom_id
                 JOIN applications a        ON a.id = ls.app_id
                 WHERE v.org_id = $1 AND v.severity IN ('CRITICAL','HIGH')
                   AND NOT EXISTS (
                     SELECT 1 FROM vex_statements vx
                     WHERE vx.component_id = v.component_id
                       AND vx.osv_id = v.osv_id
                       AND vx.org_id = v.org_id
                       AND vx.status = 'not_affected'
                   )
                 GROUP BY v.cve_id, v.osv_id, v.severity, v.cvss_score, v.title
                 ORDER BY v.cvss_score DESC NULLS LAST, apps_affected DESC
                 LIMIT 10`,
                [req.org.id]
            ),
            db.query(
                `SELECT a.name, ls.critical_count, ls.vulnerability_count,
                        ls.component_count, ls.quality_score, ls.created_at
                 FROM app_latest_sboms ls
                 JOIN applications a ON a.id = ls.app_id
                 WHERE ls.org_id = $1
                 ORDER BY ls.critical_count DESC, ls.vulnerability_count DESC
                 LIMIT 10`,
                [req.org.id]
            ),
            db.query(
                `SELECT
                   COUNT(DISTINCT a.id)  AS total_apps,
                   COUNT(DISTINCT c.id)  AS unique_components,
                   COUNT(DISTINCT v.id)  AS total_vulnerabilities,
                   SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical,
                   SUM(CASE WHEN v.severity = 'HIGH'     THEN 1 ELSE 0 END) AS high
                 FROM applications a
                 LEFT JOIN app_latest_sboms ls  ON ls.app_id = a.id
                 LEFT JOIN sbom_components sc   ON sc.sbom_id = ls.sbom_id
                 LEFT JOIN components c         ON c.id = sc.component_id
                 LEFT JOIN vulnerabilities v    ON v.component_id = c.id
                 WHERE a.org_id = $1`,
                [req.org.id]
            ),
        ]);

        res.json({
            summary: summary.rows[0],
            topVulnerabilities: topVulns.rows,
            mostExposedApps: topApps.rows,
        });
    } catch (err) {
        console.error('[report]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ── SBOM diff ─────────────────────────────────────────────────────────────────
// GET /api/v1/apps/:name/diff
// Compare the two most-recent SBOMs for an app.
// Optional ?from=<sbom_id>&to=<sbom_id> to compare specific pairs.
app.get('/api/v1/apps/:name/diff', requireScope('sbom:read'), async (req, res) => {
    try {
        // Resolve app
        const appRes = await db.query(
            `SELECT id FROM applications WHERE org_id = $1 AND name = $2`,
            [req.org.id, req.params.name]
        );
        if (!appRes.rows.length) return res.status(404).json({ error: 'App not found' });
        const appId = appRes.rows[0].id;

        // Resolve the two SBOM IDs
        let fromId = req.query.from;
        let toId   = req.query.to;

        if (!fromId || !toId) {
            const recent = await db.query(
                `SELECT id, version, created_at
                 FROM sboms WHERE app_id = $1 ORDER BY created_at DESC LIMIT 2`,
                [appId]
            );
            if (recent.rows.length < 2) {
                return res.status(409).json({ error: 'Need at least two SBOMs to diff' });
            }
            toId   = toId   || recent.rows[0].id;
            fromId = fromId || recent.rows[1].id;
        }

        // Fetch component lists for each SBOM
        const compQuery = `
            SELECT c.purl, c.name, c.version, c.ecosystem
            FROM sbom_components sc
            JOIN components c ON c.id = sc.component_id
            WHERE sc.sbom_id = $1`;

        const vulnQuery = `
            SELECT v.osv_id, v.cve_id, v.severity, c.purl AS component_purl, c.name AS component_name
            FROM vulnerabilities v
            JOIN components c       ON c.id = v.component_id
            JOIN sbom_components sc ON sc.component_id = c.id
            WHERE sc.sbom_id = $1 AND v.org_id = $2`;

        const [fromComps, toComps, fromVulns, toVulns, fromMeta, toMeta] = await Promise.all([
            db.query(compQuery, [fromId]),
            db.query(compQuery, [toId]),
            db.query(vulnQuery, [fromId, req.org.id]),
            db.query(vulnQuery, [toId,   req.org.id]),
            db.query(`SELECT id, version, created_at FROM sboms WHERE id = $1`, [fromId]),
            db.query(`SELECT id, version, created_at FROM sboms WHERE id = $1`, [toId]),
        ]);

        const compDiff = diffComponents(fromComps.rows, toComps.rows);
        const vulnDiff = diffVulns(fromVulns.rows, toVulns.rows);

        res.json({
            from:    fromMeta.rows[0],
            to:      toMeta.rows[0],
            summary: {
                ...compDiff.summary,
                newVulnerabilities:      vulnDiff.introduced.length,
                resolvedVulnerabilities: vulnDiff.resolved.length,
            },
            added:                   compDiff.added,
            removed:                 compDiff.removed,
            updated:                 compDiff.updated,
            newVulnerabilities:      vulnDiff.introduced,
            resolvedVulnerabilities: vulnDiff.resolved,
        });
    } catch (err) {
        console.error('[diff]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ── AI explain ───────────────────────────────────────────────────────────────
// POST /api/v1/apps/:name/explain
// Returns an AI-generated vulnerability summary and remediation plan.
// Requires DEEPSEEK_API_KEY to be set on the server.
app.post('/api/v1/apps/:name/explain', requireScope('sbom:read'), async (req, res) => {
    if (!process.env.DEEPSEEK_API_KEY) {
        return res.status(501).json({ error: 'AI explain is not configured on this server (DEEPSEEK_API_KEY not set)' });
    }
    try {
        const appRes = await db.query(
            `SELECT id FROM applications WHERE org_id = $1 AND name = $2`,
            [req.org.id, req.params.name]
        );
        if (!appRes.rows.length) return res.status(404).json({ error: 'App not found' });
        const appId = appRes.rows[0].id;

        // Fetch vulns from latest SBOM via app_latest_sboms
        const { rows: vulnRows } = await db.query(
            `SELECT c.name, c.version, c.ecosystem,
                    v.osv_id, v.cve_id, v.severity, v.cvss_score, v.fixed_version, v.title, v.kev
             FROM app_latest_sboms ls
             JOIN sbom_components sc ON sc.sbom_id = ls.sbom_id
             JOIN components c       ON c.id = sc.component_id
             JOIN vulnerabilities v  ON v.component_id = c.id AND v.org_id = $1
             LEFT JOIN vex_statements vx
                    ON vx.component_id = c.id AND vx.osv_id = v.osv_id AND vx.org_id = $1
             WHERE ls.app_id = $2 AND (vx.status IS NULL OR vx.status != 'not_affected')
             ORDER BY v.severity DESC NULLS LAST`,
            [req.org.id, appId]
        );

        if (!vulnRows.length) {
            return res.json({ explanation: 'No active vulnerabilities found for this app.' });
        }

        const explanation = await explainVulnRows(vulnRows, req.params.name);
        res.json({ explanation, vulnerabilityCount: vulnRows.length });
    } catch (err) {
        console.error('[explain]', err.message);
        res.status(500).json({ error: 'Explain failed' });
    }
});

// ── VEX statements ────────────────────────────────────────────────────────────
const VEX_STATUSES      = new Set(['not_affected', 'affected', 'fixed', 'under_investigation']);
const VEX_JUSTIFICATIONS = new Set([
    'component_not_present', 'vulnerable_code_not_present',
    'vulnerable_code_not_in_execute_path',
    'vulnerable_code_cannot_be_controlled_by_adversary',
    'inline_mitigations_already_exist',
]);

// POST /api/v1/vex  — create or update a VEX statement
app.post('/api/v1/vex', requireScope('sbom:ingest'), async (req, res) => {
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
        // Verify the component belongs to this org
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

// GET /api/v1/vex  — list VEX statements for the org
app.get('/api/v1/vex', requireScope('sbom:read'), async (req, res) => {
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

// DELETE /api/v1/vex/:id  — revoke a VEX statement
app.delete('/api/v1/vex/:id', requireScope('sbom:ingest'), async (req, res) => {
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

// ── Key management ────────────────────────────────────────────────────────────
// POST /api/v1/keys
// Create a scoped API key for the authenticated org. Requires org:admin.
// Body: { name, scopes }  — scopes defaults to ["sbom:ingest","sbom:read"]
app.post('/api/v1/keys', requireScope('org:admin'), async (req, res) => {
    const VALID_SCOPES = new Set(['sbom:ingest', 'sbom:read', 'org:admin']);
    const rawName = req.body.name;
    const name    = (typeof rawName === 'string' && rawName.trim()) ? rawName.trim() : 'default';
    const scopes  = req.body.scopes ?? ['sbom:ingest', 'sbom:read'];

    if (rawName !== undefined && (typeof rawName !== 'string' || rawName.length > 100)) {
        return res.status(400).json({ error: 'name must be a string ≤ 100 characters' });
    }
    if (!Array.isArray(scopes) || scopes.length === 0 || !scopes.every(s => VALID_SCOPES.has(s))) {
        return res.status(400).json({
            error: 'Invalid scopes',
            valid: [...VALID_SCOPES],
        });
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
        // Plaintext key shown once — caller must store it securely.
        res.status(201).json({ ...rows[0], api_key: apiKey });
    } catch (err) {
        console.error('[keys/create]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/v1/keys  — list all active keys for the org (no plaintext)
app.get('/api/v1/keys', requireScope('org:admin'), async (req, res) => {
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

// DELETE /api/v1/keys/:id  — revoke a key
app.delete('/api/v1/keys/:id', requireScope('org:admin'), async (req, res) => {
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

// ── Repository scanning ───────────────────────────────────────────────────────
// POST /api/v1/scan  body: { repo, ref?, token? }
// Queues an async server-side scan. Returns { jobId } for polling.
app.post('/api/v1/scan', scanLimiter, requireScope('sbom:ingest'), async (req, res) => {
    const { repo, ref, token } = req.body;

    if (!repo || typeof repo !== 'string' || !repo.trim()) {
        return res.status(400).json({ error: 'repo is required (e.g. "owner/repo")' });
    }
    const cleanRepo = repo.trim();
    const cleanRef  = (ref && typeof ref === 'string' && ref.trim()) ? ref.trim() : null;

    if (!parseGitHubTarget(cleanRepo)) {
        return res.status(400).json({ error: 'Invalid repo format. Use owner/repo or owner/repo@branch.' });
    }
    if (token !== undefined && typeof token !== 'string') {
        return res.status(400).json({ error: 'token must be a string' });
    }

    const active = activeScanCounts.get(req.org.id) || 0;
    if (active >= 2) {
        return res.status(429).json({ error: 'You already have active scans running. Wait for them to complete.' });
    }

    try {
        const { rows } = await db.query(
            `INSERT INTO scan_jobs (org_id, repo, ref) VALUES ($1, $2, $3) RETURNING id`,
            [req.org.id, cleanRepo, cleanRef]
        );
        const jobId = rows[0].id;
        activeScanCounts.set(req.org.id, active + 1);
        runScanJob(jobId, req.org.id, cleanRepo, cleanRef, token || null);
        res.status(202).json({ jobId });
    } catch (err) {
        console.error('[scan/create]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/v1/scan  — list recent scan jobs for the org
app.get('/api/v1/scan', requireScope('sbom:read'), async (req, res) => {
    try {
        const { rows } = await db.query(
            `SELECT id, repo, ref, status, error, app_name, created_at, updated_at
             FROM scan_jobs WHERE org_id = $1 ORDER BY created_at DESC LIMIT 20`,
            [req.org.id]
        );
        res.json({ jobs: rows });
    } catch (err) {
        console.error('[scan/list]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/v1/scan/:jobId  — poll a single scan job
app.get('/api/v1/scan/:jobId', requireScope('sbom:read'), async (req, res) => {
    try {
        const { rows } = await db.query(
            `SELECT j.id, j.repo, j.ref, j.status, j.error, j.app_name, j.sbom_id,
                    j.created_at, j.updated_at,
                    s.ai_models, s.ai_threats, s.ai_critical, s.least_agency_score
             FROM scan_jobs j
             LEFT JOIN sboms s ON s.id = j.sbom_id
             WHERE j.id = $1 AND j.org_id = $2`,
            [req.params.jobId, req.org.id]
        );
        if (!rows.length) return res.status(404).json({ error: 'Job not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('[scan/get]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ── Billing ───────────────────────────────────────────────────────────────────

// GET /api/v1/billing  — current plan info
app.get('/api/v1/billing', requireScope('org:admin'), async (req, res) => {
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

// GET /api/v1/billing/prices  — returns price IDs the client needs for checkout
// Safe to expose: price IDs are not secrets.
app.get('/api/v1/billing/prices', (_req, res) => {
    res.json({
        starter_monthly:  process.env.STRIPE_PRICE_STARTER_MONTHLY  || null,
        starter_annual:   process.env.STRIPE_PRICE_STARTER_ANNUAL   || null,
        team_monthly:     process.env.STRIPE_PRICE_TEAM_MONTHLY     || null,
        team_annual:      process.env.STRIPE_PRICE_TEAM_ANNUAL      || null,
        business_monthly: process.env.STRIPE_PRICE_BUSINESS_MONTHLY || null,
        business_annual:  process.env.STRIPE_PRICE_BUSINESS_ANNUAL  || null,
    });
});

// POST /api/v1/billing/checkout  body: { priceId }
// Creates a Stripe Checkout session and returns { url }.
app.post('/api/v1/billing/checkout', requireScope('org:admin'), async (req, res) => {
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
        const org       = rows[0];
        const appUrl    = process.env.APP_URL || 'https://api.packrai.xyz';

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

// POST /api/v1/billing/portal  — Stripe customer portal session
app.post('/api/v1/billing/portal', requireScope('org:admin'), async (req, res) => {
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

        const appUrl = process.env.APP_URL || 'https://api.packrai.xyz';
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

// ── Account deletion ──────────────────────────────────────────────────────────
// DELETE /api/v1/account  body: { confirm: "delete my account" }
// Permanently deletes the org and all associated data via FK cascade.
app.delete('/api/v1/account', requireScope('org:admin'), async (req, res) => {
    if (req.body.confirm !== 'delete my account') {
        return res.status(400).json({
            error: 'Set confirm to "delete my account" to proceed',
        });
    }
    try {
        await db.query('DELETE FROM organizations WHERE id = $1', [req.org.id]);
        res.status(204).end();
    } catch (err) {
        console.error('[account/delete]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ── Org provisioning (admin key only) ────────────────────────────────────────
// POST /api/v1/orgs   body: { name }
// Disabled by default. Set ENABLE_ADMIN_API=true to activate.
// Never expose on the public internet without IP allowlisting.
app.post('/api/v1/orgs', async (req, res) => {
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
        // Return plaintext key once — caller must store it.
        res.status(201).json({ ...rows[0], api_key: apiKey });
    } catch (err) {
        console.error('[orgs]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3080;
app.listen(PORT, () => {
    process.stdout.write(`PackrAI API listening on :${PORT}\n`);
    if (process.env.KATZILLA_API_KEY) startKEVRefresh();
});

module.exports = app;
