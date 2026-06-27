'use strict';

function esc(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

const crypto  = require('crypto');
const express = require('express');
const db      = require('../db');
const { sendEmail }                         = require('../services/emailService');
const { hashApiKey, generateApiKey }        = require('../middleware/auth');
const { registerLimiter, resendKeyLimiter } = require('../middleware/rateLimits');
const orgsRepo = require('../repositories/orgsRepo');
const keysRepo = require('../repositories/keysRepo');

const router = express.Router();

router.get('/verify', async (req, res) => {
    const { token } = req.query;

    const page = (title, body) =>
        `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${title} — SBOMix</title>` +
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
        const verification = await orgsRepo.findEmailVerification(db, token);
        if (!verification) {
            return res.status(410).send(page('Link expired',
                '<h1>Link expired</h1><p>This verification link has expired or already been used.</p>' +
                '<p><a href="/register">Register again →</a></p>'));
        }

        const { email, org_name } = verification;

        const existing = await orgsRepo.findByEmail(db, email);
        if (existing) {
            await orgsRepo.deleteEmailVerification(db, token);
            return res.send(page('Already verified',
                '<h1>Already verified</h1><p>This email was already verified. Check your inbox for your API key, or ' +
                '<a href="/recover">request a new key</a>.</p><br><a href="/dashboard" class="btn">Go to dashboard</a>'));
        }

        const apiKey  = generateApiKey();
        const keyHash = hashApiKey(apiKey);
        await db.tx(async (client) => {
            await orgsRepo.createOrg(client, org_name, email, keyHash);
            await orgsRepo.deleteEmailVerification(client, token);
        });

        await sendEmail({
            to: email,
            subject: 'Your SBOMix API Key',
            html: `
<!DOCTYPE html><html><body style="background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:40px;max-width:560px;margin:0 auto">
<h1 style="font-size:22px;font-weight:700;margin-bottom:6px">Welcome to <span style="color:#3fb950">SBOMix</span></h1>
<p style="color:#8b949e;margin-bottom:28px">Your org <strong style="color:#e6edf3">${esc(org_name)}</strong> is ready.</p>
<p style="margin-bottom:10px;font-weight:600">Your API key</p>
<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;font-family:monospace;font-size:13px;word-break:break-all;color:#3fb950;margin-bottom:6px">${apiKey}</div>
<p style="color:#8b949e;font-size:12px;margin-bottom:28px">⚠ Save this key — it won't be shown again.</p>
<h2 style="font-size:15px;font-weight:600;margin-bottom:12px">Quick start</h2>
<pre style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;font-size:12px;overflow-x:auto;color:#e6edf3">npm install -g sbomix
# Scan locally and push to dashboard via GitHub Action
# See: https://api.sbomix.com/docs#scan-modes

# Or scan manually:
npx sbomix owner/repo
# then view results at https://api.sbomix.com/dashboard</pre>
<p style="margin-top:28px;color:#8b949e;font-size:13px">Need help? Reply to this email or visit <a href="https://sbomix.com" style="color:#58a6ff">sbomix.com</a>.</p>
</body></html>`,
        });

        return res.send(page('Email verified',
            `<h1 style="color:#3fb950">✓ Email verified!</h1>` +
            `<p>Welcome, <strong style="color:#e6edf3">${esc(org_name)}</strong>. Your API key is below and has been emailed to <strong style="color:#e6edf3">${esc(email)}</strong>.</p>` +
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

router.post('/api/v1/register', registerLimiter, async (req, res) => {
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
        const existing = await orgsRepo.findByEmail(db, cleanEmail);
        if (existing) {
            return res.json({ message: 'Check your email for a verification link.' });
        }

        const token     = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
        await orgsRepo.upsertEmailVerification(db, cleanEmail, cleanOrgName, token, expiresAt);

        const verifyUrl = `https://api.sbomix.com/verify?token=${token}`;
        await sendEmail({
            to: cleanEmail,
            subject: 'Verify your SBOMix email',
            html: `
<!DOCTYPE html><html><body style="background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:40px;max-width:560px;margin:0 auto">
<h1 style="font-size:22px;font-weight:700;margin-bottom:6px">Verify your <span style="color:#3fb950">SBOMix</span> email</h1>
<p style="color:#8b949e;margin-bottom:28px">One click to activate <strong style="color:#e6edf3">${esc(cleanOrgName)}</strong>. This link expires in 24 hours.</p>
<a href="${verifyUrl}" style="display:inline-block;background:#238636;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;font-size:15px;margin-bottom:28px">Verify email &amp; get API key</a>
<p style="color:#8b949e;font-size:12px;margin-bottom:4px">Or copy this URL into your browser:</p>
<div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px;font-family:monospace;font-size:11px;word-break:break-all;color:#58a6ff">${verifyUrl}</div>
<p style="margin-top:28px;color:#8b949e;font-size:12px">If you didn't sign up for SBOMix, you can safely ignore this email.</p>
</body></html>`,
        });

        res.json({ message: 'Check your email for a verification link.' });
    } catch (err) {
        console.error('[register]', err.message);
        res.status(500).json({ error: 'Registration failed — please try again' });
    }
});

router.post('/api/v1/resend-key', resendKeyLimiter, async (req, res) => {
    const { email } = req.body;

    if (!email || typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
        return res.status(400).json({ error: 'A valid email address is required' });
    }

    const cleanEmail = email.trim().toLowerCase();

    try {
        const org = await orgsRepo.findByEmail(db, cleanEmail);

        if (org) {
            const apiKey  = generateApiKey();
            const keyHash = hashApiKey(apiKey);
            await keysRepo.createKey(db, org.id, 'recovery', keyHash, ['org:admin']);

            await sendEmail({
                to: cleanEmail,
                subject: 'Your SBOMix API Key (recovery)',
                html: `
<!DOCTYPE html><html><body style="background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:40px;max-width:560px;margin:0 auto">
<h1 style="font-size:22px;font-weight:700;margin-bottom:6px"><span style="color:#3fb950">SBOMix</span> — API key recovery</h1>
<p style="color:#8b949e;margin-bottom:28px">Here is a new API key for <strong style="color:#e6edf3">${esc(org.name)}</strong>. This key has <strong>org:admin</strong> access.</p>
<p style="margin-bottom:10px;font-weight:600">New API key</p>
<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;font-family:monospace;font-size:13px;word-break:break-all;color:#3fb950;margin-bottom:6px">${apiKey}</div>
<p style="color:#8b949e;font-size:12px;margin-bottom:28px">⚠ Save this key — it won't be shown again.</p>
<p style="color:#8b949e;font-size:13px">If you didn't request this, you can ignore it — your existing keys remain active.</p>
<p style="margin-top:16px"><a href="https://api.sbomix.com/dashboard" style="color:#58a6ff">Open dashboard →</a></p>
</body></html>`,
            });
        }

        res.json({ message: 'If that email is registered, a new API key has been sent.' });
    } catch (err) {
        console.error('[resend-key]', err.message);
        res.status(500).json({ error: 'Request failed — please try again' });
    }
});

module.exports = router;
