'use strict';

const express = require('express');
const path    = require('path');

const router  = express.Router();
const PAGES   = path.join(__dirname, '..');

router.get('/',        (_req, res) => res.redirect('/register'));
router.get('/dashboard', (_req, res) => res.sendFile(path.join(PAGES, 'dashboard.html')));
router.get('/register',  (_req, res) => res.sendFile(path.join(PAGES, 'register.html')));
router.get('/terms',     (_req, res) => res.sendFile(path.join(PAGES, 'terms.html')));
router.get('/privacy',   (_req, res) => res.sendFile(path.join(PAGES, 'privacy.html')));
router.get('/docs', (_req, res) => {
    res.setHeader('Content-Security-Policy',
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.com; style-src 'self' 'unsafe-inline' https://unpkg.com; connect-src 'self'; img-src 'self' data:; font-src 'self' https://unpkg.com; object-src 'none'; frame-src 'none';"
    );
    res.sendFile(path.join(PAGES, 'docs.html'));
});
router.get('/pricing',   (_req, res) => res.sendFile(path.join(PAGES, 'pricing.html')));
router.get('/health',    (_req, res) => res.json({ ok: true }));

router.get('/recover', (_req, res) => {
    res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Recover API Key — SBOMix</title>
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

module.exports = router;
