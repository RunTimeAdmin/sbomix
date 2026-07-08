'use strict';
const API = '';
let orgScopes = [];
let currentApp = null;
let currentAppMeta = null;
let currentVulns = [];
let currentComponents = [];

// ── Helpers ───────────────────────────────────────────────────────────────────

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g,
    c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}

function timeAgo(iso) {
  if (!iso) return '—';
  const m = Math.floor((Date.now() - new Date(iso)) / 60000);
  if (m < 2)  return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function sevBadge(s) {
  if (!s) return '<span class="badge b-muted">—</span>';
  const cls = { CRITICAL:'b-red', HIGH:'b-yellow', MEDIUM:'b-muted', LOW:'b-muted' }[s] || 'b-muted';
  return `<span class="badge ${cls}">${esc(s)}</span>`;
}

function qsBadge(n) {
  if (n === null || n === undefined) return '<span class="badge b-muted">—</span>';
  const v = Math.round(n);
  const cls = v >= 80 ? 'b-green' : v >= 50 ? 'b-yellow' : 'b-red';
  return `<span class="badge ${cls}">${v}/100</span>`;
}

function ecoTags(arr) {
  if (!arr?.length) return '<span class="c-muted">—</span>';
  return arr.map(e => `<span class="eco">${esc(e)}</span>`).join('');
}

async function apiFetch(path, opts = {}) {
  const r = await fetch(API + path, {
    ...opts,
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
  });
  if (r.status === 401) { window.location.href = '/login'; return; }
  if (!r.ok) { const err = new Error(r.status); err.status = r.status; throw err; }
  return r.json();
}

// ── Navigation ────────────────────────────────────────────────────────────────

function showScreen(id) {
  for (const s of ['list-screen', 'detail-screen']) {
    const el = document.getElementById(s);
    if (!el) continue;
    el.style.display = s === id ? 'block' : 'none';
  }
}

function showList() {
  currentApp = null;
  showScreen('list-screen');
}

function logout() {  document.getElementById('logout-btn').style.display = 'none';  showScreen('auth-screen');
}

// ── Dashboard (list view) ─────────────────────────────────────────────────────

async function loadDashboard() {
  showScreen('list-screen');
  document.getElementById('logout-btn').style.display = 'block';

  // Fetch me, apps, and report concurrently
  const [meRes, appsRes, reportRes] = await Promise.allSettled([
    apiFetch('/api/v1/me'),
    apiFetch('/api/v1/apps'),
    apiFetch('/api/v1/report'),
  ]);

  if (meRes.status === 'fulfilled') {
    orgScopes = meRes.value.scopes || [];
    const isAdmin   = orgScopes.includes('org:admin');
    const canIngest = isAdmin || orgScopes.includes('sbom:ingest');
    document.getElementById('keys-section').style.display  = isAdmin   ? 'block' : 'none';
    document.getElementById('scan-section').style.display  = canIngest ? 'block' : 'none';
    if (isAdmin) {
      loadKeys();
      loadBilling();
      document.getElementById('alerts-toggle').checked = meRes.value.vuln_alerts !== false;
    }
    if (canIngest) loadScanJobs();
  }

  // Show upgrade success banner if redirected from Stripe
  if (new URLSearchParams(window.location.search).get('upgraded') === '1') {
    const banner = document.createElement('div');
    banner.style.cssText = 'position:fixed;top:16px;left:50%;transform:translateX(-50%);z-index:9999;background:#1f4722;border:1px solid #3fb950;color:#3fb950;padding:12px 24px;border-radius:8px;font-weight:600;font-size:14px;box-shadow:0 4px 20px rgba(0,0,0,.4)';
    banner.textContent = '✓ Plan upgraded successfully! Welcome to the next level.';
    document.body.appendChild(banner);
    setTimeout(() => banner.remove(), 6000);
    history.replaceState({}, '', '/dashboard');
  }

  // Summary cards + apps table — delegated to shared helpers (also used by scan poll)
  if (reportRes.status === 'fulfilled') renderSummaryCards(reportRes.value.summary);
  if (appsRes.status === 'fulfilled') {
    renderAppsList(appsRes.value.apps);
  } else {
    document.getElementById('apps-wrap').innerHTML = '<div class="empty">Failed to load applications.</div>';
  }

  // Top vulnerabilities table
  const topEl = document.getElementById('top-vulns-wrap');
  if (reportRes.status === 'fulfilled') {
    const vulns = reportRes.value.topVulnerabilities;
    if (!vulns.length) {
      topEl.innerHTML = `<div class="empty c-green">✓ No critical or high vulnerabilities across your org.</div>`;
    } else {
      topEl.innerHTML = `
        <div class="table-wrap"><table>
          <thead><tr>
            <th>CVE / OSV ID</th><th>Severity</th><th>CVSS</th><th>Apps affected</th><th>Title</th>
          </tr></thead>
          <tbody>${vulns.map(v => `
            <tr>
              <td class="mono">
                <a href="https://osv.dev/vulnerability/${esc(v.osv_id)}" target="_blank" rel="noopener"
                   style="color:var(--blue);text-decoration:none">${esc(v.cve_id || v.osv_id)}</a>
                ${v.kev ? ' <span class="badge b-kev" title="CISA Known Exploited Vulnerability">KEV</span>' : ''}
              </td>
              <td>${sevBadge(v.severity)}</td>
              <td class="c-muted">${v.cvss_score ?? '—'}</td>
              <td>${v.apps_affected}</td>
              <td class="c-muted" style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(v.title || '')}</td>
            </tr>`).join('')}
          </tbody>
        </table></div>`;
    }
  }
}

// ── App detail ────────────────────────────────────────────────────────────────

async function showDetail(appName) {
  currentApp = appName;
  showScreen('detail-screen');

  // Reset
  document.getElementById('d-name').textContent = appName;
  document.getElementById('d-meta').innerHTML = '';
  document.getElementById('dc-comps').textContent = '—';
  document.getElementById('dc-vulns').textContent = '—';
  document.getElementById('dc-crit').textContent  = '—';
  document.getElementById('dc-kev').textContent   = '—';
  document.getElementById('detail-vulns-wrap').innerHTML =
    '<div class="loading"><span class="spinner"></span>Loading…</div>';
  document.getElementById('detail-comps-wrap').innerHTML =
    '<div class="loading"><span class="spinner"></span>Loading…</div>';
  // reset tabs to vulnerabilities
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === 'vulns'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === 'tab-vulns'));
  document.getElementById('diff-section').style.display = 'none';
  document.getElementById('diff-wrap').innerHTML = '';
  const ep = document.getElementById('explain-panel');
  ep.classList.remove('open');
  ep.innerHTML = '';
  document.getElementById('explain-btn').textContent = 'AI Explain';
  document.getElementById('explain-btn').disabled = false;

  const [sbomRes, vulnsRes] = await Promise.allSettled([
    apiFetch(`/api/v1/apps/${encodeURIComponent(appName)}/sbom`),
    apiFetch(`/api/v1/apps/${encodeURIComponent(appName)}/vulns`),
  ]);

  // Header metadata
  if (sbomRes.status === 'fulfilled') {
    const s = sbomRes.value;
    currentAppMeta = s;
    const parts = [];
    if (s.branch)    parts.push(`<span class="detail-meta-item">⎇ ${esc(s.branch)}</span>`);
    if (s.commit_sha) parts.push(`<span class="mono" style="font-size:12px">${esc(s.commit_sha.slice(0,7))}</span>`);
    if (s.version && s.version !== 'unknown') parts.push(`<span>v${esc(s.version)}</span>`);
    parts.push(`<span>Scanned ${timeAgo(s.created_at)}</span>`);
    parts.push(`<span>Quality ${qsBadge(s.quality_score)}</span>`);
    if (s.ecosystems?.length) parts.push(`<span>${ecoTags(s.ecosystems)}</span>`);
    document.getElementById('d-meta').innerHTML = parts.join('');

    const comps = document.getElementById('dc-comps');
    comps.textContent = s.component_count ?? '—';

    const crit = document.getElementById('dc-crit');
    crit.textContent = s.critical_count ?? '0';
    crit.className = `dc-value ${Number(s.critical_count) > 0 ? 'c-red' : 'c-green'}`;
  }

  // Vulnerability table
  const vulnsEl = document.getElementById('detail-vulns-wrap');
  if (vulnsRes.status === 'fulfilled') {
    const vulns = vulnsRes.value.vulnerabilities;
    currentVulns = vulns;
    const kevCount = vulns.filter(v => v.kev).length;

    const dvEl = document.getElementById('dc-vulns');
    dvEl.textContent = vulns.length;
    dvEl.className   = `dc-value ${vulns.length > 0 ? 'c-yellow' : 'c-green'}`;

    const dkEl = document.getElementById('dc-kev');
    dkEl.textContent = kevCount;
    dkEl.className   = `dc-value ${kevCount > 0 ? 'c-red' : 'c-green'}`;

    if (!vulns.length) {
      vulnsEl.innerHTML =
        '<div class="empty c-green">✓ No active vulnerabilities for this app.</div>';
    } else {
      vulnsEl.innerHTML = `
        <div class="table-wrap"><table>
          <thead><tr>
            <th>CVE / OSV ID</th><th>Severity</th><th>CVSS</th>
            <th>Component</th><th>Version</th><th>Fix available</th>
          </tr></thead>
          <tbody>${vulns.map(v => `
            <tr>
              <td class="mono">
                <a href="https://osv.dev/vulnerability/${esc(v.osv_id)}" target="_blank" rel="noopener"
                   style="color:var(--blue);text-decoration:none">${esc(v.cve_id || v.osv_id)}</a>
                ${v.kev ? ' <span class="badge b-kev" title="CISA Known Exploited Vulnerability — actively exploited in the wild">KEV</span>' : ''}
              </td>
              <td>${sevBadge(v.severity)}</td>
              <td class="c-muted">${v.cvss_score ?? '—'}</td>
              <td class="mono">${esc(v.component)}</td>
              <td class="mono c-muted">${esc(v.component_version)}</td>
              <td class="mono ${v.fixed_version ? 'c-green' : 'c-muted'}">${esc(v.fixed_version || 'No fix')}</td>
            </tr>`).join('')}
          </tbody>
        </table></div>`;
    }
  } else {
    vulnsEl.innerHTML = '<div class="empty">Failed to load vulnerabilities.</div>';
  }

  // Components and diff (non-blocking)
  loadComponents(appName);
  loadDiff(appName);
}

// ── Components ────────────────────────────────────────────────────────────────

async function loadComponents(appName) {
  const el = document.getElementById('detail-comps-wrap');
  try {
    const data = await apiFetch(`/api/v1/apps/${encodeURIComponent(appName)}/components`);
    const comps = data.components;
    currentComponents = comps;
    if (!comps.length) {
      el.innerHTML = '<div class="empty">No components found.</div>';
      return;
    }
    el.innerHTML = `
      <div class="table-wrap"><table>
        <thead><tr>
          <th>Component</th><th>Version</th><th>Ecosystem</th><th>Vulns</th><th>PURL</th>
        </tr></thead>
        <tbody>${comps.map(c => `
          <tr>
            <td class="mono">${esc(c.name)}</td>
            <td class="mono c-muted">${esc(c.version)}</td>
            <td><span class="eco">${esc(c.ecosystem)}</span></td>
            <td>${Number(c.vuln_count) > 0
                  ? `<span class="badge ${c.max_severity === 'CRITICAL' ? 'b-red' : 'b-yellow'}">${c.vuln_count}</span>`
                  : '<span class="c-green">0</span>'}</td>
            <td class="mono c-muted" style="font-size:11px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(c.purl)}">${esc(c.purl || '—')}</td>
          </tr>`).join('')}
        </tbody>
      </table></div>`;
  } catch {
    el.innerHTML = '<div class="empty">Failed to load components.</div>';
  }
}

// ── SBOM Diff ─────────────────────────────────────────────────────────────────

async function loadDiff(appName) {
  try {
    const diff = await apiFetch(`/api/v1/apps/${encodeURIComponent(appName)}/diff`);
    const s = diff.summary;
    const hasChanges = s.added + s.removed + s.updated +
                       s.newVulnerabilities + s.resolvedVulnerabilities > 0;

    document.getElementById('diff-section').style.display = 'block';

    const fv = diff.from.version && diff.from.version !== 'unknown'
      ? `v${diff.from.version}` : timeAgo(diff.from.created_at);
    const tv = diff.to.version && diff.to.version !== 'unknown'
      ? `v${diff.to.version}` : timeAgo(diff.to.created_at);

    let html = `<div class="diff-box">
      <div class="diff-versions">${esc(fv)} <span class="c-muted">→</span> ${esc(tv)}</div>`;

    if (!hasChanges) {
      html += `<div class="c-green" style="font-size:13px">✓ No changes between the last two scans.</div>`;
    } else {
      html += `<div class="diff-summary">`;
      if (s.added)   html += `<span><span class="diff-stat-added">+${s.added}</span> added</span>`;
      if (s.removed) html += `<span><span class="diff-stat-removed">−${s.removed}</span> removed</span>`;
      if (s.updated) html += `<span><span class="diff-stat-changed">~${s.updated}</span> updated</span>`;
      if (s.newVulnerabilities)
        html += `<span><span class="diff-stat-removed">+${s.newVulnerabilities}</span> new vuln${s.newVulnerabilities !== 1 ? 's' : ''}</span>`;
      if (s.resolvedVulnerabilities)
        html += `<span><span class="diff-stat-added">−${s.resolvedVulnerabilities}</span> resolved</span>`;
      html += `</div>`;

      if (diff.newVulnerabilities?.length) {
        html += `<div class="diff-list-title">New vulnerabilities introduced</div>
          <div class="diff-list">`;
        for (const v of diff.newVulnerabilities) {
          html += `<div class="diff-row">
            <span class="mono c-red">${esc(v.cve_id || v.osv_id)}</span>
            ${sevBadge(v.severity)}
            <span class="mono c-muted">${esc(v.component_name)}</span>
          </div>`;
        }
        html += `</div>`;
      }

      if (diff.added?.length) {
        html += `<div class="diff-list-title">Components added</div>
          <div class="diff-list">`;
        for (const c of diff.added.slice(0, 20)) {
          html += `<div class="diff-row">
            <span class="diff-stat-added">+</span>
            <span class="mono">${esc(c.name)}</span>
            <span class="mono c-muted">${esc(c.version)}</span>
            <span class="eco">${esc(c.ecosystem)}</span>
          </div>`;
        }
        if (diff.added.length > 20)
          html += `<div class="diff-row c-muted">…and ${diff.added.length - 20} more</div>`;
        html += `</div>`;
      }

      if (diff.removed?.length) {
        html += `<div class="diff-list-title">Components removed</div>
          <div class="diff-list">`;
        for (const c of diff.removed.slice(0, 20)) {
          html += `<div class="diff-row">
            <span class="diff-stat-removed">−</span>
            <span class="mono">${esc(c.name)}</span>
            <span class="mono c-muted">${esc(c.version)}</span>
          </div>`;
        }
        if (diff.removed.length > 20)
          html += `<div class="diff-row c-muted">…and ${diff.removed.length - 20} more</div>`;
        html += `</div>`;
      }
    }

    html += `</div>`;
    document.getElementById('diff-wrap').innerHTML = html;
  } catch (err) {
    // 409 = fewer than 2 SBOMs — expected, stay hidden
    if (err.status !== 409) {
      document.getElementById('diff-section').style.display = 'block';
      document.getElementById('diff-wrap').innerHTML =
        `<div class="diff-box c-muted" style="font-size:13px">SBOM diff unavailable.</div>`;
    }
  }
}

// ── AI Explain ────────────────────────────────────────────────────────────────

document.getElementById('explain-btn').addEventListener('click', async () => {
  const btn   = document.getElementById('explain-btn');
  const panel = document.getElementById('explain-panel');

  if (panel.classList.contains('open')) {
    panel.classList.remove('open');
    btn.textContent = 'AI Explain';
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Asking AI…';
  panel.classList.add('open');
  panel.innerHTML = '<span class="spinner"></span> Generating remediation advice…';

  try {
    const data = await apiFetch(
      `/api/v1/apps/${encodeURIComponent(currentApp)}/explain`,
      { method: 'POST' }
    );
    if (data.explanation === 'No active vulnerabilities found for this app.') {
      panel.innerHTML = `<span class="c-green">✓ No active vulnerabilities — nothing to explain.</span>`;
    } else {
      panel.innerHTML = `
        <div class="explain-label">
          AI Remediation Advice &nbsp;·&nbsp;
          ${data.vulnerabilityCount} vuln${data.vulnerabilityCount !== 1 ? 's' : ''} analysed &nbsp;·&nbsp;
          Claude Haiku
        </div>
        <pre>${esc(data.explanation)}</pre>`;
    }
    btn.textContent = 'Hide advice';
  } catch {
    panel.innerHTML = `<span class="c-red">AI explain failed — check that EXPLAIN_API_KEY is configured on the server.</span>`;
    panel.classList.remove('open');
    btn.textContent = 'AI Explain';
  }
  btn.disabled = false;
});

// ── CVE search ────────────────────────────────────────────────────────────────

async function runCVESearch() {
  const q  = document.getElementById('cve-input').value.trim();
  const el = document.getElementById('cve-results');
  if (!q) return;
  el.innerHTML = '<div class="loading"><span class="spinner"></span>Searching…</div>';
  try {
    const data = await apiFetch(`/api/v1/search?cve=${encodeURIComponent(q)}`);
    if (!data.results.length) {
      el.innerHTML = `<div class="empty c-green">✓ No apps exposed to <strong>${esc(q)}</strong></div>`;
      return;
    }
    el.innerHTML = `
      <div style="margin-bottom:10px;color:var(--muted)">
        ${data.exposedApps} app${data.exposedApps !== 1 ? 's' : ''} exposed to
        <strong style="color:var(--text)">${esc(q)}</strong>
      </div>
      <div class="table-wrap"><table>
        <thead><tr>
          <th>App</th><th>Component</th><th>Version</th><th>Severity</th><th>Fix</th><th>VEX</th>
        </tr></thead>
        <tbody>${data.results.map(r => `
          <tr>
            <td><span class="app-link" data-goto="${esc(r.app)}">${esc(r.app)}</span></td>
            <td class="mono">${esc(r.component)}</td>
            <td class="mono c-muted">${esc(r.component_version)}</td>
            <td>${sevBadge(r.severity)}</td>
            <td class="mono ${r.fixed_version ? 'c-green' : 'c-muted'}">${esc(r.fixed_version || 'No fix')}</td>
            <td>${r.vex_status ? `<span class="badge b-blue">${esc(r.vex_status)}</span>` : '—'}</td>
          </tr>`).join('')}
        </tbody>
      </table></div>`;
  } catch {
    el.innerHTML = '<div class="empty">Search failed.</div>';
  }
}

document.getElementById('cve-btn').addEventListener('click', runCVESearch);
document.getElementById('cve-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') runCVESearch();
});

// ── Key management ────────────────────────────────────────────────────────────

async function loadKeys() {
  const el = document.getElementById('keys-wrap');
  try {
    const data = await apiFetch('/api/v1/keys');
    const keys = data.keys;
    if (!keys.length) {
      el.innerHTML = '<div class="empty c-muted">No keys yet. Create one above.</div>';
      return;
    }
    el.innerHTML = `
      <div class="table-wrap"><table>
        <thead><tr>
          <th>Name</th><th>Scopes</th><th>Created</th><th>Last used</th><th></th>
        </tr></thead>
        <tbody>${keys.map(k => `
          <tr>
            <td class="mono">${esc(k.name)}</td>
            <td>${(k.scopes || []).map(s => `<span class="eco">${esc(s)}</span>`).join(' ')}</td>
            <td class="c-muted">${timeAgo(k.created_at)}</td>
            <td class="c-muted">${k.last_used_at ? timeAgo(k.last_used_at) : 'Never'}</td>
            <td><button class="btn-sm" style="border-color:var(--red);color:var(--red)" data-revoke="${esc(k.id)}">Revoke</button></td>
          </tr>`).join('')}
        </tbody>
      </table></div>`;
  } catch {
    el.innerHTML = '<div class="empty">Failed to load keys.</div>';
  }
}

// New key form toggle
document.getElementById('new-key-btn').addEventListener('click', () => {
  const form = document.getElementById('new-key-form');
  const showing = form.style.display !== 'none';
  form.style.display = showing ? 'none' : 'block';
  document.getElementById('new-key-result').style.display = 'none';
  document.getElementById('new-key-name').value = '';
});
document.getElementById('cancel-key-btn').addEventListener('click', () => {
  document.getElementById('new-key-form').style.display = 'none';
});

// Create key
document.getElementById('create-key-btn').addEventListener('click', async () => {
  const name = document.getElementById('new-key-name').value.trim();
  if (!name) { document.getElementById('new-key-name').focus(); return; }

  const scopes = [];
  if (document.getElementById('scope-ingest').checked) scopes.push('sbom:ingest');
  if (document.getElementById('scope-read').checked)   scopes.push('sbom:read');
  if (document.getElementById('scope-admin').checked)  scopes.push('org:admin');
  if (!scopes.length) { alert('Select at least one scope.'); return; }

  const btn = document.getElementById('create-key-btn');
  btn.disabled = true;
  btn.textContent = 'Creating…';

  try {
    const data = await apiFetch('/api/v1/keys', {
      method: 'POST',
      body: JSON.stringify({ name, scopes }),
    });
    document.getElementById('new-key-value').textContent = data.api_key;
    document.getElementById('new-key-result').style.display = 'block';
    loadKeys();
  } catch {
    alert('Failed to create key.');
  }
  btn.disabled = false;
  btn.textContent = 'Create';
});

// Copy newly created key
document.getElementById('copy-key-btn').addEventListener('click', () => {
  const val = document.getElementById('new-key-value').textContent;
  navigator.clipboard.writeText(val).then(() => {
    const btn = document.getElementById('copy-key-btn');
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
  });
});

// Revoke key — event delegation on keys-wrap
document.getElementById('keys-wrap').addEventListener('click', async e => {
  const btn = e.target.closest('[data-revoke]');
  if (!btn) return;
  if (!confirm('Revoke this key? Any system using it will lose access immediately.')) return;
  const id = btn.dataset.revoke;
  btn.disabled = true;
  btn.textContent = 'Revoking…';
  try {
    await apiFetch(`/api/v1/keys/${id}`, { method: 'DELETE' });
    loadKeys();
  } catch {
    alert('Failed to revoke key.');
    btn.disabled = false;
    btn.textContent = 'Revoke';
  }
});

// ── Tab switching ─────────────────────────────────────────────────────────────

document.addEventListener('click', e => {
  const tab = e.target.closest('.tab');
  if (!tab) return;
  const target = tab.dataset.tab;
  if (!target) return;
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === target));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === `tab-${target}`));
});

// ── Event delegation for app navigation ──────────────────────────────────────

document.addEventListener('click', e => {
  const el = e.target.closest('[data-goto]');
  if (el) showDetail(el.dataset.goto);
});

// ── Report generation ─────────────────────────────────────────────────────────

function buildReport() {
  const app  = currentApp || '—';
  const meta = currentAppMeta || {};
  const vulns = currentVulns;
  const comps = currentComponents;
  const now   = new Date().toLocaleString();
  const kevCount = vulns.filter(v => v.kev).length;
  const critCount = vulns.filter(v => v.severity === 'CRITICAL').length;

  const sevColor = { CRITICAL: '#f85149', HIGH: '#d29922', MEDIUM: '#8b949e', LOW: '#8b949e' };

  const vulnRows = vulns.map(v => `
    <tr>
      <td><a href="https://osv.dev/vulnerability/${esc(v.osv_id)}" style="color:#58a6ff">${esc(v.cve_id || v.osv_id)}</a>${v.kev ? ' <span style="background:#3a1010;color:#ff6b6b;border:1px solid #f85149;border-radius:3px;font-size:10px;padding:1px 5px;font-weight:700">KEV</span>' : ''}</td>
      <td><span style="background:${sevColor[v.severity] || '#8b949e'}22;color:${sevColor[v.severity] || '#8b949e'};padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600">${esc(v.severity || '—')}</span></td>
      <td>${v.cvss_score ?? '—'}</td>
      <td style="font-family:monospace;font-size:12px">${esc(v.component)}</td>
      <td style="font-family:monospace;font-size:12px;color:#8b949e">${esc(v.component_version)}</td>
      <td style="font-family:monospace;font-size:12px;color:${v.fixed_version ? '#3fb950' : '#8b949e'}">${esc(v.fixed_version || 'No fix')}</td>
    </tr>`).join('');

  const compRows = comps.map(c => `
    <tr>
      <td style="font-family:monospace;font-size:12px">${esc(c.name)}</td>
      <td style="font-family:monospace;font-size:12px;color:#8b949e">${esc(c.version)}</td>
      <td><span style="background:#58a6ff15;color:#58a6ff;border:1px solid #58a6ff30;border-radius:20px;padding:1px 8px;font-size:11px">${esc(c.ecosystem)}</span></td>
      <td style="color:${Number(c.vuln_count) > 0 ? '#d29922' : '#3fb950'}">${c.vuln_count}</td>
      <td style="font-family:monospace;font-size:11px;color:#8b949e;max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(c.purl || '—')}</td>
    </tr>`).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SBOMix Report — ${esc(app)}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0d1117; color: #e6edf3; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 14px; padding: 40px; }
  @media print {
    body { background: #fff; color: #000; padding: 20px; }
    a { color: #0066cc; }
    .no-print { display: none; }
  }
  h1  { font-size: 22px; font-weight: 700; font-family: monospace; letter-spacing: -0.3px; }
  h2  { font-size: 15px; font-weight: 600; margin: 32px 0 12px; padding-bottom: 8px; border-bottom: 1px solid #30363d; }
  .meta { color: #8b949e; font-size: 13px; margin: 6px 0 24px; display: flex; flex-wrap: wrap; gap: 16px; }
  .stats { display: flex; gap: 24px; margin-bottom: 32px; }
  .stat { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 14px 20px; min-width: 110px; }
  .stat-label { font-size: 11px; text-transform: uppercase; letter-spacing: .5px; color: #8b949e; margin-bottom: 4px; }
  .stat-value { font-size: 26px; font-weight: 700; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 8px 12px; font-size: 11px; text-transform: uppercase; letter-spacing: .4px; color: #8b949e; border-bottom: 2px solid #30363d; }
  td { padding: 9px 12px; border-bottom: 1px solid #21262d; vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  .footer { margin-top: 40px; color: #8b949e; font-size: 12px; text-align: center; padding-top: 16px; border-top: 1px solid #30363d; }
  .print-btn { background: #3fb950; color: #000; font-weight: 700; border: none; padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 13px; margin-bottom: 24px; }
</style>
</head>
<body>
<button class="print-btn no-print" onclick="window.print()">Print / Save as PDF</button>
<h1>${esc(app)}</h1>
<div class="meta">
  ${meta.branch ? `<span>⎇ ${esc(meta.branch)}</span>` : ''}
  ${meta.commit_sha ? `<span style="font-family:monospace">${esc(meta.commit_sha.slice(0,7))}</span>` : ''}
  ${meta.version && meta.version !== 'unknown' ? `<span>v${esc(meta.version)}</span>` : ''}
  <span>Generated ${now}</span>
  <span>SBOMix Security Report</span>
</div>

<div class="stats">
  <div class="stat"><div class="stat-label">Components</div><div class="stat-value">${comps.length}</div></div>
  <div class="stat"><div class="stat-label">Vulnerabilities</div><div class="stat-value" style="color:#d29922">${vulns.length}</div></div>
  <div class="stat"><div class="stat-label">Critical</div><div class="stat-value" style="color:#f85149">${critCount}</div></div>
  <div class="stat"><div class="stat-label">KEV</div><div class="stat-value" style="color:#f85149">${kevCount}</div></div>
</div>

<h2>Vulnerabilities (${vulns.length})</h2>
${vulns.length ? `<table>
  <thead><tr><th>CVE / OSV ID</th><th>Severity</th><th>CVSS</th><th>Component</th><th>Version</th><th>Fix</th></tr></thead>
  <tbody>${vulnRows}</tbody>
</table>` : '<p style="color:#3fb950">✓ No active vulnerabilities.</p>'}

<h2>Components (${comps.length})</h2>
${comps.length ? `<table>
  <thead><tr><th>Name</th><th>Version</th><th>Ecosystem</th><th>Vulns</th><th>PURL</th></tr></thead>
  <tbody>${compRows}</tbody>
</table>` : '<p style="color:#8b949e">No components found.</p>'}

<div class="footer">SBOMix · api.sbomix.com · ${esc(app)} · ${now}</div>
</body>
</html>`;
}

function downloadHTML() {
  const html = buildReport();
  const blob = new Blob([html], { type: 'text/html' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `sbomix-${currentApp}-${new Date().toISOString().slice(0,10)}.html`;
  a.click();
  URL.revokeObjectURL(a.href);
}

function printReport() {
  const html = buildReport();
  const win = window.open('', '_blank');
  win.document.write(html);
  win.document.close();
  win.addEventListener('load', () => win.print());
}

document.getElementById('export-html-btn').addEventListener('click', downloadHTML);
document.getElementById('export-pdf-btn').addEventListener('click', printReport);

// SBOM download dropdown
const sbomDlBtn  = document.getElementById('sbom-dl-btn');
const sbomDlMenu = document.getElementById('sbom-dl-menu');

sbomDlBtn.addEventListener('click', e => {
  e.stopPropagation();
  sbomDlMenu.style.display = sbomDlMenu.style.display === 'none' ? 'block' : 'none';
});

document.addEventListener('click', () => { sbomDlMenu.style.display = 'none'; });

document.querySelectorAll('.sbom-dl-item').forEach(item => {
  item.addEventListener('click', async () => {
    sbomDlMenu.style.display = 'none';
    const fmt = item.dataset.fmt;
    const url = `/api/v1/apps/${encodeURIComponent(currentApp)}/sbom/download?format=${fmt}`;
    try {
      const r = await fetch(url, { credentials: 'same-origin' });
      if (r.status === 404) {
        const err = await r.json();
        alert(err.error || 'SBOM not available in that format.');
        return;
      }
      if (!r.ok) { alert('Download failed.'); return; }
      const blob = await r.blob();
      const ext  = fmt === 'spdx' ? 'spdx.json' : 'cdx.json';
      const a    = document.createElement('a');
      a.href     = URL.createObjectURL(blob);
      a.download = `${currentApp}-sbom.${ext}`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch {
      alert('Download failed.');
    }
  });
});

// ── Agent Trust Report download ─────────────────────────────────────────────

const atrDlBtn  = document.getElementById('atr-dl-btn');
const atrDlMenu = document.getElementById('atr-dl-menu');

atrDlBtn.addEventListener('click', e => {
  e.stopPropagation();
  atrDlMenu.style.display = atrDlMenu.style.display === 'none' ? 'block' : 'none';
});

document.addEventListener('click', () => { atrDlMenu.style.display = 'none'; });

document.querySelectorAll('.atr-dl-item').forEach(item => {
  item.addEventListener('click', async () => {
    atrDlMenu.style.display = 'none';
    const fmt = item.dataset.fmt;
    const url = `/api/v1/apps/${encodeURIComponent(currentApp)}/agent-trust-report?format=${fmt}`;
    try {
      const r = await fetch(url, { credentials: 'same-origin' });
      if (r.status === 404) {
        const err = await r.json();
        alert(err.error || 'No SBOM found for this app yet.');
        return;
      }
      if (!r.ok) { alert('Agent Trust Report generation failed.'); return; }
      const blob = await r.blob();
      const ext  = fmt === 'html' ? 'html' : 'json';
      const a    = document.createElement('a');
      a.href     = URL.createObjectURL(blob);
      a.download = `${currentApp}-agent-trust-report.${ext}`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch {
      alert('Agent Trust Report generation failed.');
    }
  });
});

// ── Scan jobs ─────────────────────────────────────────────────────────────────

let scanPollTimer = null;

function renderScanJobs(jobs) {
  const el = document.getElementById('scan-jobs-wrap');
  if (!jobs.length) { el.innerHTML = ''; return; }

  const statusBadge = j => {
    if (j.status === 'done')    return '<span class="badge b-green">Done</span>';
    if (j.status === 'failed')  return '<span class="badge b-red">Failed</span>';
    if (j.status === 'running') return '<span class="badge b-spinning">Scanning…</span>';
    return '<span class="badge b-muted">Queued</span>';
  };

  el.innerHTML = `<div class="table-wrap"><table>
    <thead><tr><th>Repository</th><th>Ref</th><th>Status</th><th>App</th><th>Time</th><th>Details</th></tr></thead>
    <tbody>${jobs.map(j => `<tr>
      <td class="job-repo">${esc(j.repo)}</td>
      <td class="job-ref">${j.ref ? esc(j.ref) : '<span class="c-muted">default</span>'}</td>
      <td>${statusBadge(j)}</td>
      <td>${j.app_name
            ? `<span class="app-link" data-goto="${esc(j.app_name)}" style="cursor:pointer">${esc(j.app_name)}</span>`
            : '<span class="c-muted">—</span>'}</td>
      <td class="c-muted">${timeAgo(j.created_at)}</td>
      <td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--red);font-size:12px">${
        j.status === 'failed' ? esc(j.error || 'Unknown error') : ''
      }</td>
    </tr>`).join('')}
    </tbody></table></div>`;
}

async function loadScanJobs() {
  try {
    const data = await apiFetch('/api/v1/scan');
    renderScanJobs(data.jobs);
    scheduleScanPoll(data.jobs);
  } catch { /* silent */ }
}

function scheduleScanPoll(jobs) {
  clearTimeout(scanPollTimer);
  const hasActive = jobs.some(j => j.status === 'pending' || j.status === 'running');
  if (hasActive) {
    scanPollTimer = setTimeout(async () => {
      await loadScanJobs();
      // Refresh apps list when a job just completed
      const fresh = await apiFetch('/api/v1/scan').catch(() => ({ jobs: [] }));
      const nowDone = fresh.jobs.some(j => j.status === 'done');
      if (nowDone) {
        const [appsRes, reportRes] = await Promise.allSettled([
          apiFetch('/api/v1/apps'),
          apiFetch('/api/v1/report'),
        ]);
        // Re-render apps (reuse loadDashboard logic inline)
        if (appsRes.status === 'fulfilled') renderAppsList(appsRes.value.apps);
        if (reportRes.status === 'fulfilled') renderSummaryCards(reportRes.value.summary);
      }
    }, 3000);
  }
}

function renderSummaryCards(s) {
  if (!s) return;
  document.getElementById('s-apps').textContent       = s.total_apps       ?? '0';
  document.getElementById('s-components').textContent = s.unique_components ?? '0';
  document.getElementById('s-critical').textContent   = s.critical          ?? '0';
  document.getElementById('s-high').textContent       = s.high              ?? '0';
}

function renderAppsList(apps) {
  const appsEl = document.getElementById('apps-wrap');
  if (!apps.length) {
    appsEl.innerHTML = `<div class="empty">No apps ingested yet.<br><br>
      Run <code style="font-family:monospace;font-size:12px;color:var(--accent)">npx sbomix owner/repo</code>
      and push your SBOM to see data here.</div>`;
    return;
  }
  appsEl.innerHTML = `<div class="table-wrap"><table>
    <thead><tr>
      <th>Application</th><th>Ecosystems</th><th>Last scanned</th>
      <th>Components</th><th>Vulns</th><th>Critical</th><th>Quality</th>
    </tr></thead>
    <tbody>${apps.map(a => `
      <tr class="clickable" data-goto="${esc(a.name)}">
        <td><span class="app-link">${esc(a.name)}</span></td>
        <td>${ecoTags(a.ecosystems)}</td>
        <td class="c-muted">${timeAgo(a.last_scanned)}</td>
        <td>${a.component_count ?? '—'}</td>
        <td>${Number(a.vulnerability_count) > 0
              ? `<span class="badge b-yellow">${a.vulnerability_count}</span>`
              : '<span class="c-green">0</span>'}</td>
        <td>${Number(a.critical_count) > 0
              ? `<span class="badge b-red">${a.critical_count}</span>`
              : '<span class="c-green">0</span>'}</td>
        <td>${qsBadge(a.quality_score)}</td>
      </tr>`).join('')}
    </tbody></table></div>`;
}

document.getElementById('scan-btn').addEventListener('click', async () => {
  const repoVal  = document.getElementById('scan-repo').value.trim();
const errEl    = document.getElementById('scan-error');
  const btn      = document.getElementById('scan-btn');

  errEl.style.display = 'none';
  if (!repoVal) {
    errEl.textContent = 'Enter a repository (e.g. facebook/react)';
    errEl.style.display = 'block';
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Starting…';

  try {
    const body = { repo: repoVal };    await apiFetch('/api/v1/scan', { method: 'POST', body: JSON.stringify(body) });
    document.getElementById('scan-repo').value  = '';
    await loadScanJobs();
  } catch (err) {
    errEl.textContent = err.status === 429
      ? 'Active scans already running — wait for them to finish.'
      : 'Failed to start scan. Check the repo name and try again.';
    errEl.style.display = 'block';
  }

  btn.disabled = false;
  btn.textContent = 'Scan';
});

document.getElementById('scan-repo').addEventListener('keydown', e => {
  if (e.key === 'Enter') document.getElementById('scan-btn').click();
});

// ── Billing ───────────────────────────────────────────────────────────────────

const PLAN_LABELS = {
  free:     { name: 'Free',     desc: 'Generate SBOMs · 1 app · 7-day history' },
  starter:  { name: 'Hosted',  desc: 'Track your apps · 10 apps · 30-day history' },
  team:     { name: 'Team',     desc: 'Protect every PR · 50 apps · 5 seats · 180-day history' },
  business: { name: 'Business', desc: 'Manage org exposure · 250 apps · 20 seats · 1-year history' },
  enterprise:{ name:'Enterprise',desc:'Governed supply-chain risk at scale' },
};

// price IDs injected from the server at page load (see loadBilling)
let PRICES = {};
let currentBillingCycle = 'monthly';

async function loadBilling() {
  try {
    const data = await apiFetch('/api/v1/billing');
    renderBilling(data);

    // Also fetch available prices from the server
    const priceData = await apiFetch('/api/v1/billing/prices').catch(() => null);
    if (priceData) PRICES = priceData;
  } catch { /* silent — billing section just stays in default state */ }
}

function renderBilling(data) {
  const plan   = data.plan || 'free';
  const status = data.status;
  const label  = PLAN_LABELS[plan] || PLAN_LABELS.free;

  document.getElementById('billing-plan-name').textContent = label.name;
  document.getElementById('billing-plan-desc').textContent = label.desc;

  // Status badge
  const badgeEl = document.getElementById('billing-status-badge');
  if (status === 'trialing') {
    badgeEl.innerHTML = '<span class="badge b-blue">Trial</span>';
  } else if (status === 'past_due') {
    badgeEl.innerHTML = '<span class="badge b-red">Past due</span>';
  } else if (status === 'canceled') {
    badgeEl.innerHTML = '<span class="badge b-muted">Canceled</span>';
  } else if (status === 'active' && plan !== 'free') {
    badgeEl.innerHTML = '<span class="badge b-green">Active</span>';
  } else {
    badgeEl.innerHTML = '';
  }

  // Period end
  const periodEl = document.getElementById('billing-period');
  if (data.current_period_end) {
    const d = new Date(data.current_period_end);
    const label = status === 'trialing' ? 'Trial ends' : status === 'canceled' ? 'Access until' : 'Renews';
    periodEl.textContent = `${label} ${d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}`;
  } else {
    periodEl.textContent = '';
  }

  // Buttons
  const upgradeBtn = document.getElementById('billing-upgrade-btn');
  const manageBtn  = document.getElementById('billing-manage-btn');

  if (plan === 'free' || plan === 'starter' || status === 'canceled') {
    upgradeBtn.style.display = '';
    manageBtn.style.display  = 'none';
  } else if (data.has_payment_method) {
    upgradeBtn.style.display = 'none';
    manageBtn.style.display  = '';
  }
}

function setBillingCycle(cycle) {
  currentBillingCycle = cycle;
  document.getElementById('cycle-monthly').classList.toggle('active', cycle === 'monthly');
  document.getElementById('cycle-annual').classList.toggle('active',  cycle === 'annual');
  document.getElementById('cycle-monthly').style.borderColor = cycle === 'monthly' ? 'var(--accent)' : 'var(--border)';
  document.getElementById('cycle-monthly').style.color       = cycle === 'monthly' ? 'var(--accent)' : 'var(--muted)';
  document.getElementById('cycle-annual').style.borderColor  = cycle === 'annual'  ? 'var(--accent)' : 'var(--border)';
  document.getElementById('cycle-annual').style.color        = cycle === 'annual'  ? 'var(--accent)' : 'var(--muted)';
  renderPlanCards();
}

const PLAN_CARD_META = [
  { plan: 'starter',  label: 'Hosted',  monthly: '$49/mo', annual: '$499/yr', save: '' },
  { plan: 'team',     label: 'Team',     monthly: '$99/mo', annual: '$990/yr', save: 'Most popular' },
  { plan: 'business', label: 'Business', monthly: '$299/mo',annual: '$2,990/yr',save: '' },
];

function renderPlanCards() {
  const container = document.getElementById('plan-cards');
  container.innerHTML = PLAN_CARD_META.map(p => {
    const priceId = PRICES[`${p.plan}_${currentBillingCycle}`];
    const price   = currentBillingCycle === 'annual' ? p.annual : p.monthly;
    return `<div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px">
      <div style="font-weight:700;font-size:13px;margin-bottom:2px">${p.label}${p.save ? ` <span style="color:var(--accent);font-size:10px;font-weight:600">${p.save}</span>` : ''}</div>
      <div style="font-size:18px;font-weight:800;margin-bottom:10px">${price}</div>
      <button class="btn-sm plan-select-btn" data-price-id="${priceId || ''}" style="width:100%;border-color:var(--accent);color:var(--accent)">
        Select
      </button>
    </div>`;
  }).join('');
}

async function startCheckout(priceId) {
  const errEl = document.getElementById('plan-picker-error');
  errEl.style.display = 'none';

  if (!priceId) {
    errEl.textContent = 'Billing is not yet configured on this server.';
    errEl.style.display = 'block';
    return;
  }

  try {
    const data = await apiFetch('/api/v1/billing/checkout', {
      method: 'POST',
      body: JSON.stringify({ priceId }),
    });
    window.location.href = data.url;
  } catch (err) {
    errEl.textContent = `Could not start checkout: ${err.message || 'Unknown error'}`;
    errEl.style.display = 'block';
  }
}

document.getElementById('cycle-monthly').addEventListener('click', () => setBillingCycle('monthly'));
document.getElementById('cycle-annual').addEventListener('click',  () => setBillingCycle('annual'));

document.getElementById('plan-cards').addEventListener('click', (e) => {
  const btn = e.target.closest('.plan-select-btn');
  if (btn) startCheckout(btn.dataset.priceId);
});

document.getElementById('billing-upgrade-btn').addEventListener('click', () => {
  const picker = document.getElementById('plan-picker');
  const isOpen = picker.style.display !== 'none';
  picker.style.display = isOpen ? 'none' : 'block';
  if (!isOpen) renderPlanCards();
});

document.getElementById('billing-manage-btn').addEventListener('click', async () => {
  const btn = document.getElementById('billing-manage-btn');
  btn.disabled = true;
  btn.textContent = 'Loading…';
  try {
    const data = await apiFetch('/api/v1/billing/portal', { method: 'POST' });
    window.location.href = data.url;
  } catch {
    btn.disabled = false;
    btn.textContent = 'Manage billing';
  }
});

// ── Alert toggle ─────────────────────────────────────────────────────────────

document.getElementById('alerts-toggle').addEventListener('change', async function () {
  const checked = this.checked;
  try {
    await apiFetch('/api/v1/account/settings', {
      method: 'PATCH',
      body: JSON.stringify({ vuln_alerts: checked }),
    });
  } catch {
    this.checked = !checked; // revert on failure
  }
});

// ── Delete account ────────────────────────────────────────────────────────────

document.getElementById('delete-account-btn').addEventListener('click', () => {
  document.getElementById('delete-confirm').style.display = 'block';
  document.getElementById('delete-confirm-input').value = '';
  document.getElementById('delete-account-btn').style.display = 'none';
});

document.getElementById('delete-cancel-btn').addEventListener('click', () => {
  document.getElementById('delete-confirm').style.display = 'none';
  document.getElementById('delete-account-btn').style.display = '';
});

document.getElementById('delete-confirm-btn').addEventListener('click', async () => {
  const val = document.getElementById('delete-confirm-input').value.trim();
  if (val !== 'delete my account') {
    document.getElementById('delete-confirm-input').focus();
    document.getElementById('delete-confirm-input').style.borderColor = 'var(--red)';
    setTimeout(() => { document.getElementById('delete-confirm-input').style.borderColor = ''; }, 1200);
    return;
  }
  const btn = document.getElementById('delete-confirm-btn');
  btn.disabled = true;
  btn.textContent = 'Deleting…';
  try {
    await apiFetch('/api/v1/account', {
      method: 'DELETE',
      body: JSON.stringify({ confirm: 'delete my account' }),
    });
    logout();
  } catch {
    btn.disabled = false;
    btn.textContent = 'Delete forever';
    alert('Deletion failed — please try again.');
  }
});

document.getElementById('logout-btn').addEventListener('click', logout);
document.getElementById('back-btn').addEventListener('click', showList);
document.getElementById('logo').addEventListener('click', showList);

loadDashboard();
