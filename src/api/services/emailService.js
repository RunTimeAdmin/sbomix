'use strict';

const db = require('../db');

async function sendEmail({ to, subject, html }) {
    const key = process.env.RESEND_API_KEY;
    if (!key) { console.warn('[resend] RESEND_API_KEY not set — skipping email'); return; }
    const from = process.env.RESEND_FROM || 'SBOMix <noreply@sbomix.com>';
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

async function sendVulnAlertIfNew(orgId, appId, appName) {
    try {
        const orgRes = await db.query('SELECT email, vuln_alerts FROM organizations WHERE id = $1', [orgId]);
        const email  = orgRes.rows[0]?.email;
        if (!email || orgRes.rows[0]?.vuln_alerts === false) return;

        const sbomRes = await db.query(
            `SELECT id, critical_count FROM sboms WHERE app_id = $1 ORDER BY created_at DESC LIMIT 2`,
            [appId]
        );
        if (sbomRes.rows.length < 2) return;

        const [current, previous] = sbomRes.rows;
        if (current.critical_count <= (previous.critical_count || 0)) return;

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
            subject: `[SBOMix] ${newCrits.length} new critical vuln${newCrits.length > 1 ? 's' : ''} in ${appName}`,
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
<p style="margin-top:20px"><a href="https://api.sbomix.com/dashboard" style="background:#da3633;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:600;font-size:14px">View in Dashboard</a></p>
<p style="margin-top:24px;color:#8b949e;font-size:12px">You receive these alerts because your org has an email on file. <a href="https://api.sbomix.com/dashboard" style="color:#58a6ff">Manage →</a></p>
</body></html>`,
        });
    } catch (err) {
        console.error('[vuln-alert]', err.message);
    }
}

async function sendScanCompleteEmail(orgId, appName, stats, commitSha) {
    try {
        const orgRes = await db.query('SELECT email FROM organizations WHERE id = $1', [orgId]);
        const email  = orgRes.rows[0]?.email;
        if (!email) return;

        const hasAI   = (stats?.aiModels ?? 0) > 0;
        const vulns   = stats?.vulnerabilities ?? 0;
        const crits   = stats?.critical ?? 0;
        const quality = stats?.qualityScore ?? null;
        const commit  = commitSha ? commitSha.slice(0, 7) : null;

        const vulnColor  = vulns  > 0 ? '#e3b341' : '#3fb950';
        const threatColor = (stats?.aiThreats ?? 0) > 0 ? '#f85149' : '#3fb950';
        const aiRow = hasAI ? [
            '<tr><td colspan="2" style="padding:10px 20px;background:#161b22;border-top:1px solid #30363d;color:#58a6ff;font-weight:600">AI Bill of Materials</td></tr>',
            '<tr><td style="padding:5px 20px;color:#8b949e">AI models detected</td><td style="padding:5px 20px;text-align:right">' + (stats.aiModels ?? 0) + '</td></tr>',
            '<tr><td style="padding:5px 20px;color:#8b949e">AI-BOM threats</td><td style="padding:5px 20px;text-align:right;color:' + threatColor + '">' + (stats.aiThreats ?? 0) + '</td></tr>',
            stats.leastAgencyScore !== null ? '<tr><td style="padding:5px 20px;color:#8b949e">Least Agency Score</td><td style="padding:5px 20px;text-align:right">' + stats.leastAgencyScore + '/100</td></tr>' : '',
        ].join('') : '';

        const qualityRow = quality !== null
            ? '<tr><td style="padding:5px 20px;color:#8b949e">Quality score</td><td style="padding:5px 20px;text-align:right">' + quality + '/100</td></tr>'
            : '';

        const vulnLabel = vulns + (crits > 0 ? ' (' + crits + ' critical)' : '');

        await sendEmail({
            to: email,
            subject: '[SBOMix] Scan complete — ' + appName + (commit ? ' @' + commit : ''),
            html: '<!DOCTYPE html><html><body style="background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;padding:40px;max-width:600px;margin:0 auto">'
                + '<p style="color:#3fb950;font-size:12px;font-weight:700;letter-spacing:1px;margin-bottom:8px">SCAN COMPLETE</p>'
                + '<h1 style="font-size:22px;font-weight:700;margin:0 0 20px">' + appName + '</h1>'
                + '<table style="width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden;margin-bottom:24px">'
                + '<tr><td style="padding:6px 20px;color:#8b949e">Components</td><td style="padding:6px 20px;text-align:right">' + (stats?.totalComponents ?? 0) + '</td></tr>'
                + '<tr><td style="padding:6px 20px;color:#8b949e">Vulnerabilities</td><td style="padding:6px 20px;text-align:right;color:' + vulnColor + '">' + vulnLabel + '</td></tr>'
                + qualityRow
                + aiRow
                + '</table>'
                + '<p style="margin-bottom:24px;color:#8b949e;font-size:13px">Vulnerability enrichment is running in the background — check your dashboard in a minute for the full CVE picture.</p>'
                + '<a href="https://api.sbomix.com/dashboard" style="background:#238636;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:600;font-size:14px">View in Dashboard →</a>'
                + '<p style="margin-top:32px;color:#8b949e;font-size:11px">SBOMix · <a href="https://sbomix.com" style="color:#58a6ff">sbomix.com</a></p>'
                + '</body></html>',
        });
    } catch (err) {
        console.error('[scan-email]', err.message);
    }
}

module.exports = { sendEmail, sendVulnAlertIfNew, sendScanCompleteEmail };
