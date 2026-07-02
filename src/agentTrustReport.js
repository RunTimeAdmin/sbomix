'use strict';

/**
 * Agent Trust Report — crypto-agent profile.
 *
 * Assembles a compliance-facing report from data the normal SBOMix pipeline
 * already produces (SBOM, AI-BOM, MCP/agentic context, Least Agency Score),
 * plus two new checks (signing surface, known-bad match) that run over the
 * same component list. No new detection engine, no new pipeline pass.
 *
 * Two outputs from one JSON model:
 *   - JSON manifest (machine-readable, deterministic hash for tamper-evidence)
 *   - Standalone HTML report (styled, print-to-PDF; same pattern as the
 *     hosted dashboard's buildReport(), no PDF library dependency)
 *
 * This report states facts and flags. It does not score, grade, or certify.
 */

const crypto = require('crypto');
const pkg = require('../package.json');
const { scanSigningSurface, scanEnvForSigningKeyNames } = require('./signingSurface');
const { checkKnownBad } = require('./knownBad');

// ── Determinism ──────────────────────────────────────────────────────────────
// CycloneDX embeds a random serialNumber and a generation timestamp by design
// (spec requirement for BOM instance identity). Neither is meaningful to a
// tamper-evidence hash: strip known-volatile paths, sort object keys so key
// order can never affect the hash, then hash the result. Two runs against the
// same commit with the same known-bad list version produce the same hash.
const VOLATILE_PATHS = new Set([
    'serialNumber', 'metadata.timestamp', 'generatedAt', 'reportId', 'cover.scanDate',
]);

function stripVolatile(obj, prefix = '') {
    if (Array.isArray(obj)) return obj.map((v) => stripVolatile(v, prefix));
    if (obj && typeof obj === 'object') {
        const out = {};
        for (const [k, v] of Object.entries(obj)) {
            const p = prefix ? `${prefix}.${k}` : k;
            if (VOLATILE_PATHS.has(p)) continue;
            out[k] = stripVolatile(v, p);
        }
        return out;
    }
    return obj;
}

function stableStringify(obj) {
    if (Array.isArray(obj)) return `[${obj.map(stableStringify).join(',')}]`;
    if (obj && typeof obj === 'object') {
        const keys = Object.keys(obj).sort();
        return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(',')}}`;
    }
    return JSON.stringify(obj);
}

function canonicalSha256(obj) {
    return crypto.createHash('sha256').update(stableStringify(stripVolatile(obj)), 'utf8').digest('hex');
}

// ── Report assembly ───────────────────────────────────────────────────────────

const SEVERITY = { CRITICAL: 'Critical', ATTENTION: 'Attention', INFO: 'Informational' };

/**
 * @param {object} pipelineResult - return value of generateFromDirectory()
 * @param {object} meta - { name, version, scanTarget, commitSha, scanDir }
 * @returns {object} report JSON (manifestSha256 embedded under integrity)
 */
function buildAgentTrustReport(pipelineResult, meta = {}) {
    const { cyclonedx, aiBom, components, stats } = pipelineResult;
    const agentic = aiBom?.agentic || { mcpServers: [], prompts: [], boundaries: {} };

    const signing = scanSigningSurface(components, cyclonedx);
    const envKeys = meta.scanDir ? scanEnvForSigningKeyNames(meta.scanDir) : [];
    const knownBad = checkKnownBad(components);

    const directCount = cyclonedx?.dependencies
        ?.find((d) => d.ref === cyclonedx.metadata?.component?.purl)?.dependsOn?.length ?? null;
    const totalDeps = components.filter((c) => c.ecosystem !== 'container' && c.ecosystem !== 'ai').length;

    const flags = [];
    for (const m of knownBad.exactMatches) {
        flags.push({ item: `${m.name}@${m.version}`, category: 'known-bad', severity: SEVERITY.CRITICAL, reason: m.reason });
    }
    for (const m of knownBad.typosquatMatches) {
        flags.push({ item: `${m.name}@${m.version}`, category: 'typosquat', severity: SEVERITY.ATTENTION, reason: `name is edit-distance ${m.distance} from '${m.similarTo}'` });
    }
    for (const s of agentic.mcpServers) {
        if (s.authority?.shellAccess) flags.push({ item: s.name, category: 'mcp-authority', severity: SEVERITY.CRITICAL, reason: 'MCP server has shell execution authority' });
        if (s.authority?.broadFilesystem) flags.push({ item: s.name, category: 'mcp-authority', severity: SEVERITY.ATTENTION, reason: 'MCP server has broad filesystem access' });
        if (s.authority?.unpinnedSource) flags.push({ item: s.name, category: 'mcp-pinning', severity: SEVERITY.ATTENTION, reason: 'MCP server source is not version-pinned' });
        if (!s.requiresAuth) flags.push({ item: s.name, category: 'mcp-auth', severity: SEVERITY.INFO, reason: 'MCP server has no detected authentication' });
    }
    if (signing.hasSigningSurface) {
        flags.push({ item: `${signing.matches.length} signing-capable package(s)`, category: 'signing-surface', severity: SEVERITY.ATTENTION, reason: 'deployment includes wallet/signing libraries' });
    }

    const report = {
        reportVersion: '0.1',
        reportId: crypto.randomUUID(),
        cover: {
            projectName: meta.name || 'unknown',
            scanTarget: meta.scanTarget || meta.name || 'unknown',
            commitSha: meta.commitSha || null,
            scanDate: new Date().toISOString(),
            sbomixVersion: pkg.version,
        },
        execSummary: {
            totalDependencies: totalDeps,
            directDependencies: directCount,
            mcpServersDetected: agentic.mcpServers.length,
            aiModelsDetected: stats?.aiModels ?? 0,
            signingSurfaceDetected: signing.hasSigningSurface,
            leastAgencyScore: agentic.boundaries?.leastAgencyScore ?? null,
            flags,
        },
        sbom: {
            componentCount: totalDeps,
            ecosystems: stats?.ecosystems ?? [],
            cyclonedxSha256: cyclonedx ? canonicalSha256(cyclonedx) : null,
        },
        aiBom: {
            present: !!aiBom,
            aiModels: stats?.aiModels ?? 0,
            apiProviders: stats?.aiApiProviders ?? 0,
            frameworks: stats?.aiFrameworks ?? 0,
            threatCount: stats?.aiThreats ?? 0,
            criticalThreats: stats?.aiCritical ?? 0,
            highThreats: stats?.aiHigh ?? 0,
            aiBomSha256: aiBom ? canonicalSha256(aiBom) : null,
        },
        mcpToolSurface: {
            serverCount: agentic.mcpServers.length,
            servers: agentic.mcpServers.map((s) => ({
                name: s.name,
                transport: s.transport,
                requiresAuth: s.requiresAuth,
                unpinnedSource: s.authority?.unpinnedSource ?? false,
                shellAccess: s.authority?.shellAccess ?? false,
                broadFilesystem: s.authority?.broadFilesystem ?? false,
                publisherStatus: 'unknown', // registry verification lookup is not implemented — stated explicitly, not omitted
                knownBadMatch: knownBad.exactMatches.some((m) => m.name === s.name),
                sourceFile: s.sourceFile,
            })),
            boundaries: agentic.boundaries || {},
        },
        signingSurface: {
            detected: signing.hasSigningSurface,
            matches: signing.matches,
            envKeyNames: envKeys.map((e) => e.variable),
            statement: signing.hasSigningSurface
                ? 'This deployment contains components capable of signing transactions. A compromise of any Critical-flagged item above could result in irreversible loss of funds.'
                : 'No known signing or wallet libraries detected in the scanned dependency tree.',
            disclaimer: 'Presence detection only. This is not a code audit of the matched components.',
        },
        knownBad,
        complianceMapping: {
            euAiAct: [
                { article: 'Art. 11 / Annex IV', note: 'Technical documentation: system components, versions, and third-party elements — this report\'s SBOM and AI-BOM sections.' },
            ],
            owaspAgenticTop10: [
                { id: 'ASI04', note: 'Supply chain — dependency, MCP tool, and signing-surface inventory.' },
            ],
            disclaimer: 'Evidence-to-control mapping only. Documentation aligned to the referenced frameworks, not a certification or legal conformity assessment. Not an audit, not a penetration test, not a legal opinion.',
        },
    };

    report.integrity = { manifestSha256: canonicalSha256(report), listVersions: { knownBad: knownBad.listVersion } };

    return report;
}

// ── HTML rendering ────────────────────────────────────────────────────────────
// Same visual language and print pattern as the hosted dashboard's
// buildReport(): dark UI, print media query, no external assets.

function esc(s) {
    return String(s ?? '')
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const SEV_COLOR = { Critical: '#f85149', Attention: '#d29922', Informational: '#8b949e' };

function renderAgentTrustReportHTML(report) {
    const flagRows = report.execSummary.flags.map((f) => `
    <tr>
      <td>${esc(f.item)}</td>
      <td><span style="background:${SEV_COLOR[f.severity]}22;color:${SEV_COLOR[f.severity]};padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600">${esc(f.severity)}</span></td>
      <td style="color:#8b949e">${esc(f.category)}</td>
      <td style="color:#8b949e;font-size:13px">${esc(f.reason)}</td>
    </tr>`).join('');

    const mcpRows = report.mcpToolSurface.servers.map((s) => `
    <tr>
      <td style="font-family:monospace;font-size:12px">${esc(s.name)}</td>
      <td>${esc(s.transport)}</td>
      <td>${s.requiresAuth ? '<span style="color:#3fb950">yes</span>' : '<span style="color:#d29922">no</span>'}</td>
      <td>${s.unpinnedSource ? '<span style="color:#d29922">unpinned</span>' : '<span style="color:#3fb950">pinned</span>'}</td>
      <td>${s.shellAccess || s.broadFilesystem ? '<span style="color:#f85149">broad</span>' : '<span style="color:#3fb950">scoped</span>'}</td>
    </tr>`).join('');

    const signingRows = report.signingSurface.matches.map((m) => `
    <tr>
      <td style="font-family:monospace;font-size:12px">${esc(m.name)}</td>
      <td style="color:#8b949e">${esc(m.version)}</td>
      <td>${esc(m.ecosystem)}</td>
      <td style="color:#58a6ff">${esc(m.category)}</td>
      <td style="color:#8b949e">${esc(m.directness)}</td>
    </tr>`).join('');

    const envRows = report.signingSurface.envKeyNames.map((v) => `<span style="font-family:monospace;font-size:12px;background:#161b22;border:1px solid #30363d;border-radius:4px;padding:2px 8px;margin:2px;display:inline-block">${esc(v)}</span>`).join('');

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Agent Trust Report — ${esc(report.cover.projectName)}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0d1117; color: #e6edf3; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 14px; padding: 40px; }
  @media print {
    body { background: #fff; color: #000; padding: 20px; }
    a { color: #0066cc; }
    .no-print { display: none; }
  }
  h1 { font-size: 22px; font-weight: 700; font-family: monospace; letter-spacing: -0.3px; }
  h2 { font-size: 15px; font-weight: 600; margin: 32px 0 12px; padding-bottom: 8px; border-bottom: 1px solid #30363d; }
  .meta { color: #8b949e; font-size: 13px; margin: 6px 0 24px; display: flex; flex-wrap: wrap; gap: 16px; }
  .stats { display: flex; gap: 24px; margin-bottom: 32px; flex-wrap: wrap; }
  .stat { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 14px 20px; min-width: 110px; }
  .stat-label { font-size: 11px; text-transform: uppercase; letter-spacing: .5px; color: #8b949e; margin-bottom: 4px; }
  .stat-value { font-size: 26px; font-weight: 700; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 8px 12px; font-size: 11px; text-transform: uppercase; letter-spacing: .4px; color: #8b949e; border-bottom: 2px solid #30363d; }
  td { padding: 9px 12px; border-bottom: 1px solid #21262d; vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  .footer { margin-top: 40px; color: #8b949e; font-size: 12px; text-align: center; padding-top: 16px; border-top: 1px solid #30363d; }
  .print-btn { background: #3fb950; color: #000; font-weight: 700; border: none; padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 13px; margin-bottom: 24px; }
  .disclaimer { color: #8b949e; font-size: 12px; font-style: italic; margin-top: 10px; }
  .mono { font-family: monospace; font-size: 11px; word-break: break-all; color: #8b949e; }
</style>
</head>
<body>
<button class="print-btn no-print" onclick="window.print()">Print / Save as PDF</button>
<h1>Agent Trust Report — ${esc(report.cover.projectName)}</h1>
<div class="meta">
  <span>${esc(report.cover.scanTarget)}</span>
  ${report.cover.commitSha ? `<span style="font-family:monospace">${esc(report.cover.commitSha.slice(0, 7))}</span>` : ''}
  <span>Generated ${esc(report.cover.scanDate)}</span>
  <span>SBOMix v${esc(report.cover.sbomixVersion)}</span>
  <span>Report ${esc(report.reportId.slice(0, 8))}</span>
</div>

<h2>Executive Summary</h2>
<div class="stats">
  <div class="stat"><div class="stat-label">Dependencies</div><div class="stat-value">${report.execSummary.totalDependencies}</div></div>
  <div class="stat"><div class="stat-label">MCP Servers</div><div class="stat-value">${report.execSummary.mcpServersDetected}</div></div>
  <div class="stat"><div class="stat-label">AI Models</div><div class="stat-value">${report.execSummary.aiModelsDetected}</div></div>
  <div class="stat"><div class="stat-label">Least Agency</div><div class="stat-value">${report.execSummary.leastAgencyScore ?? '—'}</div></div>
  <div class="stat"><div class="stat-label">Signing Surface</div><div class="stat-value" style="color:${report.execSummary.signingSurfaceDetected ? '#f85149' : '#3fb950'}">${report.execSummary.signingSurfaceDetected ? 'Yes' : 'No'}</div></div>
</div>
${report.execSummary.flags.length ? `<table>
  <thead><tr><th>Item</th><th>Severity</th><th>Category</th><th>Reason</th></tr></thead>
  <tbody>${flagRows}</tbody>
</table>` : '<p style="color:#3fb950">No flags raised.</p>'}

<h2>MCP Tool Surface (${report.mcpToolSurface.serverCount})</h2>
${report.mcpToolSurface.servers.length ? `<table>
  <thead><tr><th>Server</th><th>Transport</th><th>Auth</th><th>Pinning</th><th>Authority</th></tr></thead>
  <tbody>${mcpRows}</tbody>
</table>` : '<p style="color:#8b949e">No MCP servers detected in scanned paths.</p>'}

<h2>Signing Surface</h2>
<p style="margin-bottom:12px">${esc(report.signingSurface.statement)}</p>
<p class="disclaimer">${esc(report.signingSurface.disclaimer)}</p>
${report.signingSurface.matches.length ? `<table style="margin-top:12px">
  <thead><tr><th>Package</th><th>Version</th><th>Ecosystem</th><th>Category</th><th>Scope</th></tr></thead>
  <tbody>${signingRows}</tbody>
</table>` : ''}
${report.signingSurface.envKeyNames.length ? `<p style="margin-top:16px;color:#8b949e;font-size:12px">Env variable names referencing key material (values never read):</p><div style="margin-top:6px">${envRows}</div>` : ''}

<h2>Compliance Mapping</h2>
${report.complianceMapping.euAiAct.map((c) => `<p style="margin-bottom:6px"><strong>${esc(c.article)}</strong> — ${esc(c.note)}</p>`).join('')}
${report.complianceMapping.owaspAgenticTop10.map((c) => `<p style="margin-bottom:6px"><strong>OWASP ${esc(c.id)}</strong> — ${esc(c.note)}</p>`).join('')}
<p class="disclaimer" style="margin-top:12px">${esc(report.complianceMapping.disclaimer)}</p>

<div class="footer">
  <p>SBOM manifest SHA-256: <span class="mono">${esc(report.sbom.cyclonedxSha256 || 'n/a')}</span></p>
  <p>Report manifest SHA-256: <span class="mono">${esc(report.integrity.manifestSha256)}</span></p>
  <p style="margin-top:12px">Known-bad list version: ${esc(report.integrity.listVersions.knownBad)}</p>
  <p style="margin-top:16px">SBOMix · sbomix.com</p>
</div>
</body></html>`;
}

module.exports = { buildAgentTrustReport, renderAgentTrustReportHTML, canonicalSha256 };
