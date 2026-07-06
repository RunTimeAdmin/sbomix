'use strict';

// Show a config path as its last two segments (e.g. ".cursor/mcp.json") so the
// report reads cleanly regardless of where the project lives on disk.
function shortPath(p) {
    if (!p) return p;
    const parts = String(p).replace(/\\/g, '/').split('/').filter(Boolean);
    return parts.slice(-2).join('/');
}

/**
 * AI-BOM report — the AI/ML supply chain of a project as first-class
 * components: models, external API providers, frameworks, datasets, and
 * (the part no other SBOM tool surfaces) the MCP servers and system prompts
 * an agent can reach, with their authority scope.
 *
 * Detection already happens in the normal scan (src/aibom.js,
 * src/parsers/agentic.js). This is presentation: a focused, plain-language
 * view for "what AI supply chain am I actually shipping / trusting?"
 */

function formatAiBomReport(result, projectName) {
    const aiComps  = (result.components || []).filter((c) => c.ecosystem === 'ai');
    const agentic  = result.aiBom?.agentic || { mcpServers: [], prompts: [], boundaries: {} };
    const threats  = result.aiThreats || [];
    const leastAgency = agentic.boundaries?.leastAgencyScore ?? null;

    const byRole   = (r) => aiComps.filter((c) => c.aiMetadata?.role === r);
    const models   = aiComps.filter((c) => ['model-weights', 'code-reference'].includes(c.aiMetadata?.role));
    const apis     = byRole('api-provider');
    // "framework" plus agent/runtime roles (orchestration = LangChain, etc.)
    const frameworks = aiComps.filter((c) => ['framework', 'orchestration', 'runtime', 'training'].includes(c.aiMetadata?.role));
    const datasets = byRole('dataset');
    const mcp      = agentic.mcpServers || [];
    const prompts  = agentic.prompts || [];

    if (models.length + apis.length + frameworks.length + datasets.length + mcp.length + prompts.length === 0) {
        return `\n  AI-BOM — ${projectName}\n  No AI/ML models, API providers, datasets, agents, or MCP servers detected.\n`;
    }

    const out = [];
    out.push('');
    out.push(`  AI-BOM — ${projectName}`);
    out.push('  AI/ML models, providers, datasets, and agent tooling as first-class supply-chain components.');
    out.push('');

    const section = (title, lines) => {
        if (lines.length === 0) return;
        out.push(`  ${title}`);
        for (const l of lines) out.push(l);
        out.push('');
    };

    section('MODELS & PROVIDERS', [
        ...models.map((m) => {
            const ver = m.version && m.version !== 'local' ? `@${m.version}` : '';
            const src = m.aiMetadata?.source ? `  ·  ${m.aiMetadata.source}` : '';
            const ref = m.aiMetadata?.role === 'code-reference' ? '  ·  referenced at runtime (unpinned)' : '';
            return `    • ${m.name}${ver}  ·  ${m.aiMetadata.role}${src}${ref}`;
        }),
        ...apis.map((a) => `    • ${a.aiMetadata?.provider || a.name}  ·  external API dependency  ·  sdk: ${a.aiMetadata?.sdkPackage || a.name}`),
    ]);

    section('FRAMEWORKS & RUNTIMES',
        frameworks.map((f) => `    • ${f.name}${f.version && f.version !== 'unknown' ? `@${f.version}` : ''}`));

    section('DATASETS', datasets.map((d) => `    • ${d.name}`));

    // ── MCP servers — the differentiator ────────────────────────────────────
    section(`MCP SERVERS / AGENT TOOLS (${mcp.length})  —  what your agent can call`,
        mcp.map((s) => {
            const a = s.authority || {};
            const risk = [];
            if (a.shellAccess)     risk.push('shell-exec');
            if (a.broadFilesystem) risk.push('broad-filesystem');
            if (a.dangerFlags)     risk.push('bypass-confirmation');
            if (a.unpinnedSource)  risk.push('unpinned-source');
            const auth = s.requiresAuth ? 'auth required' : 'no auth';
            const riskStr = risk.length ? `  ·  ⚠ ${risk.join(', ')}` : '';
            const from = s.sourceFile ? `\n        from ${shortPath(s.sourceFile)}` : '';
            return `    • ${s.name}  ·  ${s.transport || 'stdio'}  ·  ${auth}${riskStr}${from}`;
        }));

    section(`SYSTEM PROMPTS / AGENT RULES (${prompts.length})  —  behaviour-control surface`,
        prompts.map((p) => `    • ${p.name}${p.path ? `  ·  ${shortPath(p.path)}` : ''}`));

    if (leastAgency !== null) {
        out.push(`  Least Agency Score: ${leastAgency}/100  (higher = tighter agent authority)`);
    }
    if (threats.length) {
        const crit = threats.filter((t) => t.severity === 'CRITICAL').length;
        const high = threats.filter((t) => t.severity === 'HIGH').length;
        out.push(`  AI supply-chain threats: ${threats.length}  (${crit} critical, ${high} high)`);
        for (const t of threats) {
            out.push(`    [${t.severity}] ${t.id} ${t.name}${t.component ? `  ·  ${t.component}` : ''}`);
        }
    }
    out.push('');
    out.push('  Presence detection and static inventory — not a code audit or a security rating.');
    out.push('');
    return out.join('\n');
}

module.exports = { formatAiBomReport };
