'use strict';

const OpenAI = require('openai');

let _client = null;
let _model  = null;

const DEFAULT_BASE_URL = 'https://api.anthropic.com/v1';
const DEFAULT_MODEL    = 'claude-haiku-4-5-20251001';

/**
 * Resolve the AI provider from environment variables.
 *
 * Required (unless using Ollama):
 *   EXPLAIN_API_KEY   — Anthropic, OpenAI, or any compatible key
 *
 * Optional:
 *   EXPLAIN_BASE_URL  — defaults to https://api.anthropic.com/v1 (Anthropic Claude)
 *   EXPLAIN_MODEL     — defaults to claude-haiku-4-5-20251001
 *
 * Self-hosted (no key required):
 *   EXPLAIN_BASE_URL=http://localhost:11434/v1  EXPLAIN_MODEL=llama3.2
 */
function getClientAndModel() {
    if (_client) return { client: _client, model: _model };

    const baseURL = process.env.EXPLAIN_BASE_URL || DEFAULT_BASE_URL;
    const apiKey  = process.env.EXPLAIN_API_KEY;
    const model   = process.env.EXPLAIN_MODEL || DEFAULT_MODEL;

    const isLocalhost = baseURL.includes('localhost') || baseURL.includes('127.0.0.1');

    if (!apiKey && !isLocalhost) {
        throw new Error(
            'EXPLAIN_API_KEY is not set.\n\n' +
            'Default provider is Anthropic Claude. Get a key at https://console.anthropic.com\n' +
            'then set: EXPLAIN_API_KEY=sk-ant-...\n\n' +
            'To use a self-hosted model with no API key:\n' +
            '  Install Ollama: https://ollama.com  then: ollama pull llama3.2\n' +
            '  EXPLAIN_BASE_URL=http://localhost:11434/v1  EXPLAIN_MODEL=llama3.2\n\n' +
            'Other OpenAI-compatible providers:\n' +
            '  EXPLAIN_BASE_URL=https://api.openai.com/v1  EXPLAIN_API_KEY=sk-...  EXPLAIN_MODEL=gpt-4o-mini'
        );
    }

    _client = new OpenAI({
        apiKey:  apiKey || 'local',
        baseURL,
    });
    _model = model;

    return { client: _client, model: _model };
}

/**
 * Ask the configured AI provider to explain vulnerabilities and produce a
 * remediation plan.
 *
 * @param {object[]} components  - enriched components from the pipeline
 * @param {string}   projectName - used in the prompt for context
 * @param {Set}      [kevSet]    - set of KEV IDs for callout
 * @returns {Promise<string>}
 */
async function explainVulnerabilities(components, projectName, kevSet = null) {
    const vulnComponents = components.filter(c => c.vulnerabilities?.length);
    if (!vulnComponents.length) return null;

    const vulnSummary = vulnComponents.map(c => {
        const vulns = c.vulnerabilities.map(v => {
            const isKEV = kevSet && (kevSet.has(v.id) || v.aliases?.some(a => kevSet.has(a)));
            return `  - ${v.id}  severity=${v.severity ?? 'unknown'}` +
                (v.cvss        ? `  CVSS=${v.cvss}`        : '') +
                (v.fixedIn?.[0] ? `  fix=${v.fixedIn[0]}`  : '  no-fix-available') +
                (isKEV         ? '  [CISA KEV - actively exploited in the wild]' : '') +
                (v.summary     ? `\n    ${v.summary}`       : '');
        }).join('\n');

        const deps = c.dependedOnBy?.length
            ? `    pulled in by: ${c.dependedOnBy.slice(0, 5).join(', ')}`
            : '';

        return `${c.name}@${c.version} (${c.ecosystem})\n${vulns}${deps ? '\n' + deps : ''}`;
    }).join('\n\n');

    const prompt =
`You are a software supply chain security expert helping a developer understand and fix vulnerabilities.

Project: ${projectName}
Total vulnerable packages: ${vulnComponents.length}

VULNERABILITIES:
${vulnSummary}

Provide:
1. A 2-3 sentence plain-English summary of the overall risk posture.
2. A prioritised remediation plan - order upgrades by impact (most vulns fixed per change first). For each:
   - Package to upgrade, current version to recommended version
   - Which CVEs / OSV IDs it resolves
   - Any blocker (e.g. another package pins this version)
3. If any vulnerabilities have no fix available, say so and suggest a mitigation.

Be concise and actionable. No boilerplate. Write as if briefing a senior developer.`;

    const { client, model } = getClientAndModel();
    const response = await client.chat.completions.create({
        model,
        messages:    [{ role: 'user', content: prompt }],
        temperature: 0.2,
        max_tokens:  1024,
    });

    return response.choices[0].message.content.trim();
}

/**
 * Explain vulnerabilities from raw DB rows (used by the API endpoint).
 *
 * @param {object[]} vulnRows   - rows from DB: { name, version, ecosystem, osv_id, severity, cvss_score, fixed_version, title, kev }
 * @param {string}   appName
 * @returns {Promise<string>}
 */
async function explainVulnRows(vulnRows, appName) {
    if (!vulnRows.length) return null;

    const byComp = new Map();
    for (const r of vulnRows) {
        const key = `${r.name}@${r.version}`;
        if (!byComp.has(key)) byComp.set(key, { ...r, vulns: [] });
        byComp.get(key).vulns.push(r);
    }

    const vulnSummary = [...byComp.values()].map(c => {
        const vulns = c.vulns.map(v =>
            `  - ${v.osv_id}  severity=${v.severity ?? 'unknown'}` +
            (v.cvss_score    ? `  CVSS=${v.cvss_score}`    : '') +
            (v.fixed_version ? `  fix=${v.fixed_version}`  : '  no-fix-available') +
            (v.kev           ? '  [CISA KEV - actively exploited in the wild]' : '') +
            (v.title         ? `\n    ${v.title}`          : '')
        ).join('\n');
        return `${c.name}@${c.version} (${c.ecosystem})\n${vulns}`;
    }).join('\n\n');

    const prompt =
`You are a software supply chain security expert helping a developer understand and fix vulnerabilities.

App: ${appName}
Total vulnerable packages: ${byComp.size}

VULNERABILITIES:
${vulnSummary}

Provide:
1. A 2-3 sentence plain-English summary of the overall risk posture.
2. A prioritised remediation plan - order upgrades by impact (most vulns fixed per change first). For each:
   - Package to upgrade, current version to recommended version
   - Which CVEs / OSV IDs it resolves
   - Any blocker (e.g. another package pins this version)
3. If any vulnerabilities have no fix available, say so and suggest a mitigation.

Be concise and actionable. No boilerplate. Write as if briefing a senior developer.`;

    const { client, model } = getClientAndModel();
    const response = await client.chat.completions.create({
        model,
        messages:    [{ role: 'user', content: prompt }],
        temperature: 0.2,
        max_tokens:  1024,
    });

    return response.choices[0].message.content.trim();
}

module.exports = { explainVulnerabilities, explainVulnRows };
