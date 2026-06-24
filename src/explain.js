'use strict';

const OpenAI = require('openai');

let _client = null;

function getClient() {
    if (!_client) {
        if (!process.env.DEEPSEEK_API_KEY) {
            throw new Error(
                'DEEPSEEK_API_KEY is not set.\n' +
                'Get a key at https://platform.deepseek.com and set it in your environment:\n' +
                '  export DEEPSEEK_API_KEY=sk-...'
            );
        }
        _client = new OpenAI({
            apiKey:  process.env.DEEPSEEK_API_KEY,
            baseURL: 'https://api.deepseek.com',
        });
    }
    return _client;
}

/**
 * Ask DeepSeek to explain vulnerabilities and produce a remediation plan.
 *
 * @param {object[]} components  - enriched components from the pipeline
 * @param {string}   projectName - used in the prompt for context
 * @returns {Promise<string>}    - plain-English explanation + remediation steps
 */
async function explainVulnerabilities(components, projectName) {
    const vulnComponents = components.filter(c => c.vulnerabilities?.length);
    if (!vulnComponents.length) return null;

    // Build a compact summary: only what the model needs
    const vulnSummary = vulnComponents.map(c => {
        const vulns = c.vulnerabilities.map(v =>
            `  - ${v.id}  severity=${v.severity ?? 'unknown'}` +
            (v.cvss   ? `  CVSS=${v.cvss}`       : '') +
            (v.fixedIn?.[0] ? `  fix=${v.fixedIn[0]}` : '  no-fix-available') +
            (v.summary ? `\n    ${v.summary}`    : '')
        ).join('\n');

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
2. A prioritised remediation plan — order upgrades by impact (most vulns fixed per change first). For each:
   - Package to upgrade, current version → recommended version
   - Which CVEs / OSV IDs it resolves
   - Any blocker (e.g. another package pins this version)
3. If any vulnerabilities have no fix available, say so and suggest a mitigation.

Be concise and actionable. No boilerplate. Write as if briefing a senior developer.`;

    const response = await getClient().chat.completions.create({
        model:       'deepseek-chat',
        messages:    [{ role: 'user', content: prompt }],
        temperature: 0.2,
        max_tokens:  1024,
    });

    return response.choices[0].message.content.trim();
}

/**
 * Explain vulnerabilities from raw DB rows (used by the API endpoint).
 *
 * @param {object[]} vulnRows   - rows from DB: { name, version, ecosystem, osv_id, severity, cvss_score, fixed_version, title }
 * @param {string}   appName
 * @returns {Promise<string>}
 */
async function explainVulnRows(vulnRows, appName) {
    if (!vulnRows.length) return null;

    // Group by component
    const byComp = new Map();
    for (const r of vulnRows) {
        const key = `${r.name}@${r.version}`;
        if (!byComp.has(key)) byComp.set(key, { ...r, vulns: [] });
        byComp.get(key).vulns.push(r);
    }

    const vulnSummary = [...byComp.values()].map(c => {
        const vulns = c.vulns.map(v =>
            `  - ${v.osv_id}  severity=${v.severity ?? 'unknown'}` +
            (v.cvss_score   ? `  CVSS=${v.cvss_score}`     : '') +
            (v.fixed_version ? `  fix=${v.fixed_version}`   : '  no-fix-available') +
            (v.title         ? `\n    ${v.title}`           : '')
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
2. A prioritised remediation plan — order upgrades by impact (most vulns fixed per change first). For each:
   - Package to upgrade, current version → recommended version
   - Which CVEs / OSV IDs it resolves
   - Any blocker (e.g. another package pins this version)
3. If any vulnerabilities have no fix available, say so and suggest a mitigation.

Be concise and actionable. No boilerplate. Write as if briefing a senior developer.`;

    const response = await getClient().chat.completions.create({
        model:       'deepseek-chat',
        messages:    [{ role: 'user', content: prompt }],
        temperature: 0.2,
        max_tokens:  1024,
    });

    return response.choices[0].message.content.trim();
}

module.exports = { explainVulnerabilities, explainVulnRows };
