'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { formatAiBomReport } = require('../src/aibomReport');

function result() {
    return {
        components: [
            { name: 'lodash', version: '4.17.21', ecosystem: 'npm' }, // non-AI, must be excluded
            { name: 'Anthropic API', ecosystem: 'ai', aiMetadata: { role: 'api-provider', provider: 'Anthropic', sdkPackage: 'anthropic' } },
            { name: 'PyTorch', version: '2.4.1', ecosystem: 'ai', aiMetadata: { role: 'framework' } },
            { name: 'LangChain', version: '0.3', ecosystem: 'ai', aiMetadata: { role: 'orchestration' } },
            { name: 'allenai/c4', ecosystem: 'ai', aiMetadata: { role: 'dataset' } },
        ],
        aiBom: {
            agentic: {
                mcpServers: [
                    { name: 'shell', transport: 'stdio', requiresAuth: false, authority: { shellAccess: true }, sourceFile: '/proj/.cursor/mcp.json' },
                    { name: 'github', transport: 'stdio', requiresAuth: true, authority: {}, sourceFile: '/proj/.cursor/mcp.json' },
                ],
                prompts: [{ name: 'system.prompt', path: '/proj/prompts/system.prompt' }],
                boundaries: { leastAgencyScore: 35 },
            },
        },
        aiThreats: [{ id: 'AI-009', name: 'Excessive agency', severity: 'HIGH', component: 'mcp:shell' }],
    };
}

describe('ai-bom report', () => {
    test('agent orchestration frameworks (LangChain) are not dropped', () => {
        const r = formatAiBomReport(result(), 'demo');
        assert.match(r, /LangChain/, 'orchestration framework missing — role !== "framework" was skipped');
        assert.match(r, /PyTorch/);
    });

    test('MCP servers are first-class components with authority flags', () => {
        const r = formatAiBomReport(result(), 'demo');
        assert.match(r, /MCP SERVERS \/ AGENT TOOLS \(2\)/);
        assert.match(r, /shell.*shell-exec/s, 'shell-access authority not surfaced');
        assert.match(r, /github.*auth required/s);
    });

    test('config paths are shortened to their last two segments', () => {
        const r = formatAiBomReport(result(), 'demo');
        assert.match(r, /\.cursor\/mcp\.json/);
        assert.doesNotMatch(r, /\/proj\/\.cursor/, 'absolute path leaked instead of shortPath');
    });

    test('surfaces Least Agency Score, threats, and excludes non-AI components', () => {
        const r = formatAiBomReport(result(), 'demo');
        assert.match(r, /Least Agency Score: 35\/100/);
        assert.match(r, /AI-009/);
        assert.doesNotMatch(r, /lodash/, 'non-AI component leaked into the AI-BOM');
    });

    test('empty AI surface returns a clear "nothing detected" line', () => {
        const r = formatAiBomReport({ components: [{ name: 'x', ecosystem: 'npm' }], aiBom: null, aiThreats: [] }, 'demo');
        assert.match(r, /No AI\/ML models, API providers, datasets, agents, or MCP servers detected/);
    });
});
