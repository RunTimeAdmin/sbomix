'use strict';

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs   = require('node:fs');
const os   = require('node:os');
const path = require('node:path');

const { createComponent } = require('../src/component');
const { scanSigningSurface, scanEnvForSigningKeyNames } = require('../src/signingSurface');
const { checkKnownBad, levenshtein, KNOWN_BAD } = require('../src/knownBad');
const { buildAgentTrustReport, canonicalSha256 } = require('../src/agentTrustReport');
const { detectAgenticContext } = require('../src/parsers/agentic');

// ── signingSurface ────────────────────────────────────────────────────────────

describe('signingSurface', () => {
    test('flags a known wallet/signing package', () => {
        const comps = [
            createComponent({ name: 'ethers', version: '6.13.0', ecosystem: 'npm' }),
            createComponent({ name: 'left-pad', version: '1.3.0', ecosystem: 'npm' }),
        ];
        const { matches, hasSigningSurface } = scanSigningSurface(comps);
        assert.equal(hasSigningSurface, true);
        assert.equal(matches.length, 1);
        assert.equal(matches[0].name, 'ethers');
        assert.equal(matches[0].category, 'evm');
    });

    test('no matches when no signing libraries present', () => {
        const comps = [createComponent({ name: 'express', version: '4.18.2', ecosystem: 'npm' })];
        const { hasSigningSurface } = scanSigningSurface(comps);
        assert.equal(hasSigningSurface, false);
    });

    test('pypi match is normalized (underscore/hyphen, case-insensitive)', () => {
        const comps = [createComponent({ name: 'Eth_Account', version: '0.11.0', ecosystem: 'pypi' })];
        const { matches } = scanSigningSurface(comps);
        assert.equal(matches.length, 1);
        assert.equal(matches[0].category, 'evm');
    });

    test('derives direct vs transitive from the CycloneDX dependency graph', () => {
        const rootPurl = 'app-test';
        const comps = [
            createComponent({ name: 'ethers', version: '6.13.0', ecosystem: 'npm' }),
            createComponent({ name: '@solana/web3.js', version: '1.95.0', ecosystem: 'npm' }),
        ];
        const cyclonedx = {
            metadata: { component: { purl: rootPurl } },
            dependencies: [{ ref: rootPurl, dependsOn: [comps[0].purl] }],
        };
        const { matches } = scanSigningSurface(comps, cyclonedx);
        const byName = Object.fromEntries(matches.map((m) => [m.name, m.directness]));
        assert.equal(byName['ethers'], 'direct');
        assert.equal(byName['@solana/web3.js'], 'transitive');
    });

    test('env scan captures variable names only, never values', () => {
        const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sbomix-signing-'));
        try {
            fs.writeFileSync(path.join(root, '.env'), 'PRIVATE_KEY=0xsupersecretvalue\nPORT=3000\nWALLET_MNEMONIC=word1 word2 word3\n');
            const hits = scanEnvForSigningKeyNames(root);
            const names = hits.map((h) => h.variable).sort();
            assert.deepEqual(names, ['PRIVATE_KEY', 'WALLET_MNEMONIC']);
            assert.equal(names.includes('PORT'), false);
            // The secret value must never appear anywhere in the result.
            assert.equal(JSON.stringify(hits).includes('supersecretvalue'), false);
        } finally {
            fs.rmSync(root, { recursive: true, force: true });
        }
    });
});

// ── knownBad ──────────────────────────────────────────────────────────────────

describe('knownBad', () => {
    test('ships with an empty seed list (curation, not invention)', () => {
        assert.deepEqual(KNOWN_BAD, []);
    });

    test('typosquat check flags a near-miss of a known package name', () => {
        // 'ethars' is one substitution from 'ethers' (edit distance 1).
        const comps = [createComponent({ name: 'ethars', version: '1.0.0', ecosystem: 'npm' })];
        const { typosquatMatches } = checkKnownBad(comps);
        assert.equal(typosquatMatches.length >= 1, true);
        assert.equal(typosquatMatches[0].similarTo, 'ethers');
        assert.equal(typosquatMatches[0].distance, 1);
    });

    test('typosquat check does not flag the real package name', () => {
        const comps = [createComponent({ name: 'ethers', version: '6.13.0', ecosystem: 'npm' })];
        const { typosquatMatches } = checkKnownBad(comps);
        assert.equal(typosquatMatches.length, 0);
    });

    test('typosquat check does not flag unrelated names', () => {
        const comps = [createComponent({ name: 'express', version: '4.18.2', ecosystem: 'npm' })];
        const { typosquatMatches } = checkKnownBad(comps);
        assert.equal(typosquatMatches.length, 0);
    });

    test('levenshtein distance is symmetric and zero for identical strings', () => {
        assert.equal(levenshtein('ethers', 'ethers'), 0);
        assert.equal(levenshtein('ethers', 'ethers-js'), levenshtein('ethers-js', 'ethers'));
    });
});

// ── agentTrustReport ──────────────────────────────────────────────────────────

describe('agentTrustReport', () => {
    function fakePipelineResult(serial) {
        const rootPurl = 'app-test';
        const comps = [createComponent({ name: 'ethers', version: '6.13.0', ecosystem: 'npm' })];
        return {
            cyclonedx: {
                serialNumber: `urn:uuid:${serial}`,
                metadata: { timestamp: new Date(Date.now() + Math.random() * 1000).toISOString(), component: { purl: rootPurl } },
                dependencies: [{ ref: rootPurl, dependsOn: [comps[0].purl] }],
                components: comps,
            },
            aiBom: {
                generatedAt: new Date(Date.now() + Math.random() * 1000).toISOString(),
                agentic: { mcpServers: [], prompts: [], boundaries: { leastAgencyScore: 100 } },
            },
            components: comps,
            stats: { ecosystems: ['npm'], aiModels: 0, aiApiProviders: 0, aiFrameworks: 0, aiThreats: 0, aiCritical: 0, aiHigh: 0 },
        };
    }

    test('same input (modulo volatile fields) produces the same manifest hash', () => {
        const meta = { name: 'test-app', version: '1.0.0', scanTarget: 'test-app' };
        const r1 = buildAgentTrustReport(fakePipelineResult('11111111-1111-1111-1111-111111111111'), meta);
        const r2 = buildAgentTrustReport(fakePipelineResult('22222222-2222-2222-2222-222222222222'), meta);

        assert.notEqual(r1.reportId, r2.reportId, 'report IDs should differ (they are not part of the integrity claim)');
        assert.equal(r1.integrity.manifestSha256, r2.integrity.manifestSha256);
        assert.equal(r1.sbom.cyclonedxSha256, r2.sbom.cyclonedxSha256);
        assert.equal(r1.aiBom.aiBomSha256, r2.aiBom.aiBomSha256);
    });

    test('a real content change changes the manifest hash', () => {
        const meta = { name: 'test-app', version: '1.0.0', scanTarget: 'test-app' };
        const base = fakePipelineResult('11111111-1111-1111-1111-111111111111');
        const changed = fakePipelineResult('11111111-1111-1111-1111-111111111111');
        changed.components.push(createComponent({ name: 'left-pad', version: '1.3.0', ecosystem: 'npm' }));

        const r1 = buildAgentTrustReport(base, meta);
        const r2 = buildAgentTrustReport(changed, meta);
        assert.notEqual(r1.integrity.manifestSha256, r2.integrity.manifestSha256);
    });

    test('signing surface and its statement are present when a match is found', () => {
        const report = buildAgentTrustReport(fakePipelineResult('33333333-3333-3333-3333-333333333333'), { name: 'x' });
        assert.equal(report.signingSurface.detected, true);
        assert.match(report.signingSurface.statement, /signing transactions/);
    });

    test('compliance section carries the non-certification disclaimer', () => {
        const report = buildAgentTrustReport(fakePipelineResult('44444444-4444-4444-4444-444444444444'), { name: 'x' });
        assert.match(report.complianceMapping.disclaimer, /not a certification/i);
    });

    test('canonicalSha256 ignores key order', () => {
        assert.equal(canonicalSha256({ a: 1, b: 2 }), canonicalSha256({ b: 2, a: 1 }));
    });
});

// ── MCP config gap: .claude/settings.json ─────────────────────────────────────

describe('agentic: .claude/settings.json detection', () => {
    let root;
    before(() => {
        root = fs.mkdtempSync(path.join(os.tmpdir(), 'sbomix-claudecfg-'));
        fs.mkdirSync(path.join(root, '.claude'), { recursive: true });
        fs.writeFileSync(path.join(root, '.claude', 'settings.json'), JSON.stringify({
            mcpServers: { probe: { command: 'npx', args: ['@example/mcp-probe@1.0.0'] } },
        }));
    });
    after(() => { fs.rmSync(root, { recursive: true, force: true }); });

    test('MCP servers declared in .claude/settings.json are detected', () => {
        const { mcpServers } = detectAgenticContext(root);
        assert.equal(mcpServers.some((s) => s.name === 'probe'), true);
    });
});
