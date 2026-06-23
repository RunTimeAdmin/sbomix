#!/usr/bin/env node
'use strict';

/**
 * End-to-end integration test for the PackrAI API.
 *
 * Prerequisites:
 *   docker compose up -d   (or npm run serve with DATABASE_URL set)
 *
 * Usage:
 *   node scripts/e2e.js [api-url]
 *   node scripts/e2e.js http://localhost:3080
 *
 * Env vars:
 *   PACKRAI_API_URL   - defaults to http://localhost:3080
 *   PACKRAI_ADMIN_KEY - defaults to value in .env or "test-admin-key"
 *
 * Exit 0 = all tests passed  |  Exit 1 = failures
 */

const path      = require('path');
const { generateFromDirectory } = require('../src/pipeline');

const API_URL   = process.argv[2] || process.env.PACKRAI_API_URL || 'http://localhost:3080';
const ADMIN_KEY = process.env.PACKRAI_ADMIN_KEY || process.env.ADMIN_KEY || 'test-admin-key';

let pass = 0;
let fail = 0;

function ok(msg)   { console.log(`  \x1b[32m✓\x1b[0m ${msg}`); pass++; }
function err(msg)  { console.log(`  \x1b[31m✗\x1b[0m ${msg}`); fail++; }
function info(msg) { console.log(`  \x1b[2m${msg}\x1b[0m`); }

async function req(method, path, body, headers = {}) {
    const res = await fetch(`${API_URL}${path}`, {
        method,
        headers: { 'Content-Type': 'application/json', ...headers },
        body: body ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    let json;
    try { json = JSON.parse(text); } catch { json = { _raw: text }; }
    return { status: res.status, body: json };
}

async function main() {
    console.log(`\n  PackrAI E2E Test`);
    console.log(`  API: ${API_URL}\n`);

    // ── 1. Health check ──────────────────────────────────────────────────────
    info('1. Health check');
    try {
        const { status, body } = await req('GET', '/health');
        status === 200 && body.ok === true
            ? ok('GET /health → 200')
            : err(`GET /health → ${status} (expected 200 ok:true), got: ${JSON.stringify(body)}`);
    } catch (e) {
        err(`GET /health threw: ${e.message} — is the API running at ${API_URL}?`);
        console.log('\n  Aborting: cannot reach API.\n');
        process.exit(1);
    }

    // ── 2. Provision an org ──────────────────────────────────────────────────
    info('2. Provision test organisation');
    const orgName = `e2e-test-${Date.now()}`;
    let apiKey;
    {
        const { status, body } = await req(
            'POST', '/api/v1/orgs',
            { name: orgName },
            { 'X-Admin-Key': ADMIN_KEY }
        );
        if (status === 201 && body.api_key) {
            ok(`POST /api/v1/orgs → 201, org: ${body.name}`);
            apiKey = body.api_key;
        } else {
            err(`POST /api/v1/orgs → ${status}: ${JSON.stringify(body)}`);
            console.log('\n  Aborting: cannot provision org (check ADMIN_KEY).\n');
            process.exit(1);
        }
    }

    const authHeader = { Authorization: `Bearer ${apiKey}` };

    // ── 3. Auth — wrong key ──────────────────────────────────────────────────
    info('3. Auth rejection');
    {
        const { status } = await req('GET', '/api/v1/apps', null, { Authorization: 'Bearer wrong-key' });
        status === 401
            ? ok('GET /api/v1/apps with bad key → 401')
            : err(`expected 401 with bad key, got ${status}`);
    }

    // ── 4. Generate SBOM from local source ───────────────────────────────────
    info('4. Generate SBOM from local directory');
    const projectDir = path.join(__dirname, '..');
    let sbomResult;
    try {
        sbomResult = await generateFromDirectory(projectDir, {
            name:     'packrai',
            version:  '0.1.0',
            vulns:    true,
            licenses: false,   // skip to keep test fast
        });
        ok(`SBOM generated: ${sbomResult.stats.totalComponents} components, ` +
           `${sbomResult.stats.ecosystems.join('+')} ecosystems`);
    } catch (e) {
        err(`SBOM generation failed: ${e.message}`);
        process.exit(1);
    }

    // ── 5. Ingest SBOM ───────────────────────────────────────────────────────
    info('5. Ingest SBOM');
    let sbomId;
    {
        const { status, body } = await req(
            'POST', '/api/v1/ingest',
            {
                app:       'packrai',
                version:   '0.1.0',
                commit:    'e2e-test',
                branch:    'main',
                cyclonedx: sbomResult.cyclonedx,
                spdx:      sbomResult.spdx,
                stats:     sbomResult.stats,
            },
            authHeader
        );
        if (status === 201 && body.sbomId) {
            ok(`POST /api/v1/ingest → 201, sbomId: ${body.sbomId}`);
            sbomId = body.sbomId;
        } else {
            err(`POST /api/v1/ingest → ${status}: ${JSON.stringify(body)}`);
        }
    }

    // ── 6. List apps ─────────────────────────────────────────────────────────
    info('6. List apps');
    {
        const { status, body } = await req('GET', '/api/v1/apps', null, authHeader);
        if (status === 200 && Array.isArray(body.apps) && body.apps.length > 0) {
            ok(`GET /api/v1/apps → 200, ${body.apps.length} app(s): ${body.apps.map(a => a.name).join(', ')}`);
        } else {
            err(`GET /api/v1/apps → ${status}: ${JSON.stringify(body)}`);
        }
    }

    // ── 7. Fetch latest SBOM for the app ─────────────────────────────────────
    info('7. Fetch latest SBOM');
    {
        const { status, body } = await req('GET', '/api/v1/apps/packrai/sbom', null, authHeader);
        if (status === 200 && body.component_count > 0) {
            ok(`GET /api/v1/apps/packrai/sbom → 200, ${body.component_count} components, quality: ${body.quality_score}`);
        } else {
            err(`GET /api/v1/apps/packrai/sbom → ${status}: ${JSON.stringify(body)}`);
        }
    }

    // ── 8. CVE search (no results expected, but endpoint must work) ──────────
    info('8. CVE search endpoint');
    {
        const { status, body } = await req('GET', '/api/v1/search?cve=CVE-2021-44228', null, authHeader);
        if (status === 200 && typeof body.exposedApps === 'number') {
            ok(`GET /api/v1/search?cve=CVE-2021-44228 → 200, ${body.exposedApps} exposed app(s)`);
        } else {
            err(`GET /api/v1/search → ${status}: ${JSON.stringify(body)}`);
        }
    }

    // ── 9. Risk report ───────────────────────────────────────────────────────
    info('9. Risk report');
    {
        const { status, body } = await req('GET', '/api/v1/report', null, authHeader);
        if (status === 200 && body.summary) {
            ok(`GET /api/v1/report → 200, ${body.summary.total_apps} app(s), ${body.summary.unique_components} components`);
        } else {
            err(`GET /api/v1/report → ${status}: ${JSON.stringify(body)}`);
        }
    }

    // ── 10. Second ingest same app (idempotency) ─────────────────────────────
    info('10. Second ingest (idempotency)');
    {
        const { status, body } = await req(
            'POST', '/api/v1/ingest',
            { app: 'packrai', version: '0.1.0-b', cyclonedx: sbomResult.cyclonedx, stats: sbomResult.stats },
            authHeader
        );
        status === 201
            ? ok('Second ingest returned 201 (upsert works)')
            : err(`Second ingest → ${status}: ${JSON.stringify(body)}`);
    }

    // ── Results ──────────────────────────────────────────────────────────────
    console.log(`\n  ${'─'.repeat(40)}`);
    if (fail === 0) {
        console.log(`  \x1b[32m✓ All ${pass} tests passed\x1b[0m\n`);
    } else {
        console.log(`  \x1b[31m✗ ${fail} test(s) failed\x1b[0m (${pass} passed)\n`);
        process.exit(1);
    }
}

main().catch((e) => {
    console.error(`  Fatal: ${e.message}`);
    process.exit(1);
});
