#!/usr/bin/env node
'use strict';

/**
 * Benchmark PackrAI against Syft and Trivy on one or more public repos.
 *
 * Usage:
 *   node scripts/benchmark.js                        # default targets
 *   node scripts/benchmark.js expressjs/express      # single target
 *   node scripts/benchmark.js repo1 repo2 repo3      # multiple targets
 *
 * Syft and Trivy are skipped if not installed — only PackrAI is required.
 */

const { spawnSync } = require('child_process');
const path          = require('path');
const os            = require('os');
const fs            = require('fs');

const PACKRAI = path.join(__dirname, '..', 'bin', 'packrai.js');

const DEFAULT_TARGETS = [
    'expressjs/express',
    'pallets/flask',
    'tokio-rs/tokio',
];

function commandAvailable(cmd) {
    const r = spawnSync(cmd, ['--version'], { stdio: 'pipe' });
    return r.status === 0;
}

function timeTool(name, argv, timeout = 120_000) {
    const start = Date.now();
    const r = spawnSync(argv[0], argv.slice(1), { stdio: 'pipe', timeout });
    const elapsed = Date.now() - start;
    const failed  = r.status !== 0 && r.status !== null;
    return { name, elapsed, error: failed ? (r.stderr?.toString().slice(0, 120) || 'exit ' + r.status) : null };
}

function bar(ms, scale = 100) {
    return '█'.repeat(Math.max(1, Math.round(ms / scale)));
}

function pad(s, n) { return String(s).padEnd(n); }
function rpad(s, n) { return String(s).padStart(n); }

const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'packrai-bench-'));

async function benchTarget(target) {
    console.log(`\n  Target: ${target}`);
    console.log(`  ${'─'.repeat(60)}`);

    const results = [];

    // PackrAI
    results.push(timeTool('PackrAI', [
        'node', PACKRAI, target,
        '--no-vulns', '--no-licenses',
        '--out', outDir,
    ]));

    // Syft
    if (commandAvailable('syft')) {
        results.push(timeTool('Syft', [
            'syft', `github.com/${target}`,
            '-o', `cyclonedx-json=${path.join(outDir, 'syft.json')}`,
            '-q',
        ]));
    } else {
        results.push({ name: 'Syft', elapsed: null, error: 'not installed' });
    }

    // Trivy
    if (commandAvailable('trivy')) {
        results.push(timeTool('Trivy', [
            'trivy', 'repo', `https://github.com/${target}`,
            '--format', 'cyclonedx',
            '--output', path.join(outDir, 'trivy.json'),
            '--quiet',
        ], 300_000));
    } else {
        results.push({ name: 'Trivy', elapsed: null, error: 'not installed' });
    }

    const valid = results.filter(r => r.elapsed !== null && !r.error);
    const fastest = valid.length ? Math.min(...valid.map(r => r.elapsed)) : 1;

    for (const r of results) {
        if (r.elapsed === null) {
            console.log(`    ${pad(r.name, 10)}  —  ${r.error}`);
        } else if (r.error) {
            console.log(`    ${pad(r.name, 10)}  ${rpad(r.elapsed + 'ms', 9)}  error: ${r.error}`);
        } else {
            const speedup = r.elapsed === fastest ? ' ← fastest' : ` (${(r.elapsed / fastest).toFixed(1)}×)`;
            console.log(`    ${pad(r.name, 10)}  ${rpad(r.elapsed + 'ms', 9)}  ${bar(r.elapsed)}${speedup}`);
        }
    }
}

const targets = process.argv.slice(2).length ? process.argv.slice(2) : DEFAULT_TARGETS;

console.log('\n  PackrAI Benchmark');
console.log(`  node ${process.version}  ·  ${new Date().toISOString().slice(0, 10)}`);

(async () => {
    for (const t of targets) await benchTarget(t);
    console.log('');
    fs.rmSync(outDir, { recursive: true, force: true });
})().catch(err => { console.error(err); process.exit(1); });
