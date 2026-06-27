#!/usr/bin/env node
'use strict';

/**
 * Benchmark SBOMix against Syft and Trivy.
 *
 * Method: shallow-clone each target repo once, then run all three tools
 * against the same local directory so the comparison is fair (pure scan
 * speed, identical input).
 *
 * Requires Docker with anchore/syft and aquasec/trivy images pulled:
 *   docker pull anchore/syft && docker pull aquasec/trivy
 *
 * Usage:
 *   node scripts/benchmark.js [owner/repo ...]
 *   node scripts/benchmark.js                     # default targets
 */

const { spawnSync, execSync } = require('child_process');
const path = require('path');
const os   = require('os');
const fs   = require('fs');

const SBOMIX = path.join(__dirname, '..', 'bin', 'sbomix.js');

// Repos chosen because they commit their lock files
const DEFAULT_TARGETS = [
    'nestjs/nest',          // npm — large TypeScript project
    'psf/requests',         // Python — poetry.lock
    'BurntSushi/ripgrep',   // Rust — Cargo.lock
];

// ── Helpers ──────────────────────────────────────────────────────────────────

function dockerImagePresent(image) {
    const r = spawnSync('docker', ['image', 'inspect', image, '--format', '{{.Id}}'],
        { stdio: 'pipe', timeout: 5000 });
    return r.status === 0;
}

function shallowClone(owner, repo, destDir) {
    execSync(
        `git clone --depth=1 --single-branch --quiet https://github.com/${owner}/${repo}.git "${destDir}"`,
        { stdio: 'pipe', timeout: 60_000 }
    );
}

function timeTool(name, argv, timeoutMs = 180_000) {
    const start = Date.now();
    const r     = spawnSync(argv[0], argv.slice(1), { stdio: 'pipe', timeout: timeoutMs });
    const ms    = Date.now() - start;
    const failed = r.status !== 0 && r.status !== null;
    const stderr = r.stderr?.toString().trim().replace(/\n.*/s, '').slice(0, 160);
    return { name, ms, error: failed ? (stderr || `exit ${r.status}`) : null };
}

// ── Result display ────────────────────────────────────────────────────────────

function display(results) {
    const valid   = results.filter(r => !r.error && r.ms !== null);
    const fastest = valid.length ? Math.min(...valid.map(r => r.ms)) : null;
    for (const r of results) {
        if (r.ms === null) {
            console.log(`    ${pad(r.name, 12)}  —  not available`);
        } else if (r.error) {
            console.log(`    ${pad(r.name, 12)}  error: ${r.error}`);
        } else {
            const mult = fastest && r.ms > fastest
                ? `  (${(r.ms / fastest).toFixed(1)}× slower)`
                : '  ← fastest';
            const bar  = '█'.repeat(Math.max(1, Math.round(r.ms / 1000)));
            console.log(`    ${pad(r.name, 12)}  ${rpad(r.ms + 'ms', 8)}  ${bar}${mult}`);
        }
    }
}

function pad(s, n)  { return String(s).padEnd(n); }
function rpad(s, n) { return String(s).padStart(n); }

// Normalise Windows path to Docker-compatible format for volume mounts
function toDockerPath(winPath) {
    // Convert C:\foo\bar → /c/foo/bar  (required for Docker Desktop on Windows)
    return winPath.replace(/\\/g, '/').replace(/^([A-Z]):/, (_, d) => `/${d.toLowerCase()}`);
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function main() {
    const targets = process.argv.slice(2).length ? process.argv.slice(2) : DEFAULT_TARGETS;

    const hasSyft  = dockerImagePresent('anchore/syft');
    const hasTrivy = dockerImagePresent('aquasec/trivy');

    console.log(`\n  SBOMix Benchmark  —  ${new Date().toISOString().slice(0, 10)}`);
    console.log(`  node ${process.version}  |  Syft: ${hasSyft ? 'docker ✓' : 'not found'}  |  Trivy: ${hasTrivy ? 'docker ✓' : 'not found'}`);
    if (!hasSyft || !hasTrivy) {
        console.log(`  Missing images: docker pull anchore/syft && docker pull aquasec/trivy`);
    }
    console.log(`  Method: shallow clone → scan same local dir with each tool\n`);

    const allResults = [];

    for (const target of targets) {
        const [owner, repo] = target.split('/');
        const cloneDir = path.join(os.tmpdir(), `sbomix-bench-${repo}-${Date.now()}`);

        process.stdout.write(`  Cloning ${target} … `);
        try {
            shallowClone(owner, repo, cloneDir);
            console.log('done');
        } catch (e) {
            console.log(`FAILED: ${e.message.slice(0, 80)}`);
            continue;
        }

        console.log(`  ── ${target} ${'─'.repeat(Math.max(0, 52 - target.length))}`);

        const dockerMount = toDockerPath(cloneDir);
        const results = [];

        // SBOMix — local scan (no network needed, clone already done)
        results.push(timeTool('SBOMix', [
            'node', SBOMIX, cloneDir,
            '--no-vulns', '--no-licenses', '--json',
            '--out', os.tmpdir(),
        ]));

        // Syft — Docker volume mount
        if (hasSyft) {
            results.push(timeTool('Syft', [
                'docker', 'run', '--rm',
                '-v', `${dockerMount}:/repo`,
                'anchore/syft', '/repo',
                '-o', 'cyclonedx-json',
                '-q',
            ], 300_000));
        } else {
            results.push({ name: 'Syft', ms: null, error: null });
        }

        // Trivy — Docker filesystem scan
        if (hasTrivy) {
            results.push(timeTool('Trivy', [
                'docker', 'run', '--rm',
                '-v', `${dockerMount}:/repo`,
                'aquasec/trivy', 'fs', '/repo',
                '--format', 'cyclonedx',
                '--quiet', '--no-progress',
            ], 600_000));
        } else {
            results.push({ name: 'Trivy', ms: null, error: null });
        }

        display(results);
        allResults.push({ target, results });

        try { fs.rmSync(cloneDir, { recursive: true, force: true }); } catch {}
    }

    // Summary
    if (allResults.length > 1) {
        console.log(`\n  ── Summary ${'─'.repeat(47)}`);
        console.log(`    ${'Target'.padEnd(28)} ${'SBOMix'.padStart(9)} ${'Syft'.padStart(9)} ${'Trivy'.padStart(9)}`);
        for (const { target, results } of allResults) {
            const fmt = (r) => !r ? '       —' : r.error ? '   error' : rpad(r.ms + 'ms', 8);
            const [pr, sy, tr] = results;
            console.log(`    ${target.padEnd(28)} ${fmt(pr)} ${fmt(sy)} ${fmt(tr)}`);
        }
    }
    console.log('');
}

main().catch(err => { console.error(err.message); process.exit(1); });
