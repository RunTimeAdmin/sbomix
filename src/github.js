'use strict';

const { spawnSync, execFile } = require('child_process');
const { promisify } = require('util');
const fs = require('fs');
const path = require('path');
const os = require('os');

const execFileAsync = promisify(execFile);

// Shown when the `git` binary isn't on PATH. Remote-repo scanning shells out
// to `git clone`; without git, spawn fails with ENOENT and (previously) an
// empty "git clone failed:" message. Local-directory scans need no git.
const GIT_MISSING_MSG =
    'git is required to scan a remote GitHub repo, but it was not found on your PATH.\n' +
    '  → Install git (https://git-scm.com/downloads), or scan a local directory instead:  sbomix .';

// git streams progress ("Updating files: 42%") to stderr; on failure that
// buries the real cause. Keep only the lines that explain the failure, and add
// an actionable hint for the common Windows long-path checkout error.
function gitErrorDetail(stderr) {
    const lines = String(stderr).split(/\r?\n/).map((l) => l.trim());
    let meaningful = lines.filter((l) => /^(fatal|error|warning|remote):/i.test(l));
    if (meaningful.length === 0) meaningful = lines.filter(Boolean).slice(-3);
    let msg = meaningful.join('\n');
    if (/Filename too long|unable to checkout working tree/i.test(stderr)) {
        msg += '\n  hint: this repo has file paths longer than Windows allows. Enable long paths:'
            +  '\n        git config --global core.longpaths true';
    }
    return msg;
}

/**
 * Parse a GitHub target string into { owner, repo, ref }
 *
 * Accepts:
 *   owner/repo
 *   owner/repo@v1.2.0
 *   owner/repo@main
 *   https://github.com/owner/repo
 *   https://github.com/owner/repo/tree/v1.2.0
 */
function parseGitHubTarget(str) {
    const s = str.replace(/\/+$/, '');

    // Full HTTPS URL
    if (s.startsWith('https://github.com/') || s.startsWith('http://github.com/')) {
        const parts = new URL(s).pathname.replace(/^\//, '').split('/');
        const owner = parts[0];
        const repo  = parts[1]?.replace(/\.git$/, '');
        const ref   = (parts[2] === 'tree' || parts[2] === 'blob') ? parts[3] : undefined;
        if (!owner || !repo) return null;
        return { owner, repo, ref: ref || undefined };
    }

    // owner/repo[@ref] shorthand
    const m = s.match(/^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)(?:@(.+))?$/);
    if (m) return { owner: m[1], repo: m[2], ref: m[3] || undefined };

    return null;
}

function isGitHubTarget(str) {
    return parseGitHubTarget(str) !== null;
}

/**
 * Shallow-clone a GitHub repo to a temp directory.
 * Returns { dir, cleanup } — call cleanup() when done.
 *
 * @param {{ owner, repo, ref }} target
 * @param {{ token?: string, quiet?: boolean }} opts
 */
function cloneRepo(target, opts = {}) {
    const { owner, repo, ref } = target;

    // Token is passed via GIT_CONFIG env vars — never embedded in the URL or
    // command arguments where it could leak in process lists or error messages.
    const remoteUrl = `https://github.com/${owner}/${repo}.git`;

    const spawnEnv = { ...process.env };
    if (opts.token) {
        const b64 = Buffer.from(`x-access-token:${opts.token}`).toString('base64');
        spawnEnv.GIT_CONFIG_COUNT = '1';
        spawnEnv.GIT_CONFIG_KEY_0 = 'http.https://github.com/.extraHeader';
        spawnEnv.GIT_CONFIG_VALUE_0 = `Authorization: Basic ${b64}`;
    }

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), `sbomix-${repo}-`));

    const args = ['clone', '--depth=1', '--single-branch'];
    if (ref) args.push('--branch', ref);
    args.push(remoteUrl, tmpDir);

    if (!opts.quiet) {
        process.stdout.write(`  Cloning ${owner}/${repo}${ref ? `@${ref}` : ''} …\n`);
    }

    const result = spawnSync('git', args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        encoding: 'utf8',
        timeout: 120_000,
        env: spawnEnv,
    });

    // git binary missing → spawn fails with ENOENT and status null. Catch it
    // before the generic handler, which would otherwise throw an empty message.
    if (result.error) {
        try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
        if (result.error.code === 'ENOENT') throw new Error(GIT_MISSING_MSG);
        throw new Error(`git clone failed: ${result.error.message}`);
    }

    if (result.status !== 0) {
        try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
        const stderr = (result.stderr || result.stdout || '').trim();

        if (stderr.includes('not found') || stderr.includes('Repository not found')) {
            throw new Error(`Repository not found: ${owner}/${repo}`);
        }
        if (stderr.includes('Remote branch') && stderr.includes('not found')) {
            throw new Error(`Ref '${ref}' not found in ${owner}/${repo}`);
        }
        throw new Error(`git clone of ${owner}/${repo} failed:\n${gitErrorDetail(stderr)}`);
    }

    // Resolve the exact commit SHA so we embed it in the SBOM
    const shaResult = spawnSync('git', ['-C', tmpDir, 'rev-parse', 'HEAD'], {
        stdio: ['ignore', 'pipe', 'pipe'],
        encoding: 'utf8',
    });
    const commitSha = shaResult.stdout?.trim() || undefined;

    const cleanup = () => {
        try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    };

    return { dir: tmpDir, commitSha, cleanup };
}

/**
 * Async version of cloneRepo — uses execFile so it doesn't block the event loop.
 * Used by scan workers. Accepts an AbortSignal to kill the git process immediately
 * when the job timeout fires — prevents clones from running past their deadline.
 *
 * @param {{ owner, repo, ref }} target
 * @param {{ token?: string, signal?: AbortSignal }} opts
 */
async function cloneRepoAsync(target, opts = {}) {
    const { owner, repo, ref } = target;
    const remoteUrl = `https://github.com/${owner}/${repo}.git`;

    const spawnEnv = { ...process.env };
    if (opts.token) {
        const b64 = Buffer.from(`x-access-token:${opts.token}`).toString('base64');
        spawnEnv.GIT_CONFIG_COUNT   = '1';
        spawnEnv.GIT_CONFIG_KEY_0   = 'http.https://github.com/.extraHeader';
        spawnEnv.GIT_CONFIG_VALUE_0 = `Authorization: Basic ${b64}`;
    }

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), `sbomix-${repo}-`));
    const args   = ['clone', '--depth=1', '--single-branch', '--no-tags'];
    if (ref) args.push('--branch', ref);
    args.push(remoteUrl, tmpDir);

    try {
        await execFileAsync('git', args, { env: spawnEnv, timeout: 90_000, signal: opts.signal });
    } catch (err) {
        try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
        if (err.code === 'ERR_ABORT' || err.name === 'AbortError') {
            throw new Error('Scan timed out — repository may be too large. Use the CLI for large repos.');
        }
        if (err.code === 'ENOENT') throw new Error(GIT_MISSING_MSG);
        const msg = (err.stderr || err.stdout || err.message || '').trim();
        if (msg.includes('not found') || msg.includes('Repository not found')) {
            throw new Error(`Repository not found: ${owner}/${repo}`);
        }
        if (msg.includes('Remote branch') && msg.includes('not found')) {
            throw new Error(`Ref '${ref}' not found in ${owner}/${repo}`);
        }
        if (err.killed || err.signal === 'SIGTERM') {
            throw new Error('Scan timed out — repository may be too large. Use the CLI for large repos.');
        }
        throw new Error(`Clone failed: ${msg.slice(0, 200)}`);
    }

    let commitSha;
    try {
        const { stdout } = await execFileAsync('git', ['-C', tmpDir, 'rev-parse', 'HEAD'], { timeout: 5_000 });
        commitSha = stdout.trim();
    } catch {}

    const cleanup = () => {
        try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    };

    return { dir: tmpDir, commitSha, cleanup };
}

module.exports = { parseGitHubTarget, isGitHubTarget, cloneRepo, cloneRepoAsync };
