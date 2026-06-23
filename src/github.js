'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

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

    const remoteUrl = opts.token
        ? `https://${opts.token}@github.com/${owner}/${repo}.git`
        : `https://github.com/${owner}/${repo}.git`;

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), `packrai-${repo}-`));

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
    });

    if (result.status !== 0) {
        try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
        const stderr = (result.stderr || result.stdout || '').trim();

        if (stderr.includes('not found') || stderr.includes('Repository not found')) {
            throw new Error(`Repository not found: ${owner}/${repo}`);
        }
        if (stderr.includes('Remote branch') && stderr.includes('not found')) {
            throw new Error(`Ref '${ref}' not found in ${owner}/${repo}`);
        }
        throw new Error(`git clone failed: ${stderr}`);
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

module.exports = { parseGitHubTarget, isGitHubTarget, cloneRepo };
