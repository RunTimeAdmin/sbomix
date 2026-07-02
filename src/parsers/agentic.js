'use strict';

/**
 * Agentic & operational context detection (AI BOM Pillar 4).
 *
 * Modern AI systems are not just weights — they are agents with authority. This
 * module captures the runtime scope an AI is granted, so an AI BOM can document
 * (and an auditor can review) the "Least Agency" posture per OWASP 2026 guidance:
 *
 *   • MCP server configs   — which tools/servers the model can call, and how
 *                            they authenticate.
 *   • Prompt files         — the system instructions that define core behavior
 *                            (a prompt-injection / behavior-tampering surface).
 *   • Execution boundaries — the aggregate scope of authority: filesystem reach,
 *                            shell access, network egress, tool count.
 *
 * Everything here is local and fast: config and prompt files are small and few.
 */

const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');

const SKIP_DIRS = new Set([
    'node_modules', '.git', 'vendor', 'dist', 'build',
    '__pycache__', '.venv', 'venv', '.tox', 'target', '.cache',
]);

// Files that commonly hold MCP server definitions
const MCP_CONFIG_NAMES = new Set([
    'mcp.json', '.mcp.json', 'claude_desktop_config.json',
    'mcp_config.json', 'mcp-servers.json',
]);
// Nested locations (relative path suffixes) also checked
const MCP_NESTED = [
    '.cursor/mcp.json', '.vscode/mcp.json', '.continue/config.json',
    '.claude/settings.json', '.claude/settings.local.json',
];

// System-prompt / agent-instruction files (behavior definition surface)
const PROMPT_EXACT = new Set([
    'claude.md', 'agents.md', 'agent.md', '.cursorrules', '.clinerules', '.windsurfrules',
    'system_prompt.txt', 'system_prompt.md', 'systemprompt.txt', 'system.md',
]);
const PROMPT_NESTED = ['.github/copilot-instructions.md'];
// Extension / glob-ish matches
const PROMPT_EXT = /\.(prompt|prompty)$/i;
const PROMPT_DIR = /(^|[\\/])prompts?[\\/]/i;

const MAX_PROMPT_BYTES = 256 * 1024;

// Commands that, as an MCP server entry, grant broad authority
const SHELL_COMMANDS    = new Set(['bash', 'sh', 'zsh', 'cmd', 'cmd.exe', 'powershell', 'pwsh']);
const UNPINNED_RUNNERS  = new Set(['npx', 'uvx', 'pipx', 'bunx']);
const DANGER_FLAGS      = /--?(yolo|dangerously[-\w]*|no-?confirm|allow-?all|skip-?permissions|unsafe)/i;
const BROAD_FS_ROOTS    = new Set(['/', '~', '~/', 'c:\\', 'c:/', '/home', '/users', '/etc', '/var']);

function sha256File(filePath, maxBytes = MAX_PROMPT_BYTES) {
    try {
        const fd  = fs.openSync(filePath, 'r');
        const h   = crypto.createHash('sha256');
        const buf = Buffer.allocUnsafe(64 * 1024);
        let total = 0, n;
        try {
            while ((n = fs.readSync(fd, buf, 0, buf.length, null)) > 0) {
                total += n;
                if (total > maxBytes) { h.update(buf.subarray(0, n - (total - maxBytes))); break; }
                h.update(buf.subarray(0, n));
            }
        } finally { fs.closeSync(fd); }
        return h.digest('hex');
    } catch { return null; }
}

/** Single filesystem walk collecting agentic-relevant files. */
function walkAgentic(root, maxDepth = 4) {
    const mcpFiles = [];
    const promptFiles = [];

    // Nested well-known paths checked directly (cheap, deterministic)
    for (const rel of MCP_NESTED) {
        const p = path.join(root, rel);
        if (fs.existsSync(p)) mcpFiles.push(p);
    }
    for (const rel of PROMPT_NESTED) {
        const p = path.join(root, rel);
        if (fs.existsSync(p)) promptFiles.push(p);
    }

    (function walk(dir, depth) {
        if (depth > maxDepth) return;
        let entries;
        try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
        for (const e of entries) {
            const full = path.join(dir, e.name);
            if (e.isDirectory()) {
                if (!SKIP_DIRS.has(e.name)) walk(full, depth + 1);
                continue;
            }
            const lo = e.name.toLowerCase();
            if (MCP_CONFIG_NAMES.has(lo)) mcpFiles.push(full);
            else if (PROMPT_EXACT.has(lo) || PROMPT_EXT.test(lo) || PROMPT_DIR.test(full)) {
                promptFiles.push(full);
            }
        }
    })(root, 0);

    return { mcpFiles: dedupe(mcpFiles), promptFiles: dedupe(promptFiles) };
}

function dedupe(arr) { return [...new Set(arr)]; }

/**
 * Parse an MCP config file into a normalized server list.
 * Handles both { mcpServers: {...} } and { servers: {...} } shapes.
 */
function parseMCPConfig(filePath) {
    let json;
    try { json = JSON.parse(fs.readFileSync(filePath, 'utf8')); } catch { return []; }
    const block = json.mcpServers || json.servers || {};
    const servers = [];

    for (const [name, cfg] of Object.entries(block)) {
        if (!cfg || typeof cfg !== 'object') continue;
        const command = cfg.command || (cfg.url ? '(remote)' : null);
        const args    = Array.isArray(cfg.args) ? cfg.args : [];
        const env     = cfg.env && typeof cfg.env === 'object' ? Object.keys(cfg.env) : [];
        const url     = cfg.url || null;
        const transport = url ? (cfg.type || 'http/sse') : 'stdio';

        // Auth signals: env keys that look like secrets, or a header/authorization block
        const authVars = env.filter(k => /(_API_KEY|_TOKEN|_SECRET|PASSWORD|CREDENTIAL)/i.test(k));
        const requiresAuth = authVars.length > 0 || !!cfg.headers || !!cfg.authorization;

        // Authority analysis
        const argStr   = args.join(' ');
        const isShell  = command && SHELL_COMMANDS.has(path.basename(String(command)).toLowerCase());
        const runner   = command && UNPINNED_RUNNERS.has(path.basename(String(command)).toLowerCase());
        const unpinned = runner && !args.some(a => /@[\d]/.test(a) || /==[\d]/.test(a));
        const danger   = DANGER_FLAGS.test(argStr);
        const fsRoots  = args.filter(a => BROAD_FS_ROOTS.has(String(a).toLowerCase()));
        const isFilesystem = /filesystem|@modelcontextprotocol\/server-filesystem|fs-server/i.test(name + ' ' + argStr);

        servers.push({
            name, command, args, transport, url,
            requiresAuth, authVars,
            authority: {
                shellAccess:      !!isShell,
                unpinnedSource:   !!unpinned,
                dangerFlags:      !!danger,
                broadFilesystem:  isFilesystem || fsRoots.length > 0,
                filesystemRoots:  fsRoots,
            },
            sourceFile: filePath,
        });
    }
    return servers;
}

/**
 * Detect all agentic context under a project root.
 * @returns {{ mcpServers, prompts, boundaries }}
 */
function detectAgenticContext(root, { maxDepth = 4 } = {}) {
    const { mcpFiles, promptFiles } = walkAgentic(root, maxDepth);

    const mcpServers = [];
    for (const f of mcpFiles) mcpServers.push(...parseMCPConfig(f));

    const prompts = promptFiles.map(processPromptFile);

    // Aggregate execution boundary across all MCP servers (Least Agency view)
    const boundaries = summarizeBoundaries(mcpServers);

    return { mcpServers, prompts, boundaries };
}

function summarizeBoundaries(servers) {
    const b = {
        toolServers:       servers.length,
        shellAccess:       servers.some(s => s.authority.shellAccess),
        broadFilesystem:   servers.some(s => s.authority.broadFilesystem),
        unpinnedServers:   servers.filter(s => s.authority.unpinnedSource).map(s => s.name),
        dangerFlagServers: servers.filter(s => s.authority.dangerFlags).map(s => s.name),
        remoteServers:     servers.filter(s => s.transport !== 'stdio').map(s => s.name),
        unauthenticated:   servers.filter(s => !s.requiresAuth).map(s => s.name),
    };
    // Least Agency score: starts at 100, each broad grant deducts
    let score = 100;
    if (b.shellAccess)              score -= 30;
    if (b.broadFilesystem)         score -= 25;
    score -= Math.min(20, b.unpinnedServers.length * 10);
    score -= Math.min(15, b.dangerFlagServers.length * 15);
    score -= Math.min(10, b.remoteServers.length * 5);
    b.leastAgencyScore = Math.max(0, score);
    return b;
}

function safeSize(fp) { try { return fs.statSync(fp).size; } catch { return null; } }

function processPromptFile(fp) {
    try {
        const fd  = fs.openSync(fp, 'r');
        const buf = Buffer.allocUnsafe(MAX_PROMPT_BYTES);
        let n;
        try { n = fs.readSync(fd, buf, 0, MAX_PROMPT_BYTES, 0); }
        finally { fs.closeSync(fd); }
        const h = crypto.createHash('sha256');
        h.update(buf.subarray(0, n));
        return {
            path:      fp,
            name:      path.basename(fp),
            sha256:    h.digest('hex'),
            snippet:   buf.toString('utf8', 0, Math.min(n, 400)).replace(/\s+/g, ' ').trim(),
            sizeBytes: safeSize(fp),
        };
    } catch {
        return { path: fp, name: path.basename(fp), sha256: null, snippet: '', sizeBytes: null };
    }
}

module.exports = { detectAgenticContext, parseMCPConfig, sha256File };
