'use strict';

require('dotenv').config();
const crypto    = require('crypto');
const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const db        = require('./db');
const { validateCycloneDX } = require('../generators/cyclonedx');

// ── Startup guard ─────────────────────────────────────────────────────────────
if (!process.env.HMAC_SECRET) {
    console.error('[packrai] HMAC_SECRET env var is required. Generate one with:\n' +
        '  node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
    process.exit(1);
}

const app = express();

// ── Security headers ──────────────────────────────────────────────────────────
app.use(helmet());
app.disable('x-powered-by');

// ── CORS ──────────────────────────────────────────────────────────────────────
// Only enabled when CORS_ORIGIN is explicitly set (browser dashboard use).
// Server-to-server calls (CI, CLI) do not need CORS headers.
if (process.env.CORS_ORIGIN) {
    app.use(cors({
        origin: process.env.CORS_ORIGIN,
        methods: ['GET', 'POST', 'DELETE'],
        allowedHeaders: ['Authorization', 'Content-Type'],
        credentials: true,
    }));
}

// ── Body parser ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));

// ── Rate limiting ─────────────────────────────────────────────────────────────
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests' },
});
const ingestLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Ingest rate limit exceeded' },
});

app.use('/api/', apiLimiter);

// ── API key helpers ───────────────────────────────────────────────────────────
function hashApiKey(key) {
    return crypto.createHmac('sha256', process.env.HMAC_SECRET).update(key).digest('hex');
}

function generateApiKey() {
    return crypto.randomBytes(32).toString('hex');
}

// ── Auth middleware factory ───────────────────────────────────────────────────
// requireScope(scope) returns an Express middleware that:
//   1. Checks the api_keys table (scoped, rotatable keys)
//   2. Falls back to organizations.api_key (legacy org:admin key)
//   3. Enforces the required scope unless the key has org:admin
//
// Scopes:
//   sbom:ingest  — POST /api/v1/ingest
//   sbom:read    — GET  apps, search, report
//   org:admin    — all of the above + key management
function requireScope(scope) {
    return async (req, res, next) => {
        const header = req.headers.authorization || '';
        const key = header.startsWith('Bearer ') ? header.slice(7) : null;
        if (!key) return res.status(401).json({ error: 'Missing Authorization header' });

        try {
            const keyHash = hashApiKey(key);

            // 1. Check scoped api_keys table
            const { rows: keyRows } = await db.query(
                `SELECT k.org_id, k.scopes, o.name AS org_name
                 FROM api_keys k
                 JOIN organizations o ON o.id = k.org_id
                 WHERE k.key_hash = $1 AND k.revoked_at IS NULL`,
                [keyHash]
            );

            if (keyRows.length) {
                const { org_id, scopes, org_name } = keyRows[0];
                if (!scopes.includes(scope) && !scopes.includes('org:admin')) {
                    return res.status(403).json({
                        error: `Scope '${scope}' required`,
                        hint: `This key has scopes: ${scopes.join(', ')}`,
                    });
                }
                req.org = { id: org_id, name: org_name };
                // Update last_used_at async — don't block the request
                db.query('UPDATE api_keys SET last_used_at = NOW() WHERE key_hash = $1', [keyHash])
                    .catch(() => {});
                return next();
            }

            // 2. Legacy fallback: organizations.api_key (treated as org:admin)
            const { rows: orgRows } = await db.query(
                'SELECT id, name FROM organizations WHERE api_key = $1',
                [keyHash]
            );
            if (orgRows.length) {
                req.org = orgRows[0];
                return next();
            }

            return res.status(401).json({ error: 'Invalid API key' });
        } catch (err) {
            console.error('[auth]', err.message);
            res.status(500).json({ error: 'Internal server error' });
        }
    };
}

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => res.json({ ok: true }));

// ── Ingest ────────────────────────────────────────────────────────────────────
// POST /api/v1/ingest
// Body: { app, version, commit, branch, cyclonedx, spdx, stats }
app.post('/api/v1/ingest', ingestLimiter, requireScope('sbom:ingest'), async (req, res) => {
    const { app: appName, version, commit, branch, cyclonedx, spdx, stats } = req.body;

    // ── Input validation ──────────────────────────────────────────────────────
    if (!appName || typeof appName !== 'string') {
        return res.status(400).json({ error: 'app must be a non-empty string' });
    }
    if (appName.length > 200) {
        return res.status(400).json({ error: 'app name must be 200 characters or fewer' });
    }
    if (!cyclonedx || typeof cyclonedx !== 'object') {
        return res.status(400).json({ error: 'cyclonedx must be an object' });
    }
    const cdxCheck = validateCycloneDX(cyclonedx);
    if (!cdxCheck.valid) {
        return res.status(400).json({ error: 'Invalid CycloneDX document', details: cdxCheck.errors });
    }
    if (version  !== undefined && (typeof version  !== 'string' || version.length  > 100)) {
        return res.status(400).json({ error: 'version must be a string ≤ 100 characters' });
    }
    if (commit   !== undefined && (typeof commit   !== 'string' || commit.length   > 64)) {
        return res.status(400).json({ error: 'commit must be a string ≤ 64 characters' });
    }
    if (branch   !== undefined && (typeof branch   !== 'string' || branch.length   > 250)) {
        return res.status(400).json({ error: 'branch must be a string ≤ 250 characters' });
    }
    if (stats !== undefined) {
        if (typeof stats !== 'object' || Array.isArray(stats)) {
            return res.status(400).json({ error: 'stats must be an object' });
        }
        if (stats.totalComponents !== undefined && (typeof stats.totalComponents !== 'number' || stats.totalComponents < 0)) {
            return res.status(400).json({ error: 'stats.totalComponents must be a non-negative number' });
        }
        if (stats.critical !== undefined && (typeof stats.critical !== 'number' || stats.critical < 0)) {
            return res.status(400).json({ error: 'stats.critical must be a non-negative number' });
        }
    }

    try {
        const sbomId = await db.tx(async (client) => {
            // Upsert application
            const appRes = await client.query(
                `INSERT INTO applications (org_id, name)
                 VALUES ($1, $2)
                 ON CONFLICT (org_id, name) DO UPDATE SET name = EXCLUDED.name
                 RETURNING id`,
                [req.org.id, appName]
            );
            const appId = appRes.rows[0].id;

            // Insert SBOM record
            const sbomRes = await client.query(
                `INSERT INTO sboms
                   (app_id, org_id, version, commit_sha, branch, cyclonedx, spdx,
                    component_count, vulnerability_count, critical_count,
                    quality_score, ecosystems, elapsed_ms, generated_at)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW())
                 RETURNING id`,
                [
                    appId, req.org.id, version, commit, branch,
                    cyclonedx, spdx || null,
                    stats?.totalComponents ?? 0,
                    stats?.vulnerabilities ?? 0,
                    stats?.critical ?? 0,
                    stats?.qualityScore ?? null,
                    stats?.ecosystems ?? [],
                    stats?.elapsedMs ?? null,
                ]
            );
            const sbomId = sbomRes.rows[0].id;

            // Direct dependency set: components in the root's dependsOn list
            const rootPurl    = cyclonedx.metadata?.component?.purl;
            const directPurls = new Set(
                cyclonedx.dependencies
                    ?.find(d => d.ref === rootPurl)
                    ?.dependsOn ?? []
            );

            const components = cyclonedx.components.filter(c => c.purl);
            if (!components.length) return sbomId;

            // ── Bulk upsert components ────────────────────────────────────────
            // Single query instead of N round-trips. RETURNING gives us purl→id.
            const purls      = components.map(c => c.purl);
            const names      = components.map(c => c.name);
            const versions   = components.map(c => c.version);
            const ecosystems = components.map(c =>
                c.purl.split(':')[1]?.split('/')[0] ?? 'unknown');
            const licenses   = components.map(c =>
                c.licenses?.[0]?.license?.id || c.licenses?.[0]?.license?.name || null);

            const { rows: compRows } = await client.query(
                `INSERT INTO components (org_id, purl, name, version, ecosystem, license)
                 SELECT $1, t.purl, t.name, t.version, t.ecosystem, t.license
                 FROM UNNEST($2::text[], $3::text[], $4::text[], $5::text[], $6::text[])
                      AS t(purl, name, version, ecosystem, license)
                 ON CONFLICT (org_id, purl) DO UPDATE
                   SET license = COALESCE(EXCLUDED.license, components.license)
                 RETURNING purl, id`,
                [req.org.id, purls, names, versions, ecosystems, licenses]
            );

            const purlToCompId = new Map(compRows.map(r => [r.purl, r.id]));

            // ── Bulk insert sbom_components ───────────────────────────────────
            const compIds   = components.map(c => purlToCompId.get(c.purl)).filter(Boolean);
            const scopeVals = components.map(c => c.scope ?? 'required');
            const directs   = components.map(c => directPurls.has(c.purl));

            await client.query(
                `INSERT INTO sbom_components (sbom_id, component_id, scope, is_direct)
                 SELECT $1, t.comp_id, t.scope, t.is_direct
                 FROM UNNEST($2::uuid[], $3::text[], $4::boolean[])
                      AS t(comp_id, scope, is_direct)
                 ON CONFLICT DO NOTHING`,
                [sbomId, compIds, scopeVals, directs]
            );

            // ── Vulnerabilities (CycloneDX 1.6 top-level array) ───────────────
            for (const v of (cyclonedx.vulnerabilities || [])) {
                const osvId  = v.id;
                const cveId  = v.advisories?.find(a => a.title?.startsWith('CVE-'))?.title
                            || (osvId?.startsWith('CVE-') ? osvId : null);
                const rating = v.ratings?.[0];

                for (const affected of (v.affects || [])) {
                    const compId = purlToCompId.get(affected.ref);
                    if (!compId) continue;

                    await client.query(
                        `INSERT INTO vulnerabilities
                           (component_id, org_id, osv_id, cve_id, severity, cvss_score, fixed_version, title)
                         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
                         ON CONFLICT (component_id, osv_id) DO UPDATE
                           SET severity     = EXCLUDED.severity,
                               cvss_score   = EXCLUDED.cvss_score,
                               last_checked = NOW()`,
                        [compId, req.org.id, osvId, cveId,
                         rating?.severity?.toUpperCase() ?? null,
                         rating?.score ?? null,
                         null,
                         v.description || null]
                    );
                }
            }

            return sbomId;
        });

        res.status(201).json({ sbomId });
    } catch (err) {
        console.error('[ingest]', err.message);
        res.status(500).json({ error: 'Ingest failed' });
    }
});

// ── Apps ──────────────────────────────────────────────────────────────────────
app.get('/api/v1/apps', requireScope('sbom:read'), async (req, res) => {
    try {
        const { rows } = await db.query(
            `SELECT a.id, a.name, a.repo_url,
                    COUNT(s.id) AS sbom_count,
                    MAX(s.created_at) AS last_scanned,
                    (SELECT critical_count FROM sboms WHERE app_id = a.id
                     ORDER BY created_at DESC LIMIT 1) AS critical_count
             FROM applications a
             LEFT JOIN sboms s ON s.app_id = a.id
             WHERE a.org_id = $1
             GROUP BY a.id ORDER BY a.name`,
            [req.org.id]
        );
        res.json({ apps: rows });
    } catch (err) {
        console.error('[apps]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/v1/apps/:name/sbom', requireScope('sbom:read'), async (req, res) => {
    try {
        const { rows } = await db.query(
            `SELECT s.id, s.version, s.commit_sha, s.branch, s.component_count,
                    s.vulnerability_count, s.critical_count, s.quality_score,
                    s.ecosystems, s.elapsed_ms, s.created_at
             FROM sboms s
             JOIN applications a ON a.id = s.app_id
             WHERE a.org_id = $1 AND a.name = $2
             ORDER BY s.created_at DESC LIMIT 1`,
            [req.org.id, req.params.name]
        );
        if (!rows.length) return res.status(404).json({ error: 'App not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('[apps/sbom]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ── CVE Search ────────────────────────────────────────────────────────────────
app.get('/api/v1/search', requireScope('sbom:read'), async (req, res) => {
    const { cve, osv } = req.query;
    const id = cve || osv;
    if (!id) return res.status(400).json({ error: 'Provide ?cve= or ?osv= parameter' });

    try {
        const { rows } = await db.query(
            `WITH latest AS (
               SELECT DISTINCT ON (app_id) id AS sbom_id, app_id, version, created_at
               FROM sboms WHERE org_id = $1
               ORDER BY app_id, created_at DESC
             )
             SELECT
               a.name           AS app,
               l.version        AS app_version,
               l.created_at     AS last_scanned,
               c.purl,
               c.name           AS component,
               c.version        AS component_version,
               v.osv_id, v.cve_id, v.severity, v.cvss_score, v.fixed_version, v.title
             FROM vulnerabilities v
             JOIN components c       ON c.id = v.component_id
             JOIN sbom_components sc ON sc.component_id = c.id
             JOIN latest l           ON l.sbom_id = sc.sbom_id
             JOIN applications a     ON a.id = l.app_id
             WHERE v.org_id = $1 AND (v.cve_id = $2 OR v.osv_id = $2)
             ORDER BY v.cvss_score DESC NULLS LAST, a.name`,
            [req.org.id, id]
        );
        res.json({ query: id, exposedApps: rows.length, results: rows });
    } catch (err) {
        console.error('[search]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ── Risk Report ───────────────────────────────────────────────────────────────
app.get('/api/v1/report', requireScope('sbom:read'), async (req, res) => {
    try {
        const [topVulns, topApps, summary] = await Promise.all([
            db.query(
                `WITH latest_sboms AS (
                   SELECT DISTINCT ON (app_id) id AS sbom_id
                   FROM sboms WHERE org_id = $1 ORDER BY app_id, created_at DESC
                 )
                 SELECT v.cve_id, v.osv_id, v.severity, v.cvss_score, v.title,
                        COUNT(DISTINCT a.id) AS apps_affected
                 FROM vulnerabilities v
                 JOIN components c       ON c.id = v.component_id
                 JOIN sbom_components sc ON sc.component_id = c.id
                 JOIN latest_sboms ls    ON ls.sbom_id = sc.sbom_id
                 JOIN sboms s            ON s.id = ls.sbom_id
                 JOIN applications a     ON a.id = s.app_id
                 WHERE v.org_id = $1 AND v.severity IN ('CRITICAL','HIGH')
                 GROUP BY v.cve_id, v.osv_id, v.severity, v.cvss_score, v.title
                 ORDER BY v.cvss_score DESC NULLS LAST, apps_affected DESC
                 LIMIT 10`,
                [req.org.id]
            ),
            db.query(
                `SELECT a.name, s.critical_count, s.vulnerability_count,
                        s.component_count, s.quality_score, s.created_at
                 FROM applications a
                 JOIN LATERAL (
                   SELECT * FROM sboms WHERE app_id = a.id ORDER BY created_at DESC LIMIT 1
                 ) s ON TRUE
                 WHERE a.org_id = $1
                 ORDER BY s.critical_count DESC, s.vulnerability_count DESC LIMIT 10`,
                [req.org.id]
            ),
            db.query(
                `SELECT
                   COUNT(DISTINCT a.id)  AS total_apps,
                   COUNT(DISTINCT c.id)  AS unique_components,
                   COUNT(DISTINCT v.id)  AS total_vulnerabilities,
                   SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical,
                   SUM(CASE WHEN v.severity = 'HIGH'     THEN 1 ELSE 0 END) AS high
                 FROM applications a
                 LEFT JOIN sboms s           ON s.app_id = a.id
                 LEFT JOIN sbom_components sc ON sc.sbom_id = s.id
                 LEFT JOIN components c      ON c.id = sc.component_id
                 LEFT JOIN vulnerabilities v ON v.component_id = c.id
                 WHERE a.org_id = $1`,
                [req.org.id]
            ),
        ]);

        res.json({
            summary: summary.rows[0],
            topVulnerabilities: topVulns.rows,
            mostExposedApps: topApps.rows,
        });
    } catch (err) {
        console.error('[report]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ── Key management ────────────────────────────────────────────────────────────
// POST /api/v1/keys
// Create a scoped API key for the authenticated org. Requires org:admin.
// Body: { name, scopes }  — scopes defaults to ["sbom:ingest","sbom:read"]
app.post('/api/v1/keys', requireScope('org:admin'), async (req, res) => {
    const VALID_SCOPES = new Set(['sbom:ingest', 'sbom:read', 'org:admin']);
    const rawName = req.body.name;
    const name    = (typeof rawName === 'string' && rawName.trim()) ? rawName.trim() : 'default';
    const scopes  = req.body.scopes ?? ['sbom:ingest', 'sbom:read'];

    if (rawName !== undefined && (typeof rawName !== 'string' || rawName.length > 100)) {
        return res.status(400).json({ error: 'name must be a string ≤ 100 characters' });
    }
    if (!Array.isArray(scopes) || scopes.length === 0 || !scopes.every(s => VALID_SCOPES.has(s))) {
        return res.status(400).json({
            error: 'Invalid scopes',
            valid: [...VALID_SCOPES],
        });
    }

    try {
        const apiKey  = generateApiKey();
        const keyHash = hashApiKey(apiKey);

        const { rows } = await db.query(
            `INSERT INTO api_keys (org_id, name, key_hash, scopes)
             VALUES ($1, $2, $3, $4)
             RETURNING id, name, scopes, created_at`,
            [req.org.id, name, keyHash, scopes]
        );
        // Plaintext key shown once — caller must store it securely.
        res.status(201).json({ ...rows[0], api_key: apiKey });
    } catch (err) {
        console.error('[keys/create]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/v1/keys  — list all active keys for the org (no plaintext)
app.get('/api/v1/keys', requireScope('org:admin'), async (req, res) => {
    try {
        const { rows } = await db.query(
            `SELECT id, name, scopes, created_at, last_used_at
             FROM api_keys
             WHERE org_id = $1 AND revoked_at IS NULL
             ORDER BY created_at`,
            [req.org.id]
        );
        res.json({ keys: rows });
    } catch (err) {
        console.error('[keys/list]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// DELETE /api/v1/keys/:id  — revoke a key
app.delete('/api/v1/keys/:id', requireScope('org:admin'), async (req, res) => {
    try {
        const { rowCount } = await db.query(
            `UPDATE api_keys SET revoked_at = NOW()
             WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL`,
            [req.params.id, req.org.id]
        );
        if (!rowCount) return res.status(404).json({ error: 'Key not found' });
        res.json({ revoked: true });
    } catch (err) {
        console.error('[keys/revoke]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ── Org provisioning (admin key only) ────────────────────────────────────────
// POST /api/v1/orgs   body: { name }
// Protected by ADMIN_KEY — never expose on the public internet.
// Issues an org:admin key stored in organizations.api_key (legacy slot).
app.post('/api/v1/orgs', async (req, res) => {
    const adminKey = req.headers['x-admin-key'];
    if (!adminKey || adminKey !== process.env.ADMIN_KEY) {
        return res.status(403).json({ error: 'Forbidden' });
    }

    const { name } = req.body;
    if (!name || typeof name !== 'string' || !name.trim()) {
        return res.status(400).json({ error: 'name must be a non-empty string' });
    }
    if (name.length > 200) {
        return res.status(400).json({ error: 'name must be 200 characters or fewer' });
    }

    try {
        const apiKey     = generateApiKey();
        const apiKeyHash = hashApiKey(apiKey);

        const { rows } = await db.query(
            'INSERT INTO organizations (name, api_key) VALUES ($1, $2) RETURNING id, name',
            [name, apiKeyHash]
        );
        // Return plaintext key once — caller must store it.
        res.status(201).json({ ...rows[0], api_key: apiKey });
    } catch (err) {
        console.error('[orgs]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3080;
app.listen(PORT, () => {
    process.stdout.write(`PackrAI API listening on :${PORT}\n`);
});

module.exports = app;
