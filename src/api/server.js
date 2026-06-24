'use strict';

require('dotenv').config();
const crypto    = require('crypto');
const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const path      = require('path');
const db        = require('./db');
const { validateCycloneDX } = require('../generators/cyclonedx');
const { enrichWithOSV }     = require('../osv');
const { diffComponents, diffVulns } = require('../diff');
const { explainVulnRows }         = require('../explain');
const { startKEVRefresh, applyKEVAfterIngest } = require('../kev');

// ── Startup guard ─────────────────────────────────────────────────────────────
if (!process.env.HMAC_SECRET) {
    console.error('[packrai] HMAC_SECRET env var is required. Generate one with:\n' +
        '  node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
    process.exit(1);
}

const app = express();

// Deployed behind nginx; trust the first proxy so express-rate-limit
// uses the real client IP from X-Forwarded-For rather than throwing.
app.set('trust proxy', 1);

// ── Security headers ──────────────────────────────────────────────────────────
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc:  ["'self'"],
            scriptSrc:   ["'self'", "'unsafe-inline'"],   // dashboard inline scripts
            styleSrc:    ["'self'", "'unsafe-inline'"],
            connectSrc:  ["'self'"],
            imgSrc:      ["'self'", 'data:'],
            fontSrc:     ["'self'"],
            objectSrc:   ["'none'"],
            frameSrc:    ["'none'"],
        },
    },
}));
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

// Throttle last_used_at writes — one DB write per key per 5 minutes max
const lastUsedCache = new Map();
const LAST_USED_TTL = 5 * 60 * 1000;

function maybeUpdateLastUsed(keyHash) {
    const now = Date.now();
    if (now - (lastUsedCache.get(keyHash) || 0) < LAST_USED_TTL) return;
    lastUsedCache.set(keyHash, now);
    db.query('UPDATE api_keys SET last_used_at = NOW() WHERE key_hash = $1', [keyHash])
        .catch(() => {});
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
                maybeUpdateLastUsed(keyHash);
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

// ── OSV auto-enrichment ───────────────────────────────────────────────────────
// Called async after ingest when the payload contained no vulnerability data.
// Queries OSV for every component purl and stores results without blocking
// the ingest response.
async function osvEnrichAsync(orgId, cdxComponents, purlToCompId) {
    const components = cdxComponents.map(c => ({
        name:      c.name,
        version:   c.version || 'unknown',
        purl:      c.purl,
        ecosystem: c.purl.split(':')[1]?.split('/')[0] ?? 'unknown',
    }));

    await enrichWithOSV(components, { timeout: 20000 });

    const vulnRows = [];
    for (const comp of components) {
        if (!comp.vulnerabilities?.length) continue;
        const compId = purlToCompId.get(comp.purl);
        if (!compId) continue;
        for (const v of comp.vulnerabilities) {
            vulnRows.push({
                compId,
                osvId:        v.id,
                cveId:        v.aliases?.find(a => a.startsWith('CVE-')) ?? null,
                severity:     v.severity === 'UNKNOWN' ? null : v.severity,
                cvssScore:    (v.cvss && !isNaN(parseFloat(v.cvss))) ? parseFloat(v.cvss) : null,
                fixedVersion: v.fixedIn?.[0] ?? null,
                title:        v.summary || null,
            });
        }
    }

    if (vulnRows.length) {
        await db.query(
            `INSERT INTO vulnerabilities
               (component_id, org_id, osv_id, cve_id, severity, cvss_score, fixed_version, title)
             SELECT t.comp_id, $1, t.osv_id, t.cve_id, t.severity, t.cvss_score, t.fixed_version, t.title
             FROM UNNEST($2::uuid[], $3::text[], $4::text[], $5::text[], $6::numeric[], $7::text[], $8::text[])
                  AS t(comp_id, osv_id, cve_id, severity, cvss_score, fixed_version, title)
             ON CONFLICT (component_id, osv_id) DO UPDATE
               SET severity      = EXCLUDED.severity,
                   cvss_score    = COALESCE(EXCLUDED.cvss_score, vulnerabilities.cvss_score),
                   fixed_version = COALESCE(EXCLUDED.fixed_version, vulnerabilities.fixed_version),
                   last_checked  = NOW()`,
            [orgId,
             vulnRows.map(r => r.compId),
             vulnRows.map(r => r.osvId),
             vulnRows.map(r => r.cveId),
             vulnRows.map(r => r.severity),
             vulnRows.map(r => r.cvssScore),
             vulnRows.map(r => r.fixedVersion),
             vulnRows.map(r => r.title)]
        );
    }
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
app.get('/dashboard', (_req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

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
    const MAX_COMPONENTS = 10_000;
    if ((cyclonedx.components?.length ?? 0) > MAX_COMPONENTS) {
        return res.status(400).json({ error: `SBOM may not contain more than ${MAX_COMPONENTS} components` });
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
        const { sbomId, purlToCompId } = await db.tx(async (client) => {
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

            // Materialise latest-SBOM pointer so read endpoints skip DISTINCT ON / LATERAL.
            // WHERE guard prevents an out-of-order ingest from overwriting a newer row.
            await client.query(
                `INSERT INTO app_latest_sboms
                   (app_id, org_id, sbom_id, created_at,
                    component_count, vulnerability_count, critical_count, quality_score, ecosystems)
                 VALUES ($1,$2,$3,NOW(),$4,$5,$6,$7,$8)
                 ON CONFLICT (app_id) DO UPDATE
                   SET sbom_id             = EXCLUDED.sbom_id,
                       created_at          = EXCLUDED.created_at,
                       component_count     = EXCLUDED.component_count,
                       vulnerability_count = EXCLUDED.vulnerability_count,
                       critical_count      = EXCLUDED.critical_count,
                       quality_score       = EXCLUDED.quality_score,
                       ecosystems          = EXCLUDED.ecosystems
                 WHERE app_latest_sboms.created_at <= EXCLUDED.created_at`,
                [
                    appId, req.org.id, sbomId,
                    stats?.totalComponents ?? 0,
                    stats?.vulnerabilities ?? 0,
                    stats?.critical ?? 0,
                    stats?.qualityScore ?? null,
                    stats?.ecosystems ?? [],
                ]
            );

            // Direct dependency set: components in the root's dependsOn list
            const rootPurl    = cyclonedx.metadata?.component?.purl;
            const directPurls = new Set(
                cyclonedx.dependencies
                    ?.find(d => d.ref === rootPurl)
                    ?.dependsOn ?? []
            );

            const components = cyclonedx.components.filter(c => c.purl);
            if (!components.length) return { sbomId, purlToCompId: new Map() };

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
            // Build rows as objects first so compId, scope, and is_direct stay aligned
            // even if some purls are missing from the RETURNING results.
            const linkRows = components
                .map(c => ({
                    id:     purlToCompId.get(c.purl),
                    scope:  c.scope ?? 'required',
                    direct: directPurls.has(c.purl),
                }))
                .filter(r => r.id);

            if (linkRows.length) {
                await client.query(
                    `INSERT INTO sbom_components (sbom_id, component_id, scope, is_direct)
                     SELECT $1, t.comp_id, t.scope, t.is_direct
                     FROM UNNEST($2::uuid[], $3::text[], $4::boolean[])
                          AS t(comp_id, scope, is_direct)
                     ON CONFLICT DO NOTHING`,
                    [sbomId,
                     linkRows.map(r => r.id),
                     linkRows.map(r => r.scope),
                     linkRows.map(r => r.direct)]
                );
            }

            // ── Vulnerabilities (CycloneDX 1.6 top-level array) ── bulk insert ─
            const vulnRows = [];
            for (const v of (cyclonedx.vulnerabilities || [])) {
                const osvId = v.id;
                const cveId = v.advisories?.find(a => a.title?.startsWith('CVE-'))?.title
                           || (osvId?.startsWith('CVE-') ? osvId : null);
                const rating = v.ratings?.[0];
                for (const affected of (v.affects || [])) {
                    const compId = purlToCompId.get(affected.ref);
                    if (!compId) continue;
                    vulnRows.push({
                        compId, osvId, cveId,
                        severity:  rating?.severity?.toUpperCase() ?? null,
                        cvssScore: rating?.score ?? null,
                        title:     v.description || null,
                    });
                }
            }
            if (vulnRows.length) {
                await client.query(
                    `INSERT INTO vulnerabilities
                       (component_id, org_id, osv_id, cve_id, severity, cvss_score, fixed_version, title)
                     SELECT t.comp_id, $1, t.osv_id, t.cve_id, t.severity, t.cvss_score, NULL, t.title
                     FROM UNNEST($2::uuid[], $3::text[], $4::text[], $5::text[], $6::numeric[], $7::text[])
                          AS t(comp_id, osv_id, cve_id, severity, cvss_score, title)
                     ON CONFLICT (component_id, osv_id) DO UPDATE
                       SET severity     = EXCLUDED.severity,
                           cvss_score   = EXCLUDED.cvss_score,
                           last_checked = NOW()`,
                    [req.org.id,
                     vulnRows.map(r => r.compId),
                     vulnRows.map(r => r.osvId),
                     vulnRows.map(r => r.cveId),
                     vulnRows.map(r => r.severity),
                     vulnRows.map(r => r.cvssScore),
                     vulnRows.map(r => r.title)]
                );
            }

            return { sbomId, purlToCompId };
        });

        res.status(201).json({ sbomId });

        // Fire-and-forget OSV enrichment when payload had no vulnerability data
        if (!cyclonedx.vulnerabilities?.length && purlToCompId.size > 0) {
            osvEnrichAsync(req.org.id, cyclonedx.components.filter(c => c.purl), purlToCompId)
                .then(() => applyKEVAfterIngest(req.org.id))
                .catch(err => console.error('[osv-enrich]', err.message));
        } else {
            // Vulns came from the CycloneDX payload — cross-reference KEV immediately
            applyKEVAfterIngest(req.org.id);
        }
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
                    COUNT(s.id)             AS sbom_count,
                    ls.created_at           AS last_scanned,
                    ls.critical_count,
                    ls.vulnerability_count,
                    ls.component_count,
                    ls.quality_score,
                    ls.ecosystems
             FROM applications a
             LEFT JOIN sboms s             ON s.app_id = a.id
             LEFT JOIN app_latest_sboms ls ON ls.app_id = a.id
             WHERE a.org_id = $1
             GROUP BY a.id, a.name, a.repo_url, ls.created_at, ls.critical_count,
                      ls.vulnerability_count, ls.component_count, ls.quality_score, ls.ecosystems
             ORDER BY ls.critical_count DESC NULLS LAST, a.name`,
            [req.org.id]
        );
        res.json({ apps: rows });
    } catch (err) {
        console.error('[apps]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/v1/apps/:name/vulns
// Vulnerability list for the latest SBOM of an app, excluding VEX not_affected.
app.get('/api/v1/apps/:name/vulns', requireScope('sbom:read'), async (req, res) => {
    try {
        const appRes = await db.query(
            `SELECT a.id FROM applications a
             WHERE a.org_id = $1 AND a.name = $2`,
            [req.org.id, req.params.name]
        );
        if (!appRes.rows.length) return res.status(404).json({ error: 'App not found' });
        const appId = appRes.rows[0].id;

        const { rows } = await db.query(
            `SELECT v.osv_id, v.cve_id, v.severity, v.cvss_score,
                    v.fixed_version, v.title, v.kev,
                    c.id AS component_id, c.name AS component,
                    c.version AS component_version, c.ecosystem, c.purl
             FROM app_latest_sboms ls
             JOIN sbom_components sc     ON sc.sbom_id = ls.sbom_id
             JOIN components c           ON c.id = sc.component_id
             JOIN vulnerabilities v      ON v.component_id = c.id AND v.org_id = $1
             LEFT JOIN vex_statements vx ON vx.component_id = c.id
                                        AND vx.osv_id = v.osv_id AND vx.org_id = $1
             WHERE ls.app_id = $2
               AND (vx.status IS NULL OR vx.status != 'not_affected')
             ORDER BY v.cvss_score DESC NULLS LAST, v.severity, c.name`,
            [req.org.id, appId]
        );
        res.json({ vulnerabilities: rows });
    } catch (err) {
        console.error('[apps/vulns]', err.message);
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

// GET /api/v1/apps/:name/components
app.get('/api/v1/apps/:name/components', requireScope('sbom:read'), async (req, res) => {
    try {
        const appRes = await db.query(
            `SELECT a.id FROM applications a WHERE a.org_id = $1 AND a.name = $2`,
            [req.org.id, req.params.name]
        );
        if (!appRes.rows.length) return res.status(404).json({ error: 'App not found' });
        const appId = appRes.rows[0].id;

        const { rows } = await db.query(
            `SELECT c.name, c.version, c.ecosystem, c.purl,
                    COUNT(v.id) FILTER (WHERE vx.status IS NULL OR vx.status != 'not_affected') AS vuln_count,
                    MAX(v.severity) AS max_severity
             FROM app_latest_sboms ls
             JOIN sbom_components sc    ON sc.sbom_id = ls.sbom_id
             JOIN components c          ON c.id = sc.component_id
             LEFT JOIN vulnerabilities v  ON v.component_id = c.id AND v.org_id = $1
             LEFT JOIN vex_statements vx  ON vx.component_id = c.id
                                         AND vx.osv_id = v.osv_id AND vx.org_id = $1
             WHERE ls.app_id = $2
             GROUP BY c.name, c.version, c.ecosystem, c.purl
             ORDER BY vuln_count DESC, c.name`,
            [req.org.id, appId]
        );
        res.json({ components: rows });
    } catch (err) {
        console.error('[apps/components]', err.message);
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
            `SELECT
               a.name              AS app,
               s.version           AS app_version,
               ls.created_at       AS last_scanned,
               c.purl,
               c.name              AS component,
               c.version           AS component_version,
               v.osv_id, v.cve_id, v.severity, v.cvss_score, v.fixed_version, v.title,
               vx.status           AS vex_status,
               vx.justification    AS vex_justification
             FROM vulnerabilities v
             JOIN components c          ON c.id = v.component_id
             JOIN sbom_components sc    ON sc.component_id = c.id
             JOIN app_latest_sboms ls   ON ls.sbom_id = sc.sbom_id
             JOIN sboms s               ON s.id = ls.sbom_id
             JOIN applications a        ON a.id = ls.app_id
             LEFT JOIN vex_statements vx ON vx.component_id = c.id
                                        AND vx.osv_id = v.osv_id
                                        AND vx.org_id = v.org_id
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
                `SELECT v.cve_id, v.osv_id, v.severity, v.cvss_score, v.title,
                        COUNT(DISTINCT a.id) AS apps_affected
                 FROM vulnerabilities v
                 JOIN components c          ON c.id = v.component_id
                 JOIN sbom_components sc    ON sc.component_id = c.id
                 JOIN app_latest_sboms ls   ON ls.sbom_id = sc.sbom_id
                 JOIN applications a        ON a.id = ls.app_id
                 WHERE v.org_id = $1 AND v.severity IN ('CRITICAL','HIGH')
                   AND NOT EXISTS (
                     SELECT 1 FROM vex_statements vx
                     WHERE vx.component_id = v.component_id
                       AND vx.osv_id = v.osv_id
                       AND vx.org_id = v.org_id
                       AND vx.status = 'not_affected'
                   )
                 GROUP BY v.cve_id, v.osv_id, v.severity, v.cvss_score, v.title
                 ORDER BY v.cvss_score DESC NULLS LAST, apps_affected DESC
                 LIMIT 10`,
                [req.org.id]
            ),
            db.query(
                `SELECT a.name, ls.critical_count, ls.vulnerability_count,
                        ls.component_count, ls.quality_score, ls.created_at
                 FROM app_latest_sboms ls
                 JOIN applications a ON a.id = ls.app_id
                 WHERE ls.org_id = $1
                 ORDER BY ls.critical_count DESC, ls.vulnerability_count DESC
                 LIMIT 10`,
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
                 LEFT JOIN app_latest_sboms ls  ON ls.app_id = a.id
                 LEFT JOIN sbom_components sc   ON sc.sbom_id = ls.sbom_id
                 LEFT JOIN components c         ON c.id = sc.component_id
                 LEFT JOIN vulnerabilities v    ON v.component_id = c.id
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

// ── SBOM diff ─────────────────────────────────────────────────────────────────
// GET /api/v1/apps/:name/diff
// Compare the two most-recent SBOMs for an app.
// Optional ?from=<sbom_id>&to=<sbom_id> to compare specific pairs.
app.get('/api/v1/apps/:name/diff', requireScope('sbom:read'), async (req, res) => {
    try {
        // Resolve app
        const appRes = await db.query(
            `SELECT id FROM applications WHERE org_id = $1 AND name = $2`,
            [req.org.id, req.params.name]
        );
        if (!appRes.rows.length) return res.status(404).json({ error: 'App not found' });
        const appId = appRes.rows[0].id;

        // Resolve the two SBOM IDs
        let fromId = req.query.from;
        let toId   = req.query.to;

        if (!fromId || !toId) {
            const recent = await db.query(
                `SELECT id, version, created_at
                 FROM sboms WHERE app_id = $1 ORDER BY created_at DESC LIMIT 2`,
                [appId]
            );
            if (recent.rows.length < 2) {
                return res.status(409).json({ error: 'Need at least two SBOMs to diff' });
            }
            toId   = toId   || recent.rows[0].id;
            fromId = fromId || recent.rows[1].id;
        }

        // Fetch component lists for each SBOM
        const compQuery = `
            SELECT c.purl, c.name, c.version, c.ecosystem
            FROM sbom_components sc
            JOIN components c ON c.id = sc.component_id
            WHERE sc.sbom_id = $1`;

        const vulnQuery = `
            SELECT v.osv_id, v.cve_id, v.severity, c.purl AS component_purl, c.name AS component_name
            FROM vulnerabilities v
            JOIN components c       ON c.id = v.component_id
            JOIN sbom_components sc ON sc.component_id = c.id
            WHERE sc.sbom_id = $1 AND v.org_id = $2`;

        const [fromComps, toComps, fromVulns, toVulns, fromMeta, toMeta] = await Promise.all([
            db.query(compQuery, [fromId]),
            db.query(compQuery, [toId]),
            db.query(vulnQuery, [fromId, req.org.id]),
            db.query(vulnQuery, [toId,   req.org.id]),
            db.query(`SELECT id, version, created_at FROM sboms WHERE id = $1`, [fromId]),
            db.query(`SELECT id, version, created_at FROM sboms WHERE id = $1`, [toId]),
        ]);

        const compDiff = diffComponents(fromComps.rows, toComps.rows);
        const vulnDiff = diffVulns(fromVulns.rows, toVulns.rows);

        res.json({
            from:    fromMeta.rows[0],
            to:      toMeta.rows[0],
            summary: {
                ...compDiff.summary,
                newVulnerabilities:      vulnDiff.introduced.length,
                resolvedVulnerabilities: vulnDiff.resolved.length,
            },
            added:                   compDiff.added,
            removed:                 compDiff.removed,
            updated:                 compDiff.updated,
            newVulnerabilities:      vulnDiff.introduced,
            resolvedVulnerabilities: vulnDiff.resolved,
        });
    } catch (err) {
        console.error('[diff]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ── AI explain ───────────────────────────────────────────────────────────────
// POST /api/v1/apps/:name/explain
// Returns an AI-generated vulnerability summary and remediation plan.
// Requires DEEPSEEK_API_KEY to be set on the server.
app.post('/api/v1/apps/:name/explain', requireScope('sbom:read'), async (req, res) => {
    if (!process.env.DEEPSEEK_API_KEY) {
        return res.status(501).json({ error: 'AI explain is not configured on this server (DEEPSEEK_API_KEY not set)' });
    }
    try {
        const appRes = await db.query(
            `SELECT id FROM applications WHERE org_id = $1 AND name = $2`,
            [req.org.id, req.params.name]
        );
        if (!appRes.rows.length) return res.status(404).json({ error: 'App not found' });
        const appId = appRes.rows[0].id;

        // Fetch vulns from latest SBOM via app_latest_sboms
        const { rows: vulnRows } = await db.query(
            `SELECT c.name, c.version, c.ecosystem,
                    v.osv_id, v.cve_id, v.severity, v.cvss_score, v.fixed_version, v.title, v.kev
             FROM app_latest_sboms ls
             JOIN sbom_components sc ON sc.sbom_id = ls.sbom_id
             JOIN components c       ON c.id = sc.component_id
             JOIN vulnerabilities v  ON v.component_id = c.id AND v.org_id = $1
             LEFT JOIN vex_statements vx
                    ON vx.component_id = c.id AND vx.osv_id = v.osv_id AND vx.org_id = $1
             WHERE ls.app_id = $2 AND (vx.status IS NULL OR vx.status != 'not_affected')
             ORDER BY v.severity DESC NULLS LAST`,
            [req.org.id, appId]
        );

        if (!vulnRows.length) {
            return res.json({ explanation: 'No active vulnerabilities found for this app.' });
        }

        const explanation = await explainVulnRows(vulnRows, req.params.name);
        res.json({ explanation, vulnerabilityCount: vulnRows.length });
    } catch (err) {
        console.error('[explain]', err.message);
        res.status(500).json({ error: 'Explain failed' });
    }
});

// ── VEX statements ────────────────────────────────────────────────────────────
const VEX_STATUSES      = new Set(['not_affected', 'affected', 'fixed', 'under_investigation']);
const VEX_JUSTIFICATIONS = new Set([
    'component_not_present', 'vulnerable_code_not_present',
    'vulnerable_code_not_in_execute_path',
    'vulnerable_code_cannot_be_controlled_by_adversary',
    'inline_mitigations_already_exist',
]);

// POST /api/v1/vex  — create or update a VEX statement
app.post('/api/v1/vex', requireScope('sbom:ingest'), async (req, res) => {
    const { component_id, osv_id, status, justification, impact_statement } = req.body;

    if (!component_id || typeof component_id !== 'string') {
        return res.status(400).json({ error: 'component_id must be a UUID string' });
    }
    if (!osv_id || typeof osv_id !== 'string') {
        return res.status(400).json({ error: 'osv_id must be a non-empty string' });
    }
    if (!VEX_STATUSES.has(status)) {
        return res.status(400).json({ error: 'status must be one of: ' + [...VEX_STATUSES].join(', ') });
    }
    if (status === 'not_affected' && !justification) {
        return res.status(400).json({ error: 'justification is required when status is not_affected' });
    }
    if (justification && !VEX_JUSTIFICATIONS.has(justification)) {
        return res.status(400).json({ error: 'invalid justification value' });
    }
    if (impact_statement !== undefined && typeof impact_statement !== 'string') {
        return res.status(400).json({ error: 'impact_statement must be a string' });
    }

    try {
        // Verify the component belongs to this org
        const compCheck = await db.query(
            `SELECT id FROM components WHERE id = $1 AND org_id = $2`,
            [component_id, req.org.id]
        );
        if (!compCheck.rows.length) {
            return res.status(404).json({ error: 'Component not found' });
        }

        const { rows } = await db.query(
            `INSERT INTO vex_statements
               (org_id, component_id, osv_id, status, justification, impact_statement, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,NOW())
             ON CONFLICT (org_id, component_id, osv_id) DO UPDATE
               SET status           = EXCLUDED.status,
                   justification    = EXCLUDED.justification,
                   impact_statement = EXCLUDED.impact_statement,
                   updated_at       = NOW()
             RETURNING *`,
            [req.org.id, component_id, osv_id, status,
             justification || null, impact_statement || null]
        );
        res.status(201).json(rows[0]);
    } catch (err) {
        console.error('[vex:post]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/v1/vex  — list VEX statements for the org
app.get('/api/v1/vex', requireScope('sbom:read'), async (req, res) => {
    const { osv_id, component_id } = req.query;
    try {
        const conditions = ['vx.org_id = $1'];
        const params     = [req.org.id];
        if (osv_id) {
            params.push(osv_id);
            conditions.push(`vx.osv_id = $${params.length}`);
        }
        if (component_id) {
            params.push(component_id);
            conditions.push(`vx.component_id = $${params.length}`);
        }

        const { rows } = await db.query(
            `SELECT vx.id, vx.component_id, c.purl, c.name AS component_name, c.version,
                    vx.osv_id, vx.status, vx.justification, vx.impact_statement,
                    vx.created_at, vx.updated_at
             FROM vex_statements vx
             JOIN components c ON c.id = vx.component_id
             WHERE ${conditions.join(' AND ')}
             ORDER BY vx.updated_at DESC`,
            params
        );
        res.json({ statements: rows });
    } catch (err) {
        console.error('[vex:get]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// DELETE /api/v1/vex/:id  — revoke a VEX statement
app.delete('/api/v1/vex/:id', requireScope('sbom:ingest'), async (req, res) => {
    try {
        const { rowCount } = await db.query(
            `DELETE FROM vex_statements WHERE id = $1 AND org_id = $2`,
            [req.params.id, req.org.id]
        );
        if (!rowCount) return res.status(404).json({ error: 'VEX statement not found' });
        res.status(204).end();
    } catch (err) {
        console.error('[vex:delete]', err.message);
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
// Disabled by default. Set ENABLE_ADMIN_API=true to activate.
// Never expose on the public internet without IP allowlisting.
app.post('/api/v1/orgs', async (req, res) => {
    if (!process.env.ENABLE_ADMIN_API) {
        return res.status(404).json({ error: 'Not found' });
    }
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
    if (process.env.KATZILLA_API_KEY) startKEVRefresh();
});

module.exports = app;
