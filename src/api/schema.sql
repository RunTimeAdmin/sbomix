-- PackrAI Central Repository Schema
-- Postgres 14+  (uses gen_random_uuid(), jsonb, timestamptz)

-- ── Organizations ─────────────────────────────────────────────────────────────
CREATE TABLE organizations (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT        NOT NULL,
    -- Stores HMAC-SHA256(plaintext_key, HMAC_SECRET) — plaintext never persisted.
    -- Legacy org:admin key; prefer api_keys table for new issuance.
    api_key    TEXT        UNIQUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── API Keys (scoped, rotatable) ──────────────────────────────────────────────
-- Multiple keys per org with independent scopes and revocation.
-- Scopes: sbom:ingest  — POST /api/v1/ingest
--         sbom:read    — GET  /api/v1/apps, /search, /report
--         org:admin    — all of the above + key management
CREATE TABLE api_keys (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name         TEXT        NOT NULL DEFAULT 'default',
    -- HMAC-SHA256(plaintext_key, HMAC_SECRET) — plaintext shown once on creation only
    key_hash     TEXT        NOT NULL UNIQUE,
    scopes       TEXT[]      NOT NULL DEFAULT '{sbom:ingest,sbom:read}',
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);

-- ── Applications ──────────────────────────────────────────────────────────────
CREATE TABLE applications (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name       TEXT        NOT NULL,
    repo_url   TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (org_id, name)
);

-- ── SBOMs (one row per build) ─────────────────────────────────────────────────
CREATE TABLE sboms (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id              UUID        NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    org_id              UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    version             TEXT,
    commit_sha          TEXT,
    branch              TEXT,
    cyclonedx           JSONB,
    spdx                JSONB,
    component_count     INT         DEFAULT 0,
    vulnerability_count INT         DEFAULT 0,
    critical_count      INT         DEFAULT 0,
    quality_score       NUMERIC(5,2),
    ecosystems          TEXT[],
    elapsed_ms          INT,
    generated_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ DEFAULT NOW()
);

-- ── Components (normalised per org, deduplicated by purl) ─────────────────────
CREATE TABLE components (
    id         UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID    NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    purl       TEXT    NOT NULL,
    name       TEXT    NOT NULL,
    version    TEXT    NOT NULL,
    ecosystem  TEXT    NOT NULL,
    license    TEXT,
    UNIQUE (org_id, purl)
);

-- ── SBOM ↔ Component (many-to-many) ──────────────────────────────────────────
CREATE TABLE sbom_components (
    sbom_id      UUID    NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
    component_id UUID    NOT NULL REFERENCES components(id),
    scope        TEXT,       -- required | dev | optional
    is_direct    BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (sbom_id, component_id)
);

-- ── Vulnerabilities ───────────────────────────────────────────────────────────
-- One row per (component, osv_id). Refreshed on each ingest where vulns differ.
CREATE TABLE vulnerabilities (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    component_id    UUID        NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    org_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    osv_id          TEXT        NOT NULL,   -- OSV canonical ID (may be CVE-xxx or GHSA-xxx)
    cve_id          TEXT,                   -- CVE alias if available
    severity        TEXT,                   -- CRITICAL | HIGH | MEDIUM | LOW
    cvss_score      NUMERIC(4,2),
    fixed_version   TEXT,
    title           TEXT,
    last_checked    TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (component_id, osv_id)
);

-- ── Latest SBOM per app (materialised at ingest time) ────────────────────────
-- Avoids DISTINCT ON / LATERAL in every read endpoint.
-- Upserted inside the ingest transaction; guarded so out-of-order ingests
-- cannot overwrite a newer row.
CREATE TABLE app_latest_sboms (
    app_id              UUID        PRIMARY KEY
                                    REFERENCES applications(id) ON DELETE CASCADE,
    org_id              UUID        NOT NULL
                                    REFERENCES organizations(id) ON DELETE CASCADE,
    sbom_id             UUID        NOT NULL
                                    REFERENCES sboms(id) ON DELETE CASCADE,
    created_at          TIMESTAMPTZ NOT NULL,
    component_count     INT         NOT NULL DEFAULT 0,
    vulnerability_count INT         NOT NULL DEFAULT 0,
    critical_count      INT         NOT NULL DEFAULT 0,
    quality_score       NUMERIC(5,2),
    ecosystems          TEXT[]
);

-- ── Indexes ───────────────────────────────────────────────────────────────────
CREATE INDEX idx_api_keys_org         ON api_keys(org_id);
CREATE INDEX idx_api_keys_active      ON api_keys(key_hash) WHERE revoked_at IS NULL;
CREATE INDEX idx_applications_org     ON applications(org_id);
CREATE INDEX idx_sboms_app_time       ON sboms(app_id, created_at DESC);
CREATE INDEX idx_sboms_org_time       ON sboms(org_id, created_at DESC);
CREATE INDEX idx_components_purl      ON components(purl);
CREATE INDEX idx_components_org_eco   ON components(org_id, ecosystem);
CREATE INDEX idx_sc_component         ON sbom_components(component_id);
CREATE INDEX idx_vulns_component      ON vulnerabilities(component_id);
CREATE INDEX idx_vulns_cve_org        ON vulnerabilities(org_id, cve_id) WHERE cve_id IS NOT NULL;
CREATE INDEX idx_vulns_osv_org        ON vulnerabilities(org_id, osv_id);
CREATE INDEX idx_vulns_severity_org   ON vulnerabilities(org_id, severity);
CREATE INDEX idx_app_latest_sboms_org ON app_latest_sboms(org_id);
