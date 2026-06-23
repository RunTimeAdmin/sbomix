-- Migration 001: app_latest_sboms
-- Materialises the "latest SBOM per app" row that was previously recomputed
-- via DISTINCT ON / LATERAL in every read endpoint.
-- Safe to re-run: all statements use IF NOT EXISTS or ON CONFLICT DO NOTHING.

BEGIN;

-- ── Table ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS app_latest_sboms (
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

CREATE INDEX IF NOT EXISTS idx_app_latest_sboms_org
    ON app_latest_sboms(org_id);

-- ── Backfill from existing sboms ──────────────────────────────────────────────
-- Picks the most-recent sbom per app. ON CONFLICT DO NOTHING makes this
-- re-entrant: safe to run again if the table already has rows.
INSERT INTO app_latest_sboms
    (app_id, org_id, sbom_id, created_at,
     component_count, vulnerability_count, critical_count, quality_score, ecosystems)
SELECT DISTINCT ON (s.app_id)
    s.app_id,
    s.org_id,
    s.id                  AS sbom_id,
    s.created_at,
    COALESCE(s.component_count,     0),
    COALESCE(s.vulnerability_count, 0),
    COALESCE(s.critical_count,      0),
    s.quality_score,
    s.ecosystems
FROM sboms s
ORDER BY s.app_id, s.created_at DESC
ON CONFLICT (app_id) DO NOTHING;

COMMIT;
