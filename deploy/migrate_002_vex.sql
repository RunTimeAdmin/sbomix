-- Migration 002: vex_statements
-- Adds VEX (Vulnerability Exploitability eXchange) statement storage.
-- Status values align with CycloneDX VEX and OpenVEX specs.
-- Safe to re-run: all statements use IF NOT EXISTS.

BEGIN;

CREATE TABLE IF NOT EXISTS vex_statements (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    component_id     UUID        NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    osv_id           TEXT        NOT NULL,
    -- CycloneDX / OpenVEX status
    status           TEXT        NOT NULL CHECK (status IN (
                                     'not_affected',
                                     'affected',
                                     'fixed',
                                     'under_investigation'
                                 )),
    -- Justification is required when status = 'not_affected'
    justification    TEXT        CHECK (justification IN (
                                     'component_not_present',
                                     'vulnerable_code_not_present',
                                     'vulnerable_code_not_in_execute_path',
                                     'vulnerable_code_cannot_be_controlled_by_adversary',
                                     'inline_mitigations_already_exist'
                                 )),
    impact_statement TEXT,
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    updated_at       TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (org_id, component_id, osv_id)
);

CREATE INDEX IF NOT EXISTS idx_vex_org_osv
    ON vex_statements(org_id, osv_id);

CREATE INDEX IF NOT EXISTS idx_vex_component
    ON vex_statements(component_id);

COMMIT;
