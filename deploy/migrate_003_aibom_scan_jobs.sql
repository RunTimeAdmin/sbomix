-- Migration 003: Add AI-BOM columns to sboms; add worker columns to scan_jobs
-- Safe to run on existing databases — all statements are idempotent.
BEGIN;

-- ── sboms: AI-BOM fields ──────────────────────────────────────────────────────
ALTER TABLE sboms ADD COLUMN IF NOT EXISTS aibom               JSONB;
ALTER TABLE sboms ADD COLUMN IF NOT EXISTS ai_models           INT NOT NULL DEFAULT 0;
ALTER TABLE sboms ADD COLUMN IF NOT EXISTS ai_threats          INT NOT NULL DEFAULT 0;
ALTER TABLE sboms ADD COLUMN IF NOT EXISTS ai_critical         INT NOT NULL DEFAULT 0;
ALTER TABLE sboms ADD COLUMN IF NOT EXISTS least_agency_score  INT;

-- ── scan_jobs: queue + worker columns ────────────────────────────────────────
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS priority        INT  NOT NULL DEFAULT 100;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS attempts        INT  NOT NULL DEFAULT 0;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS max_attempts    INT  NOT NULL DEFAULT 2;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS locked_by       TEXT;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS locked_at       TIMESTAMPTZ;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS started_at      TIMESTAMPTZ;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS finished_at     TIMESTAMPTZ;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS timeout_at      TIMESTAMPTZ;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS scan_mode       TEXT NOT NULL DEFAULT 'hosted_fast'
    CHECK (scan_mode IN ('hosted_fast','hosted_deep','cli'));
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS token_ref       TEXT;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS repo_size_bytes BIGINT;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS component_count INT;

-- Widen status constraint to include timed_out and canceled
ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_status_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_status_check
    CHECK (status IN ('pending','running','done','failed','canceled','timed_out'));

-- ── Indexes ───────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_scan_jobs_queue
    ON scan_jobs(status, priority, created_at) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_scan_jobs_running_org
    ON scan_jobs(org_id, status) WHERE status = 'running';
CREATE INDEX IF NOT EXISTS idx_scan_jobs_stale_locks
    ON scan_jobs(status, locked_at) WHERE status = 'running';

COMMIT;
