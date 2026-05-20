-- Phase 3: runs, jobs, job_events.
--
-- The job queue uses FOR UPDATE SKIP LOCKED for atomic lease acquisition,
-- and LISTEN/NOTIFY ('polypent_jobs') for low-latency worker wake-up.

CREATE TABLE runs (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id    UUID         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    requested_by  UUID         REFERENCES api_tokens(id) ON DELETE SET NULL,
    capabilities  TEXT[]       NOT NULL DEFAULT ARRAY[]::TEXT[],
    parameters    JSONB        NOT NULL DEFAULT '{}'::jsonb,
    status        TEXT         NOT NULL CHECK (status IN
                      ('planning','running','succeeded','failed','cancelled')),
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    started_at    TIMESTAMPTZ,
    finished_at   TIMESTAMPTZ,
    cancelled_at  TIMESTAMPTZ,
    summary       JSONB        NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX runs_project_idx ON runs(project_id);
CREATE INDEX runs_status_idx ON runs(status);

CREATE TABLE jobs (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id            UUID         NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    project_id        UUID         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    collector         TEXT         NOT NULL,
    target_id         UUID         REFERENCES targets(id) ON DELETE SET NULL,
    target_kind       TEXT         NOT NULL,
    target_identity   TEXT         NOT NULL,
    parameters        JSONB        NOT NULL DEFAULT '{}'::jsonb,
    priority          INTEGER      NOT NULL DEFAULT 0,
    status            TEXT         NOT NULL CHECK (status IN
                          ('queued','leased','running','succeeded','failed','cancelled','timed_out')),
    leased_by         TEXT,
    lease_expires_at  TIMESTAMPTZ,
    deadline          TIMESTAMPTZ,
    attempts          INTEGER      NOT NULL DEFAULT 0,
    error             TEXT,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    started_at        TIMESTAMPTZ,
    finished_at       TIMESTAMPTZ
);
-- partial index optimized for the lease query
CREATE INDEX jobs_queued_idx ON jobs (priority DESC, created_at ASC) WHERE status = 'queued';
CREATE INDEX jobs_lease_idx ON jobs (lease_expires_at) WHERE status = 'leased';
CREATE INDEX jobs_run_idx ON jobs (run_id);
CREATE INDEX jobs_project_idx ON jobs (project_id);

CREATE TABLE job_events (
    id          BIGSERIAL    PRIMARY KEY,
    job_id      UUID         NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    kind        TEXT         NOT NULL,
    payload     JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX job_events_job_idx ON job_events (job_id, id);
