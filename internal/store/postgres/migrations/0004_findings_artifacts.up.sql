-- Phase 4: artifacts, findings, collector catalog.

CREATE TABLE artifacts (
    sha256       TEXT         PRIMARY KEY,
    size         BIGINT       NOT NULL CHECK (size >= 0),
    mime         TEXT         NOT NULL DEFAULT 'application/octet-stream',
    label        TEXT         NOT NULL DEFAULT '',
    project_id   UUID         REFERENCES projects(id) ON DELETE SET NULL,
    job_id       UUID         REFERENCES jobs(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX artifacts_project_idx ON artifacts (project_id);

CREATE TABLE findings (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    run_id          UUID         REFERENCES runs(id) ON DELETE SET NULL,
    job_id          UUID         REFERENCES jobs(id) ON DELETE SET NULL,
    collector       TEXT         NOT NULL,
    target_kind     TEXT         NOT NULL,
    target_identity TEXT         NOT NULL,
    kind            TEXT         NOT NULL,
    severity        TEXT         NOT NULL CHECK (severity IN
                        ('informational','low','medium','high','critical')),
    title           TEXT         NOT NULL,
    description     TEXT         NOT NULL DEFAULT '',
    cvss            TEXT         NOT NULL DEFAULT '',
    dedup_key       TEXT         NOT NULL,
    evidence        TEXT[]       NOT NULL DEFAULT ARRAY[]::TEXT[],
    payload         JSONB        NOT NULL DEFAULT '{}'::jsonb,
    status          TEXT         NOT NULL DEFAULT 'new' CHECK (status IN
                        ('new','triaged','accepted','false_positive','remediated')),
    first_seen_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, collector, dedup_key)
);
CREATE INDEX findings_project_idx ON findings (project_id);
CREATE INDEX findings_run_idx ON findings (run_id);
CREATE INDEX findings_severity_idx ON findings (project_id, severity);

CREATE TABLE collectors_catalog (
    name           TEXT         PRIMARY KEY,
    language       TEXT         NOT NULL,
    version        TEXT         NOT NULL,
    binary_path    TEXT         NOT NULL,
    transport      TEXT         NOT NULL DEFAULT 'ndjson'
                       CHECK (transport IN ('ndjson','jsonrpc')),
    capabilities   TEXT[]       NOT NULL DEFAULT ARRAY[]::TEXT[],
    description    TEXT         NOT NULL DEFAULT '',
    -- Optional resource hints (purely advisory in Phase 4).
    cpu_hint       INTEGER      NOT NULL DEFAULT 0,
    memory_mb_hint INTEGER      NOT NULL DEFAULT 0,
    rate_hint      INTEGER      NOT NULL DEFAULT 0,
    registered_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
