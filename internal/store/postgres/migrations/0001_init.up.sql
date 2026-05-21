-- Phase 1 schema: projects, api_tokens, audit_events.
--
-- Forward-only migrations from here on (see docs/migration-plan.md). If this
-- migration ships and is wrong, fix it with a new migration; do not edit.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE projects (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            TEXT        NOT NULL UNIQUE,
    name            TEXT        NOT NULL,
    owner           TEXT        NOT NULL,
    description     TEXT        NOT NULL DEFAULT '',
    roe_hash        TEXT        NOT NULL DEFAULT '',
    contract_start  TIMESTAMPTZ,
    contract_end    TIMESTAMPTZ,
    retention_days  INTEGER     NOT NULL DEFAULT 365 CHECK (retention_days > 0),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE api_tokens (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- NULL project_id = platform-scoped token (e.g. bootstrap admin).
    project_id  UUID        REFERENCES projects(id) ON DELETE CASCADE,
    role        TEXT        NOT NULL CHECK (role IN
                    ('admin','owner','operator','viewer','automation')),
    name        TEXT        NOT NULL,
    token_hash  BYTEA       NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);
CREATE INDEX api_tokens_project_idx ON api_tokens(project_id);

CREATE TABLE audit_events (
    id              BIGSERIAL    PRIMARY KEY,
    project_id      UUID         REFERENCES projects(id) ON DELETE SET NULL,
    actor_token_id  UUID         REFERENCES api_tokens(id) ON DELETE SET NULL,
    action          TEXT         NOT NULL,
    target_kind     TEXT         NOT NULL,
    target_id       TEXT         NOT NULL,
    metadata        JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    prev_hash       BYTEA,
    self_hash       BYTEA        NOT NULL
);
CREATE INDEX audit_events_project_idx ON audit_events(project_id);
CREATE INDEX audit_events_created_idx ON audit_events(created_at);
