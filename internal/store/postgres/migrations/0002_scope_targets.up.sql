-- Phase 2: scope rules and target store.

CREATE TABLE scope_rules (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    rule_order      INTEGER      NOT NULL,
    effect          TEXT         NOT NULL CHECK (effect IN ('allow','deny','out_of_scope')),
    kind            TEXT         NOT NULL,
    value           TEXT         NOT NULL,
    port_min        INTEGER      NOT NULL DEFAULT 0,
    port_max        INTEGER      NOT NULL DEFAULT 0,
    window_start    TIMESTAMPTZ,
    window_end      TIMESTAMPTZ,
    max_concurrent  INTEGER      NOT NULL DEFAULT 0,
    max_rps         DOUBLE PRECISION NOT NULL DEFAULT 0,
    note            TEXT         NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, rule_order)
);
CREATE INDEX scope_rules_project_order_idx ON scope_rules(project_id, rule_order);

CREATE TABLE targets (
    id                 UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id         UUID         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind               TEXT         NOT NULL,
    identity           TEXT         NOT NULL,
    attributes         JSONB        NOT NULL DEFAULT '{}'::jsonb,
    discovered_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_seen_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_scope_effect  TEXT,
    UNIQUE (project_id, kind, identity)
);
CREATE INDEX targets_project_idx ON targets(project_id);

CREATE TABLE target_provenance (
    id          BIGSERIAL    PRIMARY KEY,
    target_id   UUID         NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    source_type TEXT         NOT NULL,
    source_id   TEXT         NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX target_provenance_target_idx ON target_provenance(target_id);
