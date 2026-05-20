-- Phase 7: per-project encrypted secrets vault.
--
-- Values are stored as AES-GCM ciphertext under a per-project derived key.
-- The platform never logs plaintext, never emits plaintext into audit
-- metadata, and never returns plaintext on list endpoints.

CREATE TABLE project_secrets (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    key             TEXT         NOT NULL,
    ciphertext      BYTEA        NOT NULL,
    nonce           BYTEA        NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_by      UUID         REFERENCES api_tokens(id) ON DELETE SET NULL,
    UNIQUE (project_id, key)
);
CREATE INDEX project_secrets_project_idx ON project_secrets (project_id);
