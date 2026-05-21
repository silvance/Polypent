-- Phase 7: per-project running-job cap.
--
-- A noisy operator (or runaway automation token) can submit many runs
-- and starve workers. max_concurrent_jobs limits how many of a
-- project's jobs may be in flight (leased or running) at once; queued
-- jobs are deferred until headroom is available.
--
-- Default 0 means "no project-level cap" so existing projects keep
-- their current behavior.

ALTER TABLE projects
    ADD COLUMN max_concurrent_jobs INTEGER NOT NULL DEFAULT 0
        CHECK (max_concurrent_jobs >= 0);
