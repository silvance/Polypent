// Package queue is the Postgres-backed job queue.
//
// The contract is intentionally narrow so a non-Postgres backend can be
// dropped in later without changing callers. For v1 the implementation
// uses FOR UPDATE SKIP LOCKED for atomic lease acquisition and
// LISTEN/NOTIFY ('polypent_jobs') for low-latency worker wake-up.
//
// Lifecycle (per docs/architecture.md):
//
//	queued -> leased -> running -> (succeeded | failed | cancelled | timed_out)
//
// Leases expire; a periodic reclaim sweep returns expired leases to
// `queued` so a worker crash does not lose a job.
package queue

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// NotifyChannel is the LISTEN channel for queue wake-ups.
	NotifyChannel = "polypent_jobs"
)

// Status is the persisted lifecycle state.
type Status string

const (
	StatusQueued    Status = "queued"
	StatusLeased    Status = "leased"
	StatusRunning   Status = "running"
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
	StatusTimedOut  Status = "timed_out"
)

// Terminal reports whether s is an end-of-life status.
func (s Status) Terminal() bool {
	switch s {
	case StatusSucceeded, StatusFailed, StatusCancelled, StatusTimedOut:
		return true
	}
	return false
}

// Job is the runtime view of a row in `jobs`.
type Job struct {
	ID             uuid.UUID
	RunID          uuid.UUID
	ProjectID      uuid.UUID
	Collector      string
	TargetID       *uuid.UUID
	TargetKind     string
	TargetIdentity string
	Parameters     map[string]any
	Priority       int
	Status         Status
	LeasedBy       *string
	LeaseExpiresAt *time.Time
	Deadline       *time.Time
	Attempts       int
	Error          *string
	CreatedAt      time.Time
	StartedAt      *time.Time
	FinishedAt     *time.Time
}

// EnqueueInput is the planner's surface.
type EnqueueInput struct {
	RunID          uuid.UUID
	ProjectID      uuid.UUID
	Collector      string
	TargetID       *uuid.UUID
	TargetKind     string
	TargetIdentity string
	Parameters     map[string]any
	Priority       int
	Deadline       *time.Time
}

// Queue is the Postgres-backed queue.
type Queue struct {
	pool          *pgxpool.Pool
	leaseDuration time.Duration
}

// New returns a Queue with the given lease duration; pick a value larger
// than your longest expected job, with margin. The reclaim sweep can
// safely shorten this if needed.
func New(pool *pgxpool.Pool, leaseDuration time.Duration) *Queue {
	if leaseDuration <= 0 {
		leaseDuration = 5 * time.Minute
	}
	return &Queue{pool: pool, leaseDuration: leaseDuration}
}

// Enqueue inserts a job in status=queued and notifies listeners.
func (q *Queue) Enqueue(ctx context.Context, in EnqueueInput) (uuid.UUID, error) {
	params := in.Parameters
	if params == nil {
		params = map[string]any{}
	}
	pj, err := json.Marshal(params)
	if err != nil {
		return uuid.Nil, fmt.Errorf("queue: params: %w", err)
	}
	var id uuid.UUID
	err = q.pool.QueryRow(ctx, `
		INSERT INTO jobs
		    (run_id, project_id, collector, target_id,
		     target_kind, target_identity, parameters,
		     priority, status, deadline)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'queued',$9)
		RETURNING id`,
		in.RunID, in.ProjectID, in.Collector, in.TargetID,
		in.TargetKind, in.TargetIdentity, pj,
		in.Priority, in.Deadline,
	).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("queue: insert: %w", err)
	}
	// pg_notify payload is best-effort; workers also poll on a fallback timer.
	_, _ = q.pool.Exec(ctx, `SELECT pg_notify($1, $2)`, NotifyChannel, id.String())
	return id, nil
}

// Lease atomically takes one queued job and marks it leased. Returns
// (nil, false, nil) when nothing is available.
func (q *Queue) Lease(ctx context.Context, workerID string) (*Job, bool, error) {
	tx, err := q.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Step 1: pick a candidate queued job. We don't filter by the
	// project's concurrency cap here because that filter cannot be
	// evaluated race-free against committed-but-not-yet-visible peer
	// leases; see step 2.
	var (
		id        uuid.UUID
		projectID uuid.UUID
		cap_      int
	)
	err = tx.QueryRow(ctx, `
		SELECT j.id, j.project_id, p.max_concurrent_jobs
		FROM jobs j
		JOIN projects p ON p.id = j.project_id
		WHERE j.status = 'queued'
		ORDER BY j.priority DESC, j.created_at ASC
		FOR UPDATE OF j SKIP LOCKED
		LIMIT 1`).Scan(&id, &projectID, &cap_)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("queue: lease select: %w", err)
	}

	// Step 2: serialize per-project concurrency-cap checks via an
	// advisory lock keyed off the project's UUID. The lock is held
	// for the rest of this transaction. Workers competing for the
	// same project's cap will block here rather than racing.
	if cap_ > 0 {
		// pg_advisory_xact_lock is keyed on int8. hashtextextended
		// produces a stable int8 from the UUID's text form.
		if _, err := tx.Exec(ctx,
			`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
			projectID.String(),
		); err != nil {
			return nil, false, fmt.Errorf("queue: cap lock: %w", err)
		}
		var busy int
		if err := tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM jobs
			 WHERE project_id = $1 AND status IN ('leased','running')`,
			projectID,
		).Scan(&busy); err != nil {
			return nil, false, fmt.Errorf("queue: cap count: %w", err)
		}
		if busy >= cap_ {
			// At cap: leave the job in 'queued' (the tuple lock is
			// released on rollback). Another worker can try a
			// different project's job; this one will be picked up
			// again next round.
			return nil, false, nil
		}
	}

	expiry := time.Now().Add(q.leaseDuration)
	var j Job
	var paramsRaw []byte
	err = tx.QueryRow(ctx, `
		UPDATE jobs SET
		    status = 'leased',
		    leased_by = $2,
		    lease_expires_at = $3,
		    attempts = attempts + 1,
		    updated_at = NOW()
		WHERE id = $1
		RETURNING id, run_id, project_id, collector, target_id,
		          target_kind, target_identity, parameters, priority,
		          status, leased_by, lease_expires_at, deadline,
		          attempts, error, created_at, started_at, finished_at`,
		id, workerID, expiry,
	).Scan(&j.ID, &j.RunID, &j.ProjectID, &j.Collector, &j.TargetID,
		&j.TargetKind, &j.TargetIdentity, &paramsRaw, &j.Priority,
		(*string)(&j.Status), &j.LeasedBy, &j.LeaseExpiresAt, &j.Deadline,
		&j.Attempts, &j.Error, &j.CreatedAt, &j.StartedAt, &j.FinishedAt)
	if err != nil {
		return nil, false, fmt.Errorf("queue: lease update: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	if len(paramsRaw) > 0 {
		_ = json.Unmarshal(paramsRaw, &j.Parameters)
	}
	return &j, true, nil
}

// MarkRunning transitions a leased job to running. workerID must match the
// leaseholder; the update is a no-op otherwise.
func (q *Queue) MarkRunning(ctx context.Context, jobID uuid.UUID, workerID string) error {
	tag, err := q.pool.Exec(ctx, `
		UPDATE jobs
		SET status='running', started_at=COALESCE(started_at, NOW()), updated_at=NOW()
		WHERE id=$1 AND leased_by=$2 AND status='leased'`,
		jobID, workerID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("queue: not the leaseholder")
	}
	return nil
}

// Complete transitions a job to a terminal state. workerID must match.
func (q *Queue) Complete(ctx context.Context, jobID uuid.UUID, workerID string, status Status, errMsg string) error {
	if !status.Terminal() {
		return fmt.Errorf("queue: %s is not a terminal status", status)
	}
	var nilOrErr sql.NullString
	if errMsg != "" {
		nilOrErr = sql.NullString{String: errMsg, Valid: true}
	}
	tag, err := q.pool.Exec(ctx, `
		UPDATE jobs SET
		    status = $3,
		    finished_at = NOW(),
		    updated_at = NOW(),
		    error = $4
		WHERE id=$1 AND leased_by=$2 AND status IN ('leased','running')`,
		jobID, workerID, string(status), nilOrErr)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("queue: not the leaseholder or already completed")
	}
	return nil
}

// Cancel transitions any non-terminal job to cancelled. Allowed from any
// non-terminal state; intended for API-driven cancellation.
func (q *Queue) Cancel(ctx context.Context, jobID uuid.UUID) (bool, error) {
	tag, err := q.pool.Exec(ctx, `
		UPDATE jobs SET status='cancelled', finished_at=NOW(), updated_at=NOW()
		WHERE id=$1 AND status NOT IN ('succeeded','failed','cancelled','timed_out')`,
		jobID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// CancelRun marks all non-terminal jobs of a run as cancelled and the run
// itself as cancelled. Returns the number of jobs that were transitioned.
func (q *Queue) CancelRun(ctx context.Context, runID uuid.UUID) (int64, error) {
	tag, err := q.pool.Exec(ctx, `
		UPDATE jobs SET status='cancelled', finished_at=NOW(), updated_at=NOW()
		WHERE run_id=$1 AND status NOT IN ('succeeded','failed','cancelled','timed_out')`,
		runID)
	if err != nil {
		return 0, err
	}
	if _, err := q.pool.Exec(ctx, `
		UPDATE runs SET status='cancelled', cancelled_at=NOW(), finished_at=NOW()
		WHERE id=$1 AND status NOT IN ('succeeded','failed','cancelled')`, runID); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ReclaimExpired returns expired leases to status=queued so a stuck worker
// doesn't permanently strand a job.
func (q *Queue) ReclaimExpired(ctx context.Context) (int64, error) {
	tag, err := q.pool.Exec(ctx, `
		UPDATE jobs SET
		    status='queued',
		    leased_by=NULL,
		    lease_expires_at=NULL,
		    updated_at=NOW()
		WHERE status IN ('leased','running')
		  AND lease_expires_at < NOW()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// RecordEvent appends a row to job_events. Use for progress, log, finding,
// and transition events emitted by collectors.
func (q *Queue) RecordEvent(ctx context.Context, jobID uuid.UUID, kind string, payload map[string]any) error {
	pj, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = q.pool.Exec(ctx,
		`INSERT INTO job_events (job_id, kind, payload) VALUES ($1,$2,$3)`,
		jobID, kind, pj)
	return err
}

// LeaseDuration exposes the configured lease window (handy for tests).
func (q *Queue) LeaseDuration() time.Duration { return q.leaseDuration }

// Pool is exposed for stores that need read-only access (e.g. listing jobs
// via the API). Writes go through the typed methods above.
func (q *Queue) Pool() *pgxpool.Pool { return q.pool }
