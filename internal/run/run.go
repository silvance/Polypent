// Package run owns the planning and lifecycle of Runs and the read paths
// for jobs and job_events. Worker execution lives in internal/worker; the
// queue primitives live in internal/queue.
package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/silvance/polypent/internal/audit"
	"github.com/silvance/polypent/internal/queue"
	"github.com/silvance/polypent/internal/scope"
)

// ErrNotFound is returned when a Run lookup misses.
var ErrNotFound = errors.New("run: not found")

// Status mirrors the runs.status enum.
type Status string

const (
	StatusPlanning  Status = "planning"
	StatusRunning   Status = "running"
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

// Run is the persisted entity.
type Run struct {
	ID           uuid.UUID      `json:"id"`
	ProjectID    uuid.UUID      `json:"project_id"`
	Capabilities []string       `json:"capabilities"`
	Parameters   map[string]any `json:"parameters"`
	Status       Status         `json:"status"`
	CreatedAt    time.Time      `json:"created_at"`
	StartedAt    *time.Time     `json:"started_at,omitempty"`
	FinishedAt   *time.Time     `json:"finished_at,omitempty"`
	CancelledAt  *time.Time     `json:"cancelled_at,omitempty"`
	Summary      map[string]any `json:"summary"`
}

// PlanInput is the surface a caller (API / CLI) hands the planner.
type PlanInput struct {
	ProjectID    uuid.UUID
	RequestedBy  *uuid.UUID
	Capabilities []string       // each maps 1:1 to a collector name in v1
	Parameters   map[string]any // forwarded to each job's parameters
	Targets      []scope.Target // explicit target list; required for v1
	Priority     int
	JobDeadline  *time.Time
	OnDropped    func(audit.Event) // optional sink for "target dropped" events
}

// Planner builds runs and their jobs after scope-clamping the target list.
type Planner struct {
	pool  *pgxpool.Pool
	q     *queue.Queue
	scope *scope.Store
	audit *audit.Logger
}

func NewPlanner(pool *pgxpool.Pool, q *queue.Queue, s *scope.Store, a *audit.Logger) *Planner {
	return &Planner{pool: pool, q: q, scope: s, audit: a}
}

// Plan creates a Run and enqueues its Jobs. Returns the run id and the
// number of (kept, dropped) targets per capability.
//
// "Dropped" includes targets that scope-evaluated to deny or out_of_scope.
// Each drop is recorded as an audit event before this function returns;
// the platform is paranoid about this on purpose.
func (p *Planner) Plan(ctx context.Context, in PlanInput) (uuid.UUID, int, int, error) {
	if len(in.Capabilities) == 0 {
		return uuid.Nil, 0, 0, errors.New("plan: capabilities required")
	}
	if len(in.Targets) == 0 {
		return uuid.Nil, 0, 0, errors.New("plan: targets required")
	}

	caps := []byte("{}")
	if len(in.Parameters) > 0 {
		var err error
		caps, err = json.Marshal(in.Parameters)
		if err != nil {
			return uuid.Nil, 0, 0, fmt.Errorf("plan: parameters: %w", err)
		}
	}

	rules, err := p.scope.List(ctx, in.ProjectID)
	if err != nil {
		return uuid.Nil, 0, 0, fmt.Errorf("plan: load scope: %w", err)
	}

	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return uuid.Nil, 0, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var runID uuid.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO runs (project_id, requested_by, capabilities, parameters, status)
		VALUES ($1,$2,$3,$4,'running')
		RETURNING id`,
		in.ProjectID, in.RequestedBy, in.Capabilities, caps,
	).Scan(&runID)
	if err != nil {
		return uuid.Nil, 0, 0, fmt.Errorf("plan: insert run: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, 0, 0, err
	}

	now := time.Now()
	kept, dropped := 0, 0
	for _, capName := range in.Capabilities {
		for _, tg := range in.Targets {
			res := scope.Evaluate(tg, rules, now)
			if res.Effect != scope.EffectAllow {
				dropped++
				if _, err := p.audit.Append(ctx, audit.Event{
					ProjectID:    &in.ProjectID,
					ActorTokenID: in.RequestedBy,
					Action:       "scope.dropped",
					TargetKind:   string(tg.Kind),
					TargetID:     tg.Identity,
					Metadata: map[string]any{
						"effect":     string(res.Effect),
						"reason":     res.Reason,
						"capability": capName,
						"run_id":     runID.String(),
					},
				}); err != nil {
					return uuid.Nil, kept, dropped, fmt.Errorf("plan: audit dropped: %w", err)
				}
				continue
			}
			_, err := p.q.Enqueue(ctx, queue.EnqueueInput{
				RunID:          runID,
				ProjectID:      in.ProjectID,
				Collector:      capName,
				TargetKind:     string(tg.Kind),
				TargetIdentity: tg.Identity,
				Parameters:     in.Parameters,
				Priority:       in.Priority,
				Deadline:       in.JobDeadline,
			})
			if err != nil {
				return uuid.Nil, kept, dropped, fmt.Errorf("plan: enqueue: %w", err)
			}
			kept++
		}
	}

	if kept == 0 {
		// nothing to run; transition immediately
		if _, err := p.pool.Exec(ctx, `
			UPDATE runs SET status='succeeded', finished_at=NOW(),
			    summary=jsonb_build_object('kept',0,'dropped',$2::int)
			WHERE id=$1`, runID, dropped); err != nil {
			return uuid.Nil, kept, dropped, err
		}
	}

	return runID, kept, dropped, nil
}

// Store is the read-side projection layer for runs/jobs/events.
type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Get returns a single run.
func (s *Store) Get(ctx context.Context, id uuid.UUID) (Run, error) {
	var r Run
	var caps []string
	var paramsRaw, summaryRaw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, project_id, capabilities, parameters, status,
		       created_at, started_at, finished_at, cancelled_at, summary
		FROM runs WHERE id=$1`, id,
	).Scan(&r.ID, &r.ProjectID, &caps, &paramsRaw, (*string)(&r.Status),
		&r.CreatedAt, &r.StartedAt, &r.FinishedAt, &r.CancelledAt, &summaryRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return Run{}, ErrNotFound
	}
	if err != nil {
		return Run{}, err
	}
	r.Capabilities = caps
	if len(paramsRaw) > 0 {
		_ = json.Unmarshal(paramsRaw, &r.Parameters)
	}
	if len(summaryRaw) > 0 {
		_ = json.Unmarshal(summaryRaw, &r.Summary)
	}
	return r, nil
}

// JobRow is a denormalized view returned by ListJobs.
type JobRow struct {
	ID             uuid.UUID  `json:"id"`
	RunID          uuid.UUID  `json:"run_id"`
	Collector      string     `json:"collector"`
	TargetKind     string     `json:"target_kind"`
	TargetIdentity string     `json:"target_identity"`
	Status         string     `json:"status"`
	Attempts       int        `json:"attempts"`
	Error          *string    `json:"error,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
}

// ListJobs returns the jobs for a run, sorted by creation time.
func (s *Store) ListJobs(ctx context.Context, runID uuid.UUID) ([]JobRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, run_id, collector, target_kind, target_identity,
		       status, attempts, error, created_at, started_at, finished_at
		FROM jobs WHERE run_id=$1 ORDER BY created_at ASC, id ASC`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []JobRow
	for rows.Next() {
		var j JobRow
		if err := rows.Scan(&j.ID, &j.RunID, &j.Collector,
			&j.TargetKind, &j.TargetIdentity, &j.Status, &j.Attempts,
			&j.Error, &j.CreatedAt, &j.StartedAt, &j.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// MaybeFinishRun checks whether all of a run's jobs are terminal and, if
// so, transitions the run to succeeded/failed accordingly. Intended to be
// called by the worker after each job completion.
func MaybeFinishRun(ctx context.Context, pool *pgxpool.Pool, runID uuid.UUID) error {
	var total, done, failed int
	err := pool.QueryRow(ctx, `
		SELECT
		    COUNT(*) AS total,
		    COUNT(*) FILTER (WHERE status IN ('succeeded','failed','cancelled','timed_out')) AS done,
		    COUNT(*) FILTER (WHERE status IN ('failed','timed_out')) AS failed
		FROM jobs WHERE run_id=$1`, runID,
	).Scan(&total, &done, &failed)
	if err != nil {
		return err
	}
	if total == 0 || done < total {
		return nil
	}
	status := StatusSucceeded
	if failed > 0 {
		status = StatusFailed
	}
	_, err = pool.Exec(ctx, `
		UPDATE runs SET status=$2, finished_at=NOW(),
		    summary=jsonb_build_object('total',$3::int,'failed',$4::int)
		WHERE id=$1 AND status NOT IN ('succeeded','failed','cancelled')`,
		runID, string(status), total, failed)
	return err
}
