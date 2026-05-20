package scope

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound      = errors.New("scope: rule not found")
	ErrOrderConflict = errors.New("scope: order already in use for this project")
)

// Store persists scope rules per project.
type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Create inserts a rule. Caller has already called r.Validate.
func (s *Store) Create(ctx context.Context, projectID uuid.UUID, r Rule) (Rule, error) {
	var out Rule
	var start, end *time.Time
	if !r.Window.Start.IsZero() {
		t := r.Window.Start
		start = &t
	}
	if !r.Window.End.IsZero() {
		t := r.Window.End
		end = &t
	}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO scope_rules
		    (project_id, rule_order, effect, kind, value,
		     port_min, port_max, window_start, window_end,
		     max_concurrent, max_rps, note)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING id, rule_order, effect, kind, value, port_min, port_max,
		          window_start, window_end, max_concurrent, max_rps, note`,
		projectID, r.Order, string(r.Effect), string(r.Kind), r.Value,
		r.PortMin, r.PortMax, start, end,
		r.MaxConcurrent, r.MaxRPS, r.Note,
	).Scan(&out.ID, &out.Order, (*string)(&out.Effect), (*string)(&out.Kind),
		&out.Value, &out.PortMin, &out.PortMax,
		&start, &end, &out.MaxConcurrent, &out.MaxRPS, &out.Note)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return Rule{}, ErrOrderConflict
		}
		return Rule{}, fmt.Errorf("scope: insert: %w", err)
	}
	if start != nil {
		out.Window.Start = *start
	}
	if end != nil {
		out.Window.End = *end
	}
	return out, nil
}

// List returns all rules for a project in evaluation order.
func (s *Store) List(ctx context.Context, projectID uuid.UUID) ([]Rule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, rule_order, effect, kind, value, port_min, port_max,
		       window_start, window_end, max_concurrent, max_rps, note
		FROM scope_rules WHERE project_id = $1
		ORDER BY rule_order ASC, id ASC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var r Rule
		var start, end *time.Time
		if err := rows.Scan(&r.ID, &r.Order, (*string)(&r.Effect), (*string)(&r.Kind),
			&r.Value, &r.PortMin, &r.PortMax,
			&start, &end, &r.MaxConcurrent, &r.MaxRPS, &r.Note); err != nil {
			return nil, err
		}
		if start != nil {
			r.Window.Start = *start
		}
		if end != nil {
			r.Window.End = *end
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Delete removes a rule by id, scoped to a project to prevent cross-tenant
// deletion.
func (s *Store) Delete(ctx context.Context, projectID, ruleID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM scope_rules WHERE project_id=$1 AND id=$2`, projectID, ruleID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Get returns a single rule by (project, id).
func (s *Store) Get(ctx context.Context, projectID, ruleID uuid.UUID) (Rule, error) {
	var r Rule
	var start, end *time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT id, rule_order, effect, kind, value, port_min, port_max,
		       window_start, window_end, max_concurrent, max_rps, note
		FROM scope_rules WHERE project_id=$1 AND id=$2`, projectID, ruleID,
	).Scan(&r.ID, &r.Order, (*string)(&r.Effect), (*string)(&r.Kind),
		&r.Value, &r.PortMin, &r.PortMax,
		&start, &end, &r.MaxConcurrent, &r.MaxRPS, &r.Note)
	if errors.Is(err, pgx.ErrNoRows) {
		return Rule{}, ErrNotFound
	}
	if err != nil {
		return Rule{}, err
	}
	if start != nil {
		r.Window.Start = *start
	}
	if end != nil {
		r.Window.End = *end
	}
	return r, nil
}
