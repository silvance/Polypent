// Package target models the per-project asset inventory.
//
// Targets are discovered or operator-seeded. Each is unique per
// (project, kind, identity); re-discovery only bumps last_seen_at and may
// append a row to target_provenance.
package target

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a target lookup misses.
var ErrNotFound = errors.New("target: not found")

// Target is the persisted entity.
type Target struct {
	ID              uuid.UUID      `json:"id"`
	ProjectID       uuid.UUID      `json:"project_id"`
	Kind            string         `json:"kind"`
	Identity        string         `json:"identity"`
	Attributes      map[string]any `json:"attributes"`
	DiscoveredAt    time.Time      `json:"discovered_at"`
	LastSeenAt      time.Time      `json:"last_seen_at"`
	LastScopeEffect *string        `json:"last_scope_effect,omitempty"`
}

// Store is the Postgres-backed target store.
type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// UpsertInput is the operator/discoverer surface.
type UpsertInput struct {
	Kind       string
	Identity   string
	Attributes map[string]any
	SourceType string // 'seed' | 'run' | 'finding'
	SourceID   string
}

// Upsert inserts a target or bumps its last_seen_at. Always appends a row
// to target_provenance recording the source of this sighting.
func (s *Store) Upsert(ctx context.Context, projectID uuid.UUID, in UpsertInput) (Target, error) {
	if in.Kind == "" || in.Identity == "" {
		return Target{}, fmt.Errorf("target: kind and identity required")
	}
	if in.SourceType == "" {
		in.SourceType = "seed"
	}

	attrs := []byte("{}")
	if len(in.Attributes) > 0 {
		var err error
		attrs, err = json.Marshal(in.Attributes)
		if err != nil {
			return Target{}, fmt.Errorf("target: attributes: %w", err)
		}
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Target{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var t Target
	var attrRaw []byte
	err = tx.QueryRow(ctx, `
		INSERT INTO targets (project_id, kind, identity, attributes)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (project_id, kind, identity)
		DO UPDATE SET
		    last_seen_at = NOW(),
		    attributes = targets.attributes || EXCLUDED.attributes
		RETURNING id, project_id, kind, identity, attributes,
		          discovered_at, last_seen_at, last_scope_effect`,
		projectID, in.Kind, in.Identity, attrs,
	).Scan(&t.ID, &t.ProjectID, &t.Kind, &t.Identity, &attrRaw,
		&t.DiscoveredAt, &t.LastSeenAt, &t.LastScopeEffect)
	if err != nil {
		return Target{}, fmt.Errorf("target: upsert: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO target_provenance (target_id, source_type, source_id) VALUES ($1,$2,$3)`,
		t.ID, in.SourceType, in.SourceID,
	); err != nil {
		return Target{}, fmt.Errorf("target: provenance: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Target{}, err
	}

	if len(attrRaw) > 0 {
		_ = json.Unmarshal(attrRaw, &t.Attributes)
	}
	return t, nil
}

// List returns targets for a project ordered by discovery time.
func (s *Store) List(ctx context.Context, projectID uuid.UUID) ([]Target, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, project_id, kind, identity, attributes,
		       discovered_at, last_seen_at, last_scope_effect
		FROM targets WHERE project_id = $1 ORDER BY discovered_at ASC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Target
	for rows.Next() {
		var t Target
		var attrRaw []byte
		if err := rows.Scan(&t.ID, &t.ProjectID, &t.Kind, &t.Identity, &attrRaw,
			&t.DiscoveredAt, &t.LastSeenAt, &t.LastScopeEffect); err != nil {
			return nil, err
		}
		if len(attrRaw) > 0 {
			_ = json.Unmarshal(attrRaw, &t.Attributes)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SetLastScopeEffect updates the cached scope verdict for display.
func (s *Store) SetLastScopeEffect(ctx context.Context, projectID, targetID uuid.UUID, effect string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE targets SET last_scope_effect=$3 WHERE project_id=$1 AND id=$2`,
		projectID, targetID, effect)
	return err
}
