// Package catalog persists the registry of external collectors.
//
// Each catalog entry names a binary (or fetch reference) the supervisor
// can spawn. The in-process registry (collector.Registry) is populated
// from this catalog at daemon startup, plus any built-in collectors
// (mock, in-tree Go collectors arriving in Phase 5).
package catalog

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned by Get when no entry matches.
var ErrNotFound = errors.New("catalog: not found")

// Transport names the wire protocol the supervisor will use.
type Transport string

const (
	TransportNDJSON  Transport = "ndjson"
	TransportJSONRPC Transport = "jsonrpc"
)

// Entry is a row in collectors_catalog.
type Entry struct {
	Name         string    `json:"name"`
	Language     string    `json:"language"`
	Version      string    `json:"version"`
	BinaryPath   string    `json:"binary_path"`
	Transport    Transport `json:"transport"`
	Capabilities []string  `json:"capabilities"`
	Description  string    `json:"description"`
	CPUHint      int       `json:"cpu_hint,omitempty"`
	MemoryMBHint int       `json:"memory_mb_hint,omitempty"`
	RateHint     int       `json:"rate_hint,omitempty"`
	RegisteredAt time.Time `json:"registered_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Store is the Postgres-backed catalog.
type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Upsert inserts or replaces an entry.
func (s *Store) Upsert(ctx context.Context, e Entry) (Entry, error) {
	if e.Name == "" || e.BinaryPath == "" {
		return Entry{}, errors.New("catalog: name and binary_path required")
	}
	if e.Transport == "" {
		e.Transport = TransportNDJSON
	}
	if e.Capabilities == nil {
		e.Capabilities = []string{}
	}
	var out Entry
	err := s.pool.QueryRow(ctx, `
		INSERT INTO collectors_catalog
		    (name, language, version, binary_path, transport, capabilities,
		     description, cpu_hint, memory_mb_hint, rate_hint)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (name) DO UPDATE SET
		    language     = EXCLUDED.language,
		    version      = EXCLUDED.version,
		    binary_path  = EXCLUDED.binary_path,
		    transport    = EXCLUDED.transport,
		    capabilities = EXCLUDED.capabilities,
		    description  = EXCLUDED.description,
		    cpu_hint     = EXCLUDED.cpu_hint,
		    memory_mb_hint = EXCLUDED.memory_mb_hint,
		    rate_hint    = EXCLUDED.rate_hint,
		    updated_at   = NOW()
		RETURNING name, language, version, binary_path, transport, capabilities,
		          description, cpu_hint, memory_mb_hint, rate_hint,
		          registered_at, updated_at`,
		e.Name, e.Language, e.Version, e.BinaryPath, string(e.Transport), e.Capabilities,
		e.Description, e.CPUHint, e.MemoryMBHint, e.RateHint,
	).Scan(&out.Name, &out.Language, &out.Version, &out.BinaryPath, (*string)(&out.Transport),
		&out.Capabilities, &out.Description, &out.CPUHint, &out.MemoryMBHint, &out.RateHint,
		&out.RegisteredAt, &out.UpdatedAt)
	if err != nil {
		return Entry{}, fmt.Errorf("catalog: upsert: %w", err)
	}
	return out, nil
}

// List returns all catalog entries.
func (s *Store) List(ctx context.Context) ([]Entry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT name, language, version, binary_path, transport, capabilities,
		       description, cpu_hint, memory_mb_hint, rate_hint,
		       registered_at, updated_at
		FROM collectors_catalog
		ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.Name, &e.Language, &e.Version, &e.BinaryPath,
			(*string)(&e.Transport), &e.Capabilities, &e.Description,
			&e.CPUHint, &e.MemoryMBHint, &e.RateHint,
			&e.RegisteredAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Get fetches by name.
func (s *Store) Get(ctx context.Context, name string) (Entry, error) {
	var e Entry
	err := s.pool.QueryRow(ctx, `
		SELECT name, language, version, binary_path, transport, capabilities,
		       description, cpu_hint, memory_mb_hint, rate_hint,
		       registered_at, updated_at
		FROM collectors_catalog WHERE name=$1`, name,
	).Scan(&e.Name, &e.Language, &e.Version, &e.BinaryPath, (*string)(&e.Transport),
		&e.Capabilities, &e.Description, &e.CPUHint, &e.MemoryMBHint, &e.RateHint,
		&e.RegisteredAt, &e.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Entry{}, ErrNotFound
	}
	if err != nil {
		return Entry{}, err
	}
	return e, nil
}

// Delete removes an entry by name.
func (s *Store) Delete(ctx context.Context, name string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM collectors_catalog WHERE name=$1`, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
