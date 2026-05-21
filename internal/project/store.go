package project

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Common errors.
var (
	ErrNotFound     = errors.New("project: not found")
	ErrSlugConflict = errors.New("project: slug already in use")
)

// Store is the Postgres-backed project repository.
type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Create inserts a project. Caller must have validated the input.
func (s *Store) Create(ctx context.Context, in CreateInput) (Project, error) {
	retention := in.RetentionDays
	if retention == 0 {
		retention = 365
	}
	var p Project
	err := s.pool.QueryRow(ctx, `
		INSERT INTO projects (slug, name, owner, description, roe_hash,
		                      contract_start, contract_end, retention_days)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id, slug, name, owner, description, roe_hash,
		          contract_start, contract_end, retention_days,
		          max_concurrent_jobs, created_at, updated_at`,
		in.Slug, in.Name, in.Owner, in.Description, in.ROEHash,
		in.ContractStart, in.ContractEnd, retention,
	).Scan(&p.ID, &p.Slug, &p.Name, &p.Owner, &p.Description, &p.ROEHash,
		&p.ContractStart, &p.ContractEnd, &p.RetentionDays,
		&p.MaxConcurrentJobs, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return Project{}, ErrSlugConflict
		}
		return Project{}, fmt.Errorf("project: insert: %w", err)
	}
	return p, nil
}

// Get fetches by id.
func (s *Store) Get(ctx context.Context, id uuid.UUID) (Project, error) {
	var p Project
	err := s.pool.QueryRow(ctx, `
		SELECT id, slug, name, owner, description, roe_hash,
		       contract_start, contract_end, retention_days,
		       max_concurrent_jobs, created_at, updated_at
		FROM projects WHERE id = $1`, id,
	).Scan(&p.ID, &p.Slug, &p.Name, &p.Owner, &p.Description, &p.ROEHash,
		&p.ContractStart, &p.ContractEnd, &p.RetentionDays,
		&p.MaxConcurrentJobs, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Project{}, ErrNotFound
	}
	if err != nil {
		return Project{}, err
	}
	return p, nil
}

// List returns all projects ordered by created_at asc.
func (s *Store) List(ctx context.Context) ([]Project, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, slug, name, owner, description, roe_hash,
		       contract_start, contract_end, retention_days,
		       max_concurrent_jobs, created_at, updated_at
		FROM projects ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.Slug, &p.Name, &p.Owner, &p.Description, &p.ROEHash,
			&p.ContractStart, &p.ContractEnd, &p.RetentionDays,
			&p.MaxConcurrentJobs, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Update applies a partial patch.
func (s *Store) Update(ctx context.Context, id uuid.UUID, in UpdateInput) (Project, error) {
	// We rely on COALESCE so callers can pass NULL for unchanged fields.
	var p Project
	err := s.pool.QueryRow(ctx, `
		UPDATE projects SET
		    name                = COALESCE($2, name),
		    owner               = COALESCE($3, owner),
		    description         = COALESCE($4, description),
		    roe_hash            = COALESCE($5, roe_hash),
		    contract_start      = COALESCE($6, contract_start),
		    contract_end        = COALESCE($7, contract_end),
		    retention_days      = COALESCE($8, retention_days),
		    max_concurrent_jobs = COALESCE($9, max_concurrent_jobs),
		    updated_at          = NOW()
		WHERE id = $1
		RETURNING id, slug, name, owner, description, roe_hash,
		          contract_start, contract_end, retention_days,
		          max_concurrent_jobs, created_at, updated_at`,
		id, in.Name, in.Owner, in.Description, in.ROEHash,
		in.ContractStart, in.ContractEnd, in.RetentionDays, in.MaxConcurrentJobs,
	).Scan(&p.ID, &p.Slug, &p.Name, &p.Owner, &p.Description, &p.ROEHash,
		&p.ContractStart, &p.ContractEnd, &p.RetentionDays,
		&p.MaxConcurrentJobs, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Project{}, ErrNotFound
	}
	if err != nil {
		return Project{}, err
	}
	return p, nil
}
