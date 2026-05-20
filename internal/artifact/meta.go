package artifact

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Meta is a metadata row for an artifact.
type Meta struct {
	SHA256    string     `json:"sha256"`
	Size      int64      `json:"size"`
	Mime      string     `json:"mime"`
	Label     string     `json:"label"`
	ProjectID *uuid.UUID `json:"project_id,omitempty"`
	JobID     *uuid.UUID `json:"job_id,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// MetaStore is the Postgres-backed metadata side of the artifact store.
type MetaStore struct{ pool *pgxpool.Pool }

func NewMetaStore(pool *pgxpool.Pool) *MetaStore { return &MetaStore{pool: pool} }

// Record inserts a metadata row. Idempotent on the primary key (sha256):
// re-recording the same artifact is allowed and refreshes the label / job
// linkage.
func (m *MetaStore) Record(ctx context.Context, meta Meta) error {
	_, err := m.pool.Exec(ctx, `
		INSERT INTO artifacts (sha256, size, mime, label, project_id, job_id)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (sha256) DO UPDATE
		    SET label = EXCLUDED.label,
		        job_id = COALESCE(EXCLUDED.job_id, artifacts.job_id),
		        project_id = COALESCE(EXCLUDED.project_id, artifacts.project_id)`,
		meta.SHA256, meta.Size, meta.Mime, meta.Label, meta.ProjectID, meta.JobID,
	)
	if err != nil {
		return fmt.Errorf("artifact: record meta: %w", err)
	}
	return nil
}

// Get fetches metadata for a sha.
func (m *MetaStore) Get(ctx context.Context, sha string) (Meta, error) {
	var out Meta
	err := m.pool.QueryRow(ctx, `
		SELECT sha256, size, mime, label, project_id, job_id, created_at
		FROM artifacts WHERE sha256 = $1`, sha,
	).Scan(&out.SHA256, &out.Size, &out.Mime, &out.Label, &out.ProjectID, &out.JobID, &out.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Meta{}, ErrNotFound
	}
	if err != nil {
		return Meta{}, err
	}
	return out, nil
}
