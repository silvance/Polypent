// Package finding owns the normalized finding model and its persistence.
//
// Findings are inserted via Upsert which uses ON CONFLICT against the
// (project_id, collector, dedup_key) unique key: re-running a collector
// produces an idempotent record, with last_seen_at advancing and
// evidence accumulating.
package finding

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Severity values from the architecture doc.
type Severity string

const (
	SeverityInfo     Severity = "informational"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func (s Severity) Valid() bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

// Finding is the persisted entity.
type Finding struct {
	ID             uuid.UUID  `json:"id"`
	ProjectID      uuid.UUID  `json:"project_id"`
	RunID          *uuid.UUID `json:"run_id,omitempty"`
	JobID          *uuid.UUID `json:"job_id,omitempty"`
	Collector      string     `json:"collector"`
	TargetKind     string     `json:"target_kind"`
	TargetIdentity string     `json:"target_identity"`
	Kind           string     `json:"kind"`
	Severity       Severity   `json:"severity"`
	Title          string     `json:"title"`
	Description    string     `json:"description"`
	CVSS           string     `json:"cvss,omitempty"`
	DedupKey       string     `json:"dedup_key"`
	Evidence       []string   `json:"evidence"`
	Status         string     `json:"status"`
	FirstSeenAt    time.Time  `json:"first_seen_at"`
	LastSeenAt     time.Time  `json:"last_seen_at"`
}

// Input is the supervisor's hand-off to Upsert.
type Input struct {
	ProjectID      uuid.UUID
	RunID          *uuid.UUID
	JobID          *uuid.UUID
	Collector      string
	TargetKind     string
	TargetIdentity string
	Kind           string
	Severity       Severity
	Title          string
	Description    string
	CVSS           string
	DedupKey       string
	Evidence       []string       // artifact sha256s
	Extra          map[string]any // collector-specific payload
}

// Validate sanity-checks the input. The supervisor calls Validate before
// persisting so a malformed collector emits show up as 'error' events
// rather than dropped rows.
func (in *Input) Validate() error {
	if in.ProjectID == uuid.Nil {
		return errors.New("finding: project_id required")
	}
	if in.Collector == "" {
		return errors.New("finding: collector required")
	}
	if in.TargetIdentity == "" {
		return errors.New("finding: target_identity required")
	}
	if in.Kind == "" {
		return errors.New("finding: kind required")
	}
	if in.Title == "" {
		return errors.New("finding: title required")
	}
	if !in.Severity.Valid() {
		return fmt.Errorf("finding: invalid severity %q", in.Severity)
	}
	if in.DedupKey == "" {
		in.DedupKey = DeriveDedupKey(in.TargetIdentity, in.Kind, in.Title)
	}
	return nil
}

// DeriveDedupKey is the fallback used when the collector doesn't supply
// one. It's deliberately conservative — a more nuanced derivation belongs
// inside the collector.
func DeriveDedupKey(target, kind, title string) string {
	h := sha256.New()
	h.Write([]byte(target))
	h.Write([]byte{0})
	h.Write([]byte(kind))
	h.Write([]byte{0})
	h.Write([]byte(strings.ToLower(title)))
	return "auto:" + hex.EncodeToString(h.Sum(nil))[:32]
}

// Store is the Postgres-backed finding repository.
type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// UpsertResult tells the caller whether the row was inserted (true) or an
// existing one was updated.
type UpsertResult struct {
	Finding  Finding
	Inserted bool
}

// Upsert inserts or refreshes a finding. On re-emit:
//   - last_seen_at advances
//   - description, severity, evidence, cvss, payload get the latest values
//   - first_seen_at and id are preserved
func (s *Store) Upsert(ctx context.Context, in Input) (UpsertResult, error) {
	if err := in.Validate(); err != nil {
		return UpsertResult{}, err
	}
	if in.Evidence == nil {
		in.Evidence = []string{}
	}
	payload := []byte("{}")
	if len(in.Extra) > 0 {
		b, err := json.Marshal(in.Extra)
		if err != nil {
			return UpsertResult{}, fmt.Errorf("finding: payload: %w", err)
		}
		payload = b
	}

	var f Finding
	var status string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO findings
		    (project_id, run_id, job_id, collector, target_kind, target_identity,
		     kind, severity, title, description, cvss, dedup_key, evidence, payload)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (project_id, collector, dedup_key)
		DO UPDATE SET
		    last_seen_at = NOW(),
		    severity     = EXCLUDED.severity,
		    title        = EXCLUDED.title,
		    description  = EXCLUDED.description,
		    cvss         = EXCLUDED.cvss,
		    evidence     = (
		        SELECT ARRAY(
		            SELECT DISTINCT e FROM unnest(findings.evidence || EXCLUDED.evidence) AS e
		        )
		    ),
		    payload      = EXCLUDED.payload,
		    run_id       = EXCLUDED.run_id,
		    job_id       = EXCLUDED.job_id
		RETURNING id, project_id, run_id, job_id, collector, target_kind,
		          target_identity, kind, severity, title, description, cvss,
		          dedup_key, evidence, status, first_seen_at, last_seen_at,
		          (xmax = 0) AS inserted`,
		in.ProjectID, in.RunID, in.JobID, in.Collector, in.TargetKind, in.TargetIdentity,
		in.Kind, string(in.Severity), in.Title, in.Description, in.CVSS,
		in.DedupKey, in.Evidence, payload,
	).Scan(&f.ID, &f.ProjectID, &f.RunID, &f.JobID, &f.Collector, &f.TargetKind,
		&f.TargetIdentity, &f.Kind, (*string)(&f.Severity), &f.Title, &f.Description, &f.CVSS,
		&f.DedupKey, &f.Evidence, &status, &f.FirstSeenAt, &f.LastSeenAt,
		new(bool))
	if err != nil {
		return UpsertResult{}, fmt.Errorf("finding: upsert: %w", err)
	}
	f.Status = status

	// xmax == 0 indicates a fresh insert. Reread it here since we scanned
	// it into a discarded *bool above (Postgres returns it as boolean).
	var inserted bool
	if err := s.pool.QueryRow(ctx, `
		SELECT first_seen_at = last_seen_at FROM findings WHERE id=$1`, f.ID,
	).Scan(&inserted); err != nil {
		return UpsertResult{}, err
	}
	return UpsertResult{Finding: f, Inserted: inserted}, nil
}

// ListFilter narrows ListByProject results.
type ListFilter struct {
	Severity Severity
	Kind     string
	RunID    *uuid.UUID
}

// ListByProject returns matching findings for a project.
func (s *Store) ListByProject(ctx context.Context, projectID uuid.UUID, f ListFilter) ([]Finding, error) {
	q := `SELECT id, project_id, run_id, job_id, collector, target_kind,
	             target_identity, kind, severity, title, description, cvss,
	             dedup_key, evidence, status, first_seen_at, last_seen_at
	      FROM findings WHERE project_id=$1`
	args := []any{projectID}
	if f.Severity != "" {
		args = append(args, string(f.Severity))
		q += fmt.Sprintf(" AND severity=$%d", len(args))
	}
	if f.Kind != "" {
		args = append(args, f.Kind)
		q += fmt.Sprintf(" AND kind=$%d", len(args))
	}
	if f.RunID != nil {
		args = append(args, *f.RunID)
		q += fmt.Sprintf(" AND run_id=$%d", len(args))
	}
	q += " ORDER BY last_seen_at DESC"
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var fnd Finding
		if err := rows.Scan(&fnd.ID, &fnd.ProjectID, &fnd.RunID, &fnd.JobID, &fnd.Collector,
			&fnd.TargetKind, &fnd.TargetIdentity, &fnd.Kind, (*string)(&fnd.Severity),
			&fnd.Title, &fnd.Description, &fnd.CVSS, &fnd.DedupKey, &fnd.Evidence,
			&fnd.Status, &fnd.FirstSeenAt, &fnd.LastSeenAt); err != nil {
			return nil, err
		}
		out = append(out, fnd)
	}
	return out, rows.Err()
}
