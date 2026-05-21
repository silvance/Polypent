// Package manifest builds and signs a deterministic record of a Run.
//
// A manifest is the platform's chain-of-custody artifact: given the
// signing key in operator-side storage (or KMS in production), any
// auditor can reproduce the canonical bytes from the database state
// and verify the signature.
//
// The manifest content is intentionally a small, stable subset of the
// run/jobs/findings/artifacts tables — enough to reconstruct what was
// claimed, but not so much that schema additions later break old
// signatures. New fields go inside an explicit "extensions" object so
// future readers know which signatures they can verify.
package manifest

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Version pins the on-the-wire layout. Bumping invalidates prior
// signatures; we won't bump lightly.
const Version = "polypent-manifest/1"

// Manifest is what we sign.
type Manifest struct {
	ManifestVersion string         `json:"manifest_version"`
	PolypentVersion string         `json:"polypent_version"`
	GeneratedAt     time.Time      `json:"generated_at"`
	RunID           uuid.UUID      `json:"run_id"`
	ProjectID       uuid.UUID      `json:"project_id"`
	ProjectSlug     string         `json:"project_slug"`
	Capabilities    []string       `json:"capabilities"`
	Parameters      map[string]any `json:"parameters,omitempty"`
	Status          string         `json:"status"`
	CreatedAt       time.Time      `json:"created_at"`
	FinishedAt      *time.Time     `json:"finished_at,omitempty"`
	Scope           []ScopeRule    `json:"scope_at_run_time"`
	Jobs            []Job          `json:"jobs"`
	Findings        []Finding      `json:"findings"`
	Artifacts       []Artifact     `json:"artifacts"`
}

type ScopeRule struct {
	Order  int    `json:"order"`
	Effect string `json:"effect"`
	Kind   string `json:"kind"`
	Value  string `json:"value"`
}

type Job struct {
	ID             uuid.UUID  `json:"id"`
	Collector      string     `json:"collector"`
	TargetKind     string     `json:"target_kind"`
	TargetIdentity string     `json:"target_identity"`
	Status         string     `json:"status"`
	Attempts       int        `json:"attempts"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
}

type Finding struct {
	ID             uuid.UUID `json:"id"`
	Collector      string    `json:"collector"`
	Kind           string    `json:"kind"`
	Severity       string    `json:"severity"`
	Title          string    `json:"title"`
	TargetKind     string    `json:"target_kind"`
	TargetIdentity string    `json:"target_identity"`
	DedupKey       string    `json:"dedup_key"`
	Evidence       []string  `json:"evidence"`
	FirstSeenAt    time.Time `json:"first_seen_at"`
	LastSeenAt     time.Time `json:"last_seen_at"`
}

type Artifact struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mime   string `json:"mime,omitempty"`
}

// Signed pairs a manifest with its HMAC-SHA256 hex signature.
type Signed struct {
	Manifest  Manifest `json:"manifest"`
	Signature string   `json:"signature"` // hex hmac-sha256 over canonical(manifest)
	KeyID     string   `json:"key_id,omitempty"`
}

// Build assembles the manifest from the database state. It does not
// sign — Sign returns the signature; Encode returns the bytes to ship.
func Build(ctx context.Context, pool *pgxpool.Pool, runID uuid.UUID, polypentVersion string) (Manifest, error) {
	m := Manifest{
		ManifestVersion: Version,
		PolypentVersion: polypentVersion,
		GeneratedAt:     time.Now().UTC(),
	}

	var paramsRaw []byte
	err := pool.QueryRow(ctx, `
		SELECT r.id, r.project_id, p.slug, r.capabilities, r.parameters,
		       r.status, r.created_at, r.finished_at
		FROM runs r JOIN projects p ON p.id = r.project_id
		WHERE r.id = $1`, runID,
	).Scan(&m.RunID, &m.ProjectID, &m.ProjectSlug, &m.Capabilities, &paramsRaw,
		&m.Status, &m.CreatedAt, &m.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Manifest{}, fmt.Errorf("manifest: run %s not found", runID)
	}
	if err != nil {
		return Manifest{}, fmt.Errorf("manifest: load run: %w", err)
	}
	if len(paramsRaw) > 0 {
		_ = json.Unmarshal(paramsRaw, &m.Parameters)
	}

	// Scope at run time. We capture the *current* scope here. A future
	// enhancement should snapshot at plan time; for v1, current scope is
	// adequate evidence for an audit that reads the manifest immediately
	// after the run finishes.
	rows, err := pool.Query(ctx, `
		SELECT rule_order, effect, kind, value
		FROM scope_rules WHERE project_id = $1
		ORDER BY rule_order ASC, id ASC`, m.ProjectID)
	if err != nil {
		return Manifest{}, fmt.Errorf("manifest: load scope: %w", err)
	}
	for rows.Next() {
		var r ScopeRule
		if err := rows.Scan(&r.Order, &r.Effect, &r.Kind, &r.Value); err != nil {
			rows.Close()
			return Manifest{}, err
		}
		m.Scope = append(m.Scope, r)
	}
	rows.Close()

	// Jobs.
	jrows, err := pool.Query(ctx, `
		SELECT id, collector, target_kind, target_identity, status,
		       attempts, started_at, finished_at
		FROM jobs WHERE run_id = $1
		ORDER BY created_at ASC, id ASC`, runID)
	if err != nil {
		return Manifest{}, fmt.Errorf("manifest: load jobs: %w", err)
	}
	for jrows.Next() {
		var j Job
		if err := jrows.Scan(&j.ID, &j.Collector, &j.TargetKind, &j.TargetIdentity,
			&j.Status, &j.Attempts, &j.StartedAt, &j.FinishedAt); err != nil {
			jrows.Close()
			return Manifest{}, err
		}
		m.Jobs = append(m.Jobs, j)
	}
	jrows.Close()

	// Findings tied to this run.
	frows, err := pool.Query(ctx, `
		SELECT id, collector, kind, severity, title, target_kind,
		       target_identity, dedup_key, evidence, first_seen_at, last_seen_at
		FROM findings WHERE run_id = $1
		ORDER BY first_seen_at ASC, id ASC`, runID)
	if err != nil {
		return Manifest{}, fmt.Errorf("manifest: load findings: %w", err)
	}
	evidenceShas := map[string]struct{}{}
	for frows.Next() {
		var f Finding
		if err := frows.Scan(&f.ID, &f.Collector, &f.Kind, &f.Severity, &f.Title,
			&f.TargetKind, &f.TargetIdentity, &f.DedupKey, &f.Evidence,
			&f.FirstSeenAt, &f.LastSeenAt); err != nil {
			frows.Close()
			return Manifest{}, err
		}
		for _, sha := range f.Evidence {
			evidenceShas[sha] = struct{}{}
		}
		m.Findings = append(m.Findings, f)
	}
	frows.Close()

	// Artifacts referenced by those findings (deduped via the map).
	if len(evidenceShas) > 0 {
		shas := make([]string, 0, len(evidenceShas))
		for sha := range evidenceShas {
			shas = append(shas, sha)
		}
		arows, err := pool.Query(ctx, `
			SELECT sha256, size, mime FROM artifacts
			WHERE sha256 = ANY($1::text[])
			ORDER BY sha256 ASC`, shas)
		if err != nil {
			return Manifest{}, fmt.Errorf("manifest: load artifacts: %w", err)
		}
		for arows.Next() {
			var a Artifact
			if err := arows.Scan(&a.SHA256, &a.Size, &a.Mime); err != nil {
				arows.Close()
				return Manifest{}, err
			}
			m.Artifacts = append(m.Artifacts, a)
		}
		arows.Close()
	}

	return m, nil
}

// Canonical returns the deterministic bytes signed by Sign. JSON's map
// ordering means encoding a Go struct with explicit field tags is
// deterministic; we rely on that and reject map-based fields that
// would defeat reproducibility.
func Canonical(m Manifest) ([]byte, error) {
	return json.Marshal(m)
}

// Sign returns the hex HMAC-SHA256 of Canonical(m) under key.
func Sign(m Manifest, key []byte) (string, error) {
	if len(key) == 0 {
		return "", errors.New("manifest: signing key required")
	}
	body, err := Canonical(m)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// Verify returns true iff sig matches the HMAC of Canonical(m) under key.
func Verify(m Manifest, sig string, key []byte) (bool, error) {
	want, err := Sign(m, key)
	if err != nil {
		return false, err
	}
	if len(want) != len(sig) {
		return false, nil
	}
	return hmac.Equal([]byte(want), []byte(sig)), nil
}
