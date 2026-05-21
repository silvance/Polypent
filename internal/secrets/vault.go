// Package secrets implements the per-project secrets vault.
//
// Values are encrypted at rest with AES-256-GCM under a key derived
// from the platform master key (currently audit.signing_key) and the
// project UUID via HKDF-SHA256. The plaintext crosses the package
// boundary in exactly two places:
//
//   - Put(): the caller hands plaintext in; the vault encrypts and
//     stores.
//   - Decrypt() (intended for the job-dispatch path in a later phase):
//     reads the row and returns plaintext to the supervisor for
//     marshaling into the JobDescriptor.
//
// The HTTP API NEVER returns plaintext on GET/list paths. Plaintext
// also never reaches audit_events: the audit logger writes only the
// key name and operation, never the value.
package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/hkdf"

	"crypto/sha256"
)

// ErrNotFound is returned by Get/Delete when no row matches.
var ErrNotFound = errors.New("secrets: not found")

// keyRe constrains secret key names to a portable identifier shape so
// they can be safely embedded in JobDescriptor.Parameters and shell
// environments later.
var keyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// Vault is the per-project secrets repository.
type Vault struct {
	pool      *pgxpool.Pool
	masterKey []byte
}

// New constructs a Vault. master must be at least 16 bytes of high-
// entropy material.
func New(pool *pgxpool.Pool, master []byte) (*Vault, error) {
	if len(master) < 16 {
		return nil, errors.New("secrets: master key must be at least 16 bytes")
	}
	return &Vault{pool: pool, masterKey: append([]byte(nil), master...)}, nil
}

// Summary is the metadata-only view returned by List and Put. Plaintext
// is never included.
type Summary struct {
	Key       string    `json:"key"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Put encrypts and stores a secret. Idempotent on (project, key): a
// repeat call rotates the ciphertext (new nonce) and bumps updated_at.
func (v *Vault) Put(ctx context.Context, projectID uuid.UUID, key string, plaintext []byte, actorTokenID *uuid.UUID) (Summary, error) {
	if !keyRe.MatchString(key) {
		return Summary{}, fmt.Errorf("secrets: key %q does not match [A-Za-z_][A-Za-z0-9_]{0,63}", key)
	}
	if len(plaintext) == 0 {
		return Summary{}, errors.New("secrets: empty plaintext")
	}
	pk, err := v.deriveKey(projectID)
	if err != nil {
		return Summary{}, err
	}
	gcm, err := newGCM(pk)
	if err != nil {
		return Summary{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Summary{}, fmt.Errorf("secrets: rand: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, projectIDAdditional(projectID, key))

	var out Summary
	err = v.pool.QueryRow(ctx, `
		INSERT INTO project_secrets (project_id, key, ciphertext, nonce, created_by)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (project_id, key)
		DO UPDATE SET ciphertext=EXCLUDED.ciphertext,
		              nonce=EXCLUDED.nonce,
		              updated_at=NOW()
		RETURNING key, created_at, updated_at`,
		projectID, key, ciphertext, nonce, actorTokenID,
	).Scan(&out.Key, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		return Summary{}, fmt.Errorf("secrets: insert: %w", err)
	}
	return out, nil
}

// List returns metadata-only summaries for a project.
func (v *Vault) List(ctx context.Context, projectID uuid.UUID) ([]Summary, error) {
	rows, err := v.pool.Query(ctx, `
		SELECT key, created_at, updated_at
		FROM project_secrets WHERE project_id=$1 ORDER BY key ASC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Summary
	for rows.Next() {
		var s Summary
		if err := rows.Scan(&s.Key, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Decrypt returns plaintext for a secret. Intended for the job-dispatch
// path; the HTTP API does not expose this directly.
func (v *Vault) Decrypt(ctx context.Context, projectID uuid.UUID, key string) ([]byte, error) {
	var ciphertext, nonce []byte
	err := v.pool.QueryRow(ctx, `
		SELECT ciphertext, nonce FROM project_secrets
		WHERE project_id=$1 AND key=$2`, projectID, key,
	).Scan(&ciphertext, &nonce)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	pk, err := v.deriveKey(projectID)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(pk)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, projectIDAdditional(projectID, key))
	if err != nil {
		return nil, fmt.Errorf("secrets: decrypt: %w", err)
	}
	return plain, nil
}

// Delete removes a secret. Idempotent on missing rows (returns ErrNotFound).
func (v *Vault) Delete(ctx context.Context, projectID uuid.UUID, key string) error {
	tag, err := v.pool.Exec(ctx,
		`DELETE FROM project_secrets WHERE project_id=$1 AND key=$2`, projectID, key)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// deriveKey returns a project-specific 32-byte AES key from the master
// key via HKDF-SHA256 with the project id as salt.
func (v *Vault) deriveKey(projectID uuid.UUID) ([]byte, error) {
	r := hkdf.New(sha256.New, v.masterKey, projectID[:], []byte("polypent-secrets/v1"))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(c)
}

// projectIDAdditional binds the ciphertext to its project_id and key,
// so a row swap across projects or keys would fail to decrypt.
func projectIDAdditional(projectID uuid.UUID, key string) []byte {
	out := make([]byte, 0, 16+len(key))
	out = append(out, projectID[:]...)
	out = append(out, []byte(key)...)
	return out
}
