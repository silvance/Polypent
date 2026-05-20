// Package auth implements API token issuance, lookup, and the HTTP
// middleware that turns a bearer token into an authenticated principal.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Role enumerates the authorization roles a token may carry.
type Role string

const (
	RoleAdmin      Role = "admin" // platform-scoped: project_id NULL
	RoleOwner      Role = "owner"
	RoleOperator   Role = "operator"
	RoleViewer     Role = "viewer"
	RoleAutomation Role = "automation"
)

func (r Role) Valid() bool {
	switch r {
	case RoleAdmin, RoleOwner, RoleOperator, RoleViewer, RoleAutomation:
		return true
	}
	return false
}

// Principal is the authenticated caller produced by the middleware.
type Principal struct {
	TokenID   uuid.UUID
	ProjectID *uuid.UUID // nil for admin / platform-scoped tokens
	Role      Role
}

// Token is an issued, plaintext credential. Returned exactly once.
type Token struct {
	ID        uuid.UUID
	Plaintext string // present only on issuance; never persisted
	ProjectID *uuid.UUID
	Role      Role
	Name      string
	ExpiresAt *time.Time
}

// Store is the persistence-backed token store.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Issue creates and persists a token, returning the plaintext to the caller.
// The plaintext is never written to the database.
func (s *Store) Issue(ctx context.Context, role Role, projectID *uuid.UUID, name string, ttl time.Duration) (Token, error) {
	if !role.Valid() {
		return Token{}, fmt.Errorf("auth: invalid role %q", role)
	}
	if (role == RoleAdmin) != (projectID == nil) {
		return Token{}, errors.New("auth: admin role requires nil project_id; other roles require a project_id")
	}
	if name == "" {
		return Token{}, errors.New("auth: token name is required")
	}

	plain, err := generatePlaintext(role)
	if err != nil {
		return Token{}, err
	}
	hash := hashToken(plain)

	tok := Token{Plaintext: plain, ProjectID: projectID, Role: role, Name: name}
	var expires any
	if ttl > 0 {
		t := time.Now().Add(ttl).UTC()
		tok.ExpiresAt = &t
		expires = t
	}

	err = s.pool.QueryRow(ctx, `
		INSERT INTO api_tokens (project_id, role, name, token_hash, expires_at)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING id`,
		projectID, string(role), name, hash, expires,
	).Scan(&tok.ID)
	if err != nil {
		return Token{}, fmt.Errorf("auth: insert token: %w", err)
	}
	return tok, nil
}

// Lookup resolves a presented plaintext token to a Principal.
// Returns ErrUnauthorized for any failure (unknown / expired / revoked).
func (s *Store) Lookup(ctx context.Context, plaintext string) (Principal, error) {
	plaintext = strings.TrimSpace(plaintext)
	if plaintext == "" {
		return Principal{}, ErrUnauthorized
	}
	hash := hashToken(plaintext)

	var (
		id        uuid.UUID
		projectID *uuid.UUID
		role      string
		expiresAt *time.Time
		revokedAt *time.Time
	)
	err := s.pool.QueryRow(ctx, `
		SELECT id, project_id, role, expires_at, revoked_at
		FROM api_tokens WHERE token_hash = $1`,
		hash,
	).Scan(&id, &projectID, &role, &expiresAt, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Principal{}, ErrUnauthorized
	}
	if err != nil {
		return Principal{}, fmt.Errorf("auth: lookup: %w", err)
	}
	if revokedAt != nil {
		return Principal{}, ErrUnauthorized
	}
	if expiresAt != nil && expiresAt.Before(time.Now()) {
		return Principal{}, ErrUnauthorized
	}

	// best-effort last_used_at touch; don't fail auth if it errors
	_, _ = s.pool.Exec(ctx, `UPDATE api_tokens SET last_used_at = NOW() WHERE id = $1`, id)

	return Principal{TokenID: id, ProjectID: projectID, Role: Role(role)}, nil
}

// HasAny reports whether any token exists. Used to gate bootstrap.
func (s *Store) HasAny(ctx context.Context) (bool, error) {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM api_tokens`).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// ErrUnauthorized is returned for any failed authentication; the cause is
// deliberately not exposed to the caller.
var ErrUnauthorized = errors.New("unauthorized")

func generatePlaintext(role Role) (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "pp_" + string(role) + "_" + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func hashToken(plain string) []byte {
	sum := sha256.Sum256([]byte(plain))
	return sum[:]
}

// ConstantTimeEqual is exported for tests; not used in lookup since we hash
// then compare via the unique index.
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
