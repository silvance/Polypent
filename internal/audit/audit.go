// Package audit implements PolyPent's hmac-chained audit log.
//
// Every API call, job lifecycle transition, scope decision, and finding
// mutation is appended here. Each event's self_hash is HMAC(secret,
// prev_hash || canonical(event)), so a single tampered or removed row breaks
// the chain at that point.
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// advisoryLockKey serializes audit appends so reads of prev_hash are not
// raced. The constant is the ASCII bytes "POLYAUDT" packed as int64.
const advisoryLockKey = int64(0x504F4C5941554454)

// Event is the input to Append. The fields that participate in the chain
// hash are exactly those serialized by canonical().
type Event struct {
	ProjectID    *uuid.UUID     `json:"project_id,omitempty"`
	ActorTokenID *uuid.UUID     `json:"actor_token_id,omitempty"`
	Action       string         `json:"action"`
	TargetKind   string         `json:"target_kind"`
	TargetID     string         `json:"target_id"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

// Written is the persisted form returned by Append.
type Written struct {
	ID       int64
	PrevHash []byte
	SelfHash []byte
}

// Logger appends and verifies events. The signing key MUST NOT be logged or
// exposed via the API.
type Logger struct {
	pool *pgxpool.Pool
	key  []byte
}

// New constructs a Logger. The key is the audit signing key from config.
func New(pool *pgxpool.Pool, key []byte) (*Logger, error) {
	if len(key) == 0 {
		return nil, errors.New("audit: signing key must not be empty")
	}
	return &Logger{pool: pool, key: append([]byte(nil), key...)}, nil
}

// Append writes a new event and returns its row id and computed hashes.
func (l *Logger) Append(ctx context.Context, e Event) (Written, error) {
	if e.Action == "" || e.TargetKind == "" {
		return Written{}, errors.New("audit: action and target_kind required")
	}

	canon, err := canonical(e)
	if err != nil {
		return Written{}, fmt.Errorf("audit: canonicalize: %w", err)
	}
	metaJSON, err := metadataJSON(e.Metadata)
	if err != nil {
		return Written{}, fmt.Errorf("audit: metadata: %w", err)
	}

	tx, err := l.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Written{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", advisoryLockKey); err != nil {
		return Written{}, fmt.Errorf("audit: advisory lock: %w", err)
	}

	var prev []byte
	err = tx.QueryRow(ctx,
		`SELECT self_hash FROM audit_events ORDER BY id DESC LIMIT 1`,
	).Scan(&prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Written{}, fmt.Errorf("audit: read prev: %w", err)
	}

	self := chainHash(l.key, prev, canon)

	var out Written
	out.PrevHash = prev
	out.SelfHash = self
	err = tx.QueryRow(ctx, `
		INSERT INTO audit_events
		    (project_id, actor_token_id, action, target_kind, target_id,
		     metadata, prev_hash, self_hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id`,
		e.ProjectID, e.ActorTokenID, e.Action, e.TargetKind, e.TargetID,
		metaJSON, prev, self,
	).Scan(&out.ID)
	if err != nil {
		return Written{}, fmt.Errorf("audit: insert: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Written{}, err
	}
	return out, nil
}

// Verify walks the entire audit log in id order and recomputes each row's
// self_hash. It returns the id of the first row that fails, or 0 if the
// chain is intact.
func (l *Logger) Verify(ctx context.Context) (int64, error) {
	rows, err := l.pool.Query(ctx, `
		SELECT id, project_id, actor_token_id, action, target_kind,
		       target_id, metadata, prev_hash, self_hash
		FROM audit_events ORDER BY id ASC`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var lastHash []byte
	for rows.Next() {
		var id int64
		var projectID, actorID *uuid.UUID
		var action, targetKind, targetID string
		var metaRaw []byte
		var prev, self []byte
		if err := rows.Scan(&id, &projectID, &actorID, &action, &targetKind,
			&targetID, &metaRaw, &prev, &self); err != nil {
			return 0, err
		}

		if !bytesEqualOptional(prev, lastHash) {
			return id, nil
		}

		var meta map[string]any
		if len(metaRaw) > 0 {
			if err := json.Unmarshal(metaRaw, &meta); err != nil {
				return id, nil
			}
		}
		ev := Event{
			ProjectID:    projectID,
			ActorTokenID: actorID,
			Action:       action,
			TargetKind:   targetKind,
			TargetID:     targetID,
			Metadata:     meta,
		}
		canon, err := canonical(ev)
		if err != nil {
			return id, nil
		}
		want := chainHash(l.key, prev, canon)
		if !hmac.Equal(want, self) {
			return id, nil
		}
		lastHash = self
	}
	return 0, rows.Err()
}

func chainHash(key, prev, canon []byte) []byte {
	mac := hmac.New(sha256.New, key)
	// length-prefix prev so prev=nil and prev="" don't collide
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(prev)))
	mac.Write(l[:])
	mac.Write(prev)
	mac.Write(canon)
	return mac.Sum(nil)
}

// canonical returns the deterministic bytes hashed into the chain.
// json.Marshal sorts map keys alphabetically, and our struct has fixed
// field order via tags, so the result is reproducible.
func canonical(e Event) ([]byte, error) {
	// We marshal a fresh map (sorted by key) to guarantee field order across
	// Go versions and to keep the canonical form independent of struct
	// declaration order.
	m := map[string]any{
		"action":      e.Action,
		"target_kind": e.TargetKind,
		"target_id":   e.TargetID,
	}
	if e.ProjectID != nil {
		m["project_id"] = e.ProjectID.String()
	}
	if e.ActorTokenID != nil {
		m["actor_token_id"] = e.ActorTokenID.String()
	}
	if len(e.Metadata) > 0 {
		m["metadata"] = e.Metadata
	}
	return json.Marshal(m)
}

func metadataJSON(m map[string]any) ([]byte, error) {
	if len(m) == 0 {
		return []byte(`{}`), nil
	}
	return json.Marshal(m)
}

func bytesEqualOptional(a, b []byte) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return hmac.Equal(a, b)
}
