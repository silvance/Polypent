// Package artifact owns the content-addressed evidence store.
//
// Bytes live behind the Store interface (local filesystem in v1; an
// S3-compatible backend lands later under the same shape). Metadata lives
// in the `artifacts` table; this package owns the bytes, not the table.
package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ErrNotFound is returned when a sha is unknown to the backend.
var ErrNotFound = errors.New("artifact: not found")

// Store is the content-addressed blob backend.
type Store interface {
	// Put writes r to the backend, returning the hex sha256 and byte
	// count. Put is idempotent: writing the same bytes twice is a no-op
	// from the caller's perspective and the second call returns the same
	// hash with no error.
	Put(ctx context.Context, r io.Reader) (sha string, size int64, err error)
	// Open returns a ReadCloser for the artifact. Caller closes.
	Open(ctx context.Context, sha string) (io.ReadCloser, error)
	// Stat returns size and existence.
	Stat(ctx context.Context, sha string) (size int64, exists bool, err error)
}

// LocalFS persists artifacts under `<Root>/<aa>/<bb>/<sha>`.
type LocalFS struct {
	Root string
}

// NewLocalFS validates Root and returns a Store.
func NewLocalFS(root string) (*LocalFS, error) {
	if root == "" {
		return nil, errors.New("artifact: root path required")
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, fmt.Errorf("artifact: mkdir root: %w", err)
	}
	return &LocalFS{Root: root}, nil
}

func (l *LocalFS) shardPath(sha string) string {
	return filepath.Join(l.Root, sha[:2], sha[2:4], sha)
}

func (l *LocalFS) Put(_ context.Context, r io.Reader) (string, int64, error) {
	tmp, err := os.CreateTemp(l.Root, ".put-*")
	if err != nil {
		return "", 0, fmt.Errorf("artifact: tempfile: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	h := sha256.New()
	mw := io.MultiWriter(tmp, h)
	n, err := io.Copy(mw, r)
	if err != nil {
		_ = tmp.Close()
		return "", 0, fmt.Errorf("artifact: copy: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", 0, err
	}
	sha := hex.EncodeToString(h.Sum(nil))
	dest := l.shardPath(sha)
	if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
		return "", 0, fmt.Errorf("artifact: mkdir shard: %w", err)
	}
	// Idempotent: if a file with that sha already exists, accept it.
	if _, err := os.Stat(dest); err == nil {
		return sha, n, nil
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return "", 0, fmt.Errorf("artifact: rename: %w", err)
	}
	return sha, n, nil
}

func (l *LocalFS) Open(_ context.Context, sha string) (io.ReadCloser, error) {
	if !validSHA(sha) {
		return nil, ErrNotFound
	}
	f, err := os.Open(l.shardPath(sha))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return f, err
}

func (l *LocalFS) Stat(_ context.Context, sha string) (int64, bool, error) {
	if !validSHA(sha) {
		return 0, false, nil
	}
	st, err := os.Stat(l.shardPath(sha))
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return st.Size(), true, nil
}

// validSHA ensures the input is plausibly a hex sha256: 64 lowercase hex
// chars. Path-injection from a malicious caller is the threat we close
// here.
func validSHA(sha string) bool {
	if len(sha) != 64 {
		return false
	}
	for i := 0; i < len(sha); i++ {
		c := sha[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}
