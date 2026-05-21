package artifact

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestLocalFSPutGetIdempotent(t *testing.T) {
	store, err := NewLocalFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	body := []byte("hello world")
	sha1, n1, err := store.Put(ctx, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if n1 != int64(len(body)) {
		t.Errorf("size mismatch: %d", n1)
	}
	if len(sha1) != 64 {
		t.Errorf("sha length: %d", len(sha1))
	}
	// Second put returns same sha and does not error.
	sha2, _, err := store.Put(ctx, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if sha1 != sha2 {
		t.Errorf("sha differs across puts: %q vs %q", sha1, sha2)
	}

	r, err := store.Open(ctx, sha1)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r)
	_ = r.Close()
	if !bytes.Equal(got, body) {
		t.Errorf("get returned %q want %q", got, body)
	}

	size, exists, err := store.Stat(ctx, sha1)
	if err != nil || !exists || size != int64(len(body)) {
		t.Errorf("stat: size=%d exists=%v err=%v", size, exists, err)
	}
	if _, exists, _ := store.Stat(ctx, strings.Repeat("0", 64)); exists {
		t.Errorf("unknown sha reported existing")
	}
}

func TestLocalFSRejectsPathTraversal(t *testing.T) {
	store, _ := NewLocalFS(t.TempDir())
	if _, err := store.Open(context.Background(), "../etc/passwd"); err == nil {
		t.Fatal("expected error for invalid sha")
	}
}
