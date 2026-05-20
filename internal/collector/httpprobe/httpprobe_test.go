package httpprobe

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/silvance/polypent/internal/collector"
	"github.com/silvance/polypent/internal/queue"
)

type recorder struct {
	mu     sync.Mutex
	events []collector.Event
}

func (r *recorder) emit(_ context.Context, e collector.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func (r *recorder) byKind(kind string) []collector.Event {
	var out []collector.Event
	for _, e := range r.events {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

func TestProbeHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Server", "test-server")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("hello from httpprobe test\n"))
	}))
	defer srv.Close()

	c := New()
	// Use the test server's certs for the client.
	c.client.Transport = srv.Client().Transport
	// Restore strict TLS minimum.
	if t, ok := c.client.Transport.(*http.Transport); ok && t.TLSClientConfig != nil {
		t.TLSClientConfig.MinVersion = tls.VersionTLS12
	}

	rec := &recorder{}
	job := queue.Job{
		ID:             uuid.New(),
		RunID:          uuid.New(),
		ProjectID:      uuid.New(),
		Collector:      Name,
		TargetKind:     "url",
		TargetIdentity: srv.URL,
	}
	if err := c.Execute(context.Background(), job, rec.emit); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if got := rec.byKind("finding"); len(got) != 2 {
		t.Fatalf("findings: want 2 (live + tls), got %d: %+v", len(got), got)
	}
	if got := rec.byKind("artifact_ref"); len(got) != 1 {
		t.Fatalf("artifact_ref: want 1, got %d", len(got))
	}
	if got := rec.byKind("done"); len(got) != 1 {
		t.Fatalf("done: want 1, got %d", len(got))
	}

	live := rec.byKind("finding")[0]
	if k, _ := live.Payload["kind"].(string); k != "info.http.live" {
		t.Errorf("first finding kind = %v", live.Payload["kind"])
	}
	if dk, _ := live.Payload["dedup_key"].(string); dk == "" {
		t.Errorf("missing dedup_key")
	}
}

func TestProbeHTTP404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()

	c := New()
	rec := &recorder{}
	job := queue.Job{
		ID:             uuid.New(),
		RunID:          uuid.New(),
		ProjectID:      uuid.New(),
		TargetKind:     "url",
		TargetIdentity: srv.URL,
	}
	if err := c.Execute(context.Background(), job, rec.emit); err != nil {
		t.Fatal(err)
	}
	if got := rec.byKind("finding"); len(got) != 1 {
		t.Fatalf("findings: want 1 (no tls), got %d", len(got))
	}
}

func TestBuildURLHostTarget(t *testing.T) {
	got, err := buildURL(queue.Job{TargetKind: "host", TargetIdentity: "example.com:443"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://example.com:443/" {
		t.Errorf("got %q", got)
	}
}
