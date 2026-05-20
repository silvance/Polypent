package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/silvance/polypent/internal/api"
	"github.com/silvance/polypent/internal/audit"
	"github.com/silvance/polypent/internal/auth"
	"github.com/silvance/polypent/internal/project"
	pgstore "github.com/silvance/polypent/internal/store/postgres"
)

// testDSN returns the DSN for a Postgres database to run integration tests
// against. Tests are skipped when POLYPENT_TEST_DATABASE_URL is unset so
// `go test ./...` succeeds out-of-the-box on a fresh checkout without
// requiring Docker.
func testDSN(t *testing.T) string {
	dsn := os.Getenv("POLYPENT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("POLYPENT_TEST_DATABASE_URL not set; skipping integration test")
	}
	return dsn
}

func resetSchema(t *testing.T, dsn string) {
	t.Helper()
	if err := pgstore.MigrateDown(dsn); err != nil {
		t.Logf("migrate down (may be empty): %v", err)
	}
	if err := pgstore.Migrate(dsn); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
}

func newTestServer(t *testing.T, dsn string) (*httptest.Server, auth.Token) {
	t.Helper()
	ctx := context.Background()
	pool, err := pgstore.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(pool.Close)

	tokens := auth.NewStore(pool)
	logger, err := audit.New(pool, []byte("test-key-32-bytes-aaaaaaaaaaaaaaaa"))
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	projects := project.NewStore(pool)

	adminTok, err := tokens.Issue(ctx, auth.RoleAdmin, nil, "bootstrap", 0)
	if err != nil {
		t.Fatalf("issue admin: %v", err)
	}

	slogger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelWarn}))
	srv := api.New(":0", time.Second, api.Deps{
		Logger:   slogger,
		Projects: projects,
		Tokens:   tokens,
		Audit:    logger,
	})

	httptestSrv := httptest.NewServer(srv.Handler)
	t.Cleanup(httptestSrv.Close)
	return httptestSrv, adminTok
}

type apiClient struct {
	t   *testing.T
	url string
	tok string
}

func (c *apiClient) do(method, path string, body any) (int, []byte) {
	c.t.Helper()
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.t.Fatalf("marshal: %v", err)
		}
		buf = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.url+path, buf)
	if err != nil {
		c.t.Fatalf("req: %v", err)
	}
	if c.tok != "" {
		req.Header.Set("Authorization", "Bearer "+c.tok)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestProjectLifecycleAndAuditChain(t *testing.T) {
	dsn := testDSN(t)
	resetSchema(t, dsn)
	srv, adminTok := newTestServer(t, dsn)

	c := &apiClient{t: t, url: srv.URL, tok: adminTok.Plaintext}

	// 1. health (unauthenticated)
	status, _ := (&apiClient{t: t, url: srv.URL}).do("GET", "/healthz", nil)
	if status != http.StatusOK {
		t.Fatalf("healthz: %d", status)
	}

	// 2. unauthenticated v1 request → 401
	status, _ = (&apiClient{t: t, url: srv.URL}).do("GET", "/v1/projects", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 on unauthenticated v1, got %d", status)
	}

	// 3. create project
	status, body := c.do("POST", "/v1/projects", map[string]any{
		"slug": "acme-2026", "name": "Acme Engagement", "owner": "alice@example.com",
	})
	if status != http.StatusCreated {
		t.Fatalf("create: %d body=%s", status, body)
	}
	var created project.Project
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.Slug != "acme-2026" {
		t.Errorf("slug = %q", created.Slug)
	}

	// 4. list contains it
	status, body = c.do("GET", "/v1/projects", nil)
	if status != http.StatusOK {
		t.Fatalf("list: %d", status)
	}
	if !strings.Contains(string(body), "acme-2026") {
		t.Errorf("list did not contain new project: %s", body)
	}

	// 5. get
	status, body = c.do("GET", "/v1/projects/"+created.ID.String(), nil)
	if status != http.StatusOK {
		t.Fatalf("get: %d %s", status, body)
	}

	// 6. patch
	newDesc := "internal pentest, Q2 2026"
	status, body = c.do("PATCH", "/v1/projects/"+created.ID.String(), map[string]any{
		"description": newDesc,
	})
	if status != http.StatusOK {
		t.Fatalf("patch: %d %s", status, body)
	}
	var updated project.Project
	_ = json.Unmarshal(body, &updated)
	if updated.Description != newDesc {
		t.Errorf("description not updated: %q", updated.Description)
	}

	// 7. slug conflict
	status, _ = c.do("POST", "/v1/projects", map[string]any{
		"slug": "acme-2026", "name": "dup", "owner": "x",
	})
	if status != http.StatusConflict {
		t.Errorf("expected 409 on slug conflict, got %d", status)
	}

	// 8. issue an owner token, verify it can see only its project
	status, body = c.do("POST", "/v1/tokens", map[string]any{
		"role": "owner", "project_id": created.ID.String(), "name": "alice",
	})
	if status != http.StatusCreated {
		t.Fatalf("issue owner: %d %s", status, body)
	}
	var issued struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(body, &issued)
	ownerClient := &apiClient{t: t, url: srv.URL, tok: issued.Token}
	status, _ = ownerClient.do("POST", "/v1/projects", map[string]any{
		"slug": "other", "name": "x", "owner": "y",
	})
	if status != http.StatusForbidden {
		t.Errorf("owner should not create projects, got %d", status)
	}

	// 9. audit chain verifies clean
	pool, err := pgstore.Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	logger, err := audit.New(pool, []byte("test-key-32-bytes-aaaaaaaaaaaaaaaa"))
	if err != nil {
		t.Fatal(err)
	}
	bad, err := logger.Verify(context.Background())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if bad != 0 {
		t.Errorf("audit chain broke at id=%d", bad)
	}

	// 10. confirm rows are actually present
	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM audit_events WHERE action IN ('project.create','project.update','token.issue')`).
		Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count < 3 {
		t.Errorf("expected at least 3 audit events, got %d", count)
	}

	// 11. tamper detection: flip a byte in metadata of the first event
	if _, err := pool.Exec(context.Background(),
		`UPDATE audit_events SET metadata = jsonb_set(metadata, '{tampered}', '"yes"') WHERE id = (SELECT MIN(id) FROM audit_events)`,
	); err != nil {
		t.Fatal(err)
	}
	bad, err = logger.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if bad == 0 {
		t.Errorf("tampered event was not detected")
	}
}
