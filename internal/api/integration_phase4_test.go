package api_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/silvance/polypent/internal/api"
	"github.com/silvance/polypent/internal/artifact"
	"github.com/silvance/polypent/internal/audit"
	"github.com/silvance/polypent/internal/auth"
	"github.com/silvance/polypent/internal/catalog"
	"github.com/silvance/polypent/internal/collector"
	"github.com/silvance/polypent/internal/collector/mock"
	"github.com/silvance/polypent/internal/finding"
	"github.com/silvance/polypent/internal/project"
	"github.com/silvance/polypent/internal/queue"
	"github.com/silvance/polypent/internal/run"
	"github.com/silvance/polypent/internal/scope"
	pgstore "github.com/silvance/polypent/internal/store/postgres"
	"github.com/silvance/polypent/internal/target"
	"github.com/silvance/polypent/internal/worker"
)

func findPython(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"python3", "python"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	t.Skip("python3 not available; skipping external-collector test")
	return ""
}

func echoCollectorPath(t *testing.T) string {
	t.Helper()
	// Repo root is two directories above this test file: internal/api/ -> ../..
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	p := filepath.Join(root, "collectors", "python", "echo", "main.py")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("echo collector not found at %s: %v", p, err)
	}
	return p
}

// fullStack wires every Phase-1..4 store and starts a worker pool. The
// test owns the lifecycle: call shutdown when done.
type fullStack struct {
	srv      *httptest.Server
	pool     *queue.Queue
	worker   *worker.Pool
	shutdown func()
	adminTok auth.Token
	dsn      string
}

func newFullStack(t *testing.T) *fullStack {
	t.Helper()
	dsn := testDSN(t)
	resetSchema(t, dsn)
	ctx, cancel := context.WithCancel(context.Background())

	pgPool, err := pgstore.Open(ctx, dsn)
	if err != nil {
		cancel()
		t.Fatal(err)
	}

	tokens := auth.NewStore(pgPool)
	auditLog, _ := audit.New(pgPool, []byte("p4-key-32-bytes-aaaaaaaaaaaaaaaaa"))
	projects := project.NewStore(pgPool)
	sc := scope.NewStore(pgPool)
	q := queue.New(pgPool, 5*time.Second)
	findings := finding.NewStore(pgPool)
	artifactsFS, err := artifact.NewLocalFS(t.TempDir())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	artifactMD := artifact.NewMetaStore(pgPool)
	cat := catalog.NewStore(pgPool)

	reg := collector.NewRegistry()
	reg.Register(mock.New())

	adminTok, err := tokens.Issue(ctx, auth.RoleAdmin, nil, "p4", 0)
	if err != nil {
		cancel()
		t.Fatal(err)
	}

	logHandler := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})
	if os.Getenv("POLYPENT_TEST_VERBOSE") != "" {
		logHandler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	}
	slogger := slog.New(logHandler)

	srv := api.New(":0", time.Second, api.Deps{
		Logger:       slogger,
		Projects:     projects,
		Tokens:       tokens,
		Audit:        auditLog,
		AuditKey:     []byte("p4-key-32-bytes-aaaaaaaaaaaaaaaaa"),
		Scope:        sc,
		Targets:      target.NewStore(pgPool),
		Planner:      run.NewPlanner(pgPool, q, sc, auditLog),
		Runs:         run.NewStore(pgPool),
		Queue:        q,
		Collectors:   reg,
		Findings:     findings,
		Artifacts:    artifactsFS,
		ArtifactMeta: artifactMD,
		Catalog:      cat,
	})
	ht := httptest.NewServer(srv.Handler)

	pool := worker.New(q, reg, slogger, worker.Options{
		Size:         3,
		Poll:         50 * time.Millisecond,
		Findings:     findings,
		Artifacts:    artifactsFS,
		ArtifactMeta: artifactMD,
		Targets:      target.NewStore(pgPool),
		Scope:        sc,
		Audit:        auditLog,
	})
	done := make(chan struct{})
	go func() {
		pool.Run(ctx)
		close(done)
	}()

	shutdown := func() {
		ht.Close()
		cancel()
		<-done
		pgPool.Close()
	}
	t.Cleanup(shutdown)
	return &fullStack{srv: ht, pool: q, worker: pool, shutdown: shutdown, adminTok: adminTok, dsn: dsn}
}

func TestEndToEnd_PythonCollector_FindingsAndDedup(t *testing.T) {
	python := findPython(t)
	echo := echoCollectorPath(t)

	fs := newFullStack(t)
	c := &apiClient{t: t, url: fs.srv.URL, tok: fs.adminTok.Plaintext}

	// The Python script has a shebang and is +x in the repo; the
	// supervisor just execs it directly so the catalog needs only the
	// script path. (python interpreter discovery is the script's problem.)
	_ = python
	status, body := c.do("POST", "/v1/collectors", map[string]any{
		"name": "echo", "language": "python", "version": "0.1.0",
		"binary_path": echo, "transport": "ndjson",
	})
	if status != http.StatusCreated {
		t.Fatalf("register echo: %d %s", status, body)
	}

	// project + scope
	status, body = c.do("POST", "/v1/projects", map[string]any{
		"slug": "p4", "name": "Phase4", "owner": "alice",
	})
	if status != http.StatusCreated {
		t.Fatalf("project: %d %s", status, body)
	}
	var p struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &p)
	status, body = c.do("POST", "/v1/projects/"+p.ID+"/scope", map[string]any{
		"order": 0, "effect": "allow", "kind": "cidr", "value": "10.0.0.0/8",
	})
	if status != http.StatusCreated {
		t.Fatalf("scope: %d %s", status, body)
	}

	// First run
	status, body = c.do("POST", "/v1/projects/"+p.ID+"/runs", map[string]any{
		"capabilities": []string{"echo"},
		"targets": []map[string]any{
			{"kind": "host", "identity": "10.0.0.5", "host": "10.0.0.5"},
		},
		"parameters": map[string]any{"steps": 1},
	})
	if status != http.StatusCreated {
		t.Fatalf("run1: %d %s", status, body)
	}
	var run1 struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &run1)

	// wait for completion
	waitRunTerminal(t, c, run1.ID, 15*time.Second)

	// findings should have exactly 1 entry
	findings := listFindings(t, c, p.ID)
	if len(findings) != 1 {
		t.Fatalf("after first run: got %d findings, want 1: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Title, "10.0.0.5") {
		t.Errorf("title: %q", findings[0].Title)
	}
	if len(findings[0].Evidence) != 1 || len(findings[0].Evidence[0]) != 64 {
		t.Errorf("expected one sha256 evidence ref, got %+v", findings[0].Evidence)
	}
	firstSeen := findings[0].FirstSeenAt
	firstID := findings[0].ID

	// download the artifact
	status, body = c.do("GET", "/v1/artifacts/"+findings[0].Evidence[0], nil)
	if status != http.StatusOK {
		t.Errorf("artifact get: %d %s", status, body)
	}
	if !strings.Contains(string(body), "echo evidence for 10.0.0.5") {
		t.Errorf("artifact body unexpected: %s", body)
	}

	// Second run with the SAME target — dedup should fire.
	time.Sleep(1100 * time.Millisecond) // make last_seen_at observably distinct
	status, body = c.do("POST", "/v1/projects/"+p.ID+"/runs", map[string]any{
		"capabilities": []string{"echo"},
		"targets": []map[string]any{
			{"kind": "host", "identity": "10.0.0.5", "host": "10.0.0.5"},
		},
		"parameters": map[string]any{"steps": 1},
	})
	if status != http.StatusCreated {
		t.Fatalf("run2: %d %s", status, body)
	}
	var run2 struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &run2)
	waitRunTerminal(t, c, run2.ID, 15*time.Second)

	findings = listFindings(t, c, p.ID)
	if len(findings) != 1 {
		t.Fatalf("after second run: got %d findings, want 1 (dedup): %+v", len(findings), findings)
	}
	if findings[0].ID != firstID {
		t.Errorf("dedup created a new finding id: was %v now %v", firstID, findings[0].ID)
	}
	if !findings[0].LastSeenAt.After(firstSeen) {
		t.Errorf("last_seen_at did not advance: %v -> %v", firstSeen, findings[0].LastSeenAt)
	}
	if !findings[0].FirstSeenAt.Equal(firstSeen) {
		t.Errorf("first_seen_at must be preserved: was %v now %v", firstSeen, findings[0].FirstSeenAt)
	}
}

func waitRunTerminal(t *testing.T, c *apiClient, runID string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, body := c.do("GET", "/v1/runs/"+runID+"/jobs", nil)
		if status == http.StatusOK {
			var out struct {
				Jobs []run.JobRow `json:"jobs"`
			}
			_ = json.Unmarshal(body, &out)
			done := len(out.Jobs) > 0
			for _, j := range out.Jobs {
				switch j.Status {
				case "succeeded", "failed", "cancelled", "timed_out":
				default:
					done = false
				}
			}
			if done {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("run %s did not terminate within %v", runID, timeout)
}

func listFindings(t *testing.T, c *apiClient, projectID string) []finding.Finding {
	t.Helper()
	status, body := c.do("GET", "/v1/projects/"+projectID+"/findings", nil)
	if status != http.StatusOK {
		t.Fatalf("list findings: %d %s", status, body)
	}
	var out struct {
		Findings []finding.Finding `json:"findings"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode findings: %v body=%s", err, body)
	}
	return out.Findings
}
