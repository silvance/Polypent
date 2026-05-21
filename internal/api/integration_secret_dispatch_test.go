package api_test

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/silvance/polypent/internal/audit"
	"github.com/silvance/polypent/internal/collector"
	"github.com/silvance/polypent/internal/finding"
	"github.com/silvance/polypent/internal/project"
	"github.com/silvance/polypent/internal/queue"
	"github.com/silvance/polypent/internal/run"
	"github.com/silvance/polypent/internal/scope"
	"github.com/silvance/polypent/internal/secrets"
	pgstore "github.com/silvance/polypent/internal/store/postgres"
	"github.com/silvance/polypent/internal/worker"
)

// secretReader is an in-process collector that reads
// job.Parameters["secrets"]["TEST_KEY"] and emits a finding whose
// title contains the plaintext.
type secretReader struct{}

func (secretReader) Name() string { return "secret-reader" }

func (secretReader) Execute(ctx context.Context, job queue.Job, emit collector.Emit) error {
	bag, _ := job.Parameters["secrets"].(map[string]any)
	val, _ := bag["TEST_KEY"].(string)
	_ = emit(ctx, collector.Event{Kind: "finding", Payload: map[string]any{
		"kind":      "info.echo-secret",
		"severity":  "informational",
		"title":     "saw secret value: " + val,
		"dedup_key": "secret-reader",
	}})
	return emit(ctx, collector.Event{Kind: "done", Payload: map[string]any{}})
}

func TestSecretsDispatchedToCollectorAndScrubbedFromEvents(t *testing.T) {
	const plaintext = "SUPER_SECRET_FLAG_X9F2K"
	dsn := testDSN(t)
	resetSchema(t, dsn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pgPool, err := pgstore.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pgPool.Close()

	auditLog, _ := audit.New(pgPool, []byte("sd-key-32-bytes-aaaaaaaaaaaaaaaaa"))
	projects := project.NewStore(pgPool)
	sc := scope.NewStore(pgPool)
	q := queue.New(pgPool, 5*time.Second)
	findings := finding.NewStore(pgPool)
	vault, err := secrets.New(pgPool, []byte("sd-master-32-bytes-aaaaaaaaaaaaaaaa"))
	if err != nil {
		t.Fatal(err)
	}

	reg := collector.NewRegistry()
	reg.Register(secretReader{})

	p, err := projects.Create(ctx, project.CreateInput{Slug: "sd", Name: "Secret Dispatch", Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Create(ctx, p.ID, scope.Rule{
		Order: 0, Effect: scope.EffectAllow, Kind: scope.KindCIDR, Value: "10.0.0.0/8",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Put(ctx, p.ID, "TEST_KEY", []byte(plaintext), nil); err != nil {
		t.Fatal(err)
	}

	planner := run.NewPlanner(pgPool, q, sc, auditLog)
	_, kept, _, err := planner.Plan(ctx, run.PlanInput{
		ProjectID:    p.ID,
		Capabilities: []string{"secret-reader"},
		Targets: []scope.Target{
			{Kind: scope.TargetHost, Identity: "10.0.0.5", Host: "10.0.0.5"},
		},
		SecretKeys: []string{"TEST_KEY"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if kept != 1 {
		t.Fatalf("expected 1 kept job, got %d", kept)
	}

	slogger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	pool := worker.New(q, reg, slogger, worker.Options{
		Size:     2,
		Poll:     50 * time.Millisecond,
		Findings: findings,
		Secrets:  vault,
	})
	done := make(chan struct{})
	go func() {
		pool.Run(ctx)
		close(done)
	}()

	waitJobsTerminal(t, ctx, pgPool, 10*time.Second)
	cancel()
	<-done

	// 1. The collector received the plaintext.
	got, err := findings.ListByProject(context.Background(), p.ID, finding.ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if !strings.Contains(got[0].Title, plaintext) {
		t.Errorf("finding title should embed plaintext; got %q", got[0].Title)
	}

	// 2. job_events of any kind other than `finding` MUST NOT contain
	//    the plaintext. The platform never logs the value itself; if a
	//    collector echoes it back into a finding, that's the collector's
	//    choice and the test isolates it to `finding`-kind events.
	rows, err := pgPool.Query(context.Background(), `SELECT kind, payload::text FROM job_events`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var kind, payload string
		if err := rows.Scan(&kind, &payload); err != nil {
			t.Fatal(err)
		}
		if kind == "finding" {
			continue
		}
		if strings.Contains(payload, plaintext) {
			t.Errorf("non-finding event %q leaked plaintext: %s", kind, payload)
		}
	}

	// 3. jobs.parameters in the DB carries the secret_keys list (just
	//    names) but does NOT carry plaintext or a resolved secrets map.
	var paramsRaw string
	if err := pgPool.QueryRow(context.Background(), `SELECT parameters::text FROM jobs LIMIT 1`).Scan(&paramsRaw); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(paramsRaw, "TEST_KEY") {
		t.Errorf("expected secret_keys list in jobs.parameters; got %s", paramsRaw)
	}
	if strings.Contains(paramsRaw, plaintext) {
		t.Errorf("jobs.parameters leaked plaintext: %s", paramsRaw)
	}
	if strings.Contains(paramsRaw, `"secrets":`) {
		t.Errorf("jobs.parameters should not contain a resolved 'secrets' map; got %s", paramsRaw)
	}

	// 4. A job referencing an unknown secret fails fast at exec time
	//    with a clean error message naming the missing key.
	if _, _, _, err := planner.Plan(context.Background(), run.PlanInput{
		ProjectID:    p.ID,
		Capabilities: []string{"secret-reader"},
		Targets: []scope.Target{
			{Kind: scope.TargetHost, Identity: "10.0.0.6", Host: "10.0.0.6"},
		},
		SecretKeys: []string{"MISSING_KEY"},
	}); err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	pool2 := worker.New(q, reg, slogger, worker.Options{
		Size: 1, Poll: 50 * time.Millisecond, Findings: findings, Secrets: vault,
	})
	done2 := make(chan struct{})
	go func() { pool2.Run(ctx2); close(done2) }()
	waitJobsTerminal(t, ctx2, pgPool, 5*time.Second)
	cancel2()
	<-done2

	var failed int
	if err := pgPool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM jobs WHERE status='failed' AND error LIKE '%MISSING_KEY%'`).Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if failed != 1 {
		t.Errorf("expected 1 failed job mentioning MISSING_KEY, got %d", failed)
	}
}

func waitJobsTerminal(t *testing.T, ctx context.Context, pool *pgxpool.Pool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var pending int
		_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM jobs WHERE status NOT IN ('succeeded','failed','cancelled','timed_out')`).Scan(&pending)
		if pending == 0 {
			return
		}
		time.Sleep(80 * time.Millisecond)
	}
	t.Fatalf("jobs did not terminate within %v", timeout)
}
