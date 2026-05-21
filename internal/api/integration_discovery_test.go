package api_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/silvance/polypent/internal/audit"
	"github.com/silvance/polypent/internal/auth"
	"github.com/silvance/polypent/internal/collector"
	"github.com/silvance/polypent/internal/finding"
	"github.com/silvance/polypent/internal/project"
	"github.com/silvance/polypent/internal/queue"
	"github.com/silvance/polypent/internal/run"
	"github.com/silvance/polypent/internal/scope"
	pgstore "github.com/silvance/polypent/internal/store/postgres"
	"github.com/silvance/polypent/internal/target"
	"github.com/silvance/polypent/internal/worker"
)

// discoveryCollector emits one target_discovered for an in-scope target,
// one target_discovered for an out-of-scope target, and one finding
// that fraudulently claims a different target. We assert that the
// worker correctly handles all three cases.
type discoveryCollector struct{}

func (discoveryCollector) Name() string { return "discovery-test" }

func (discoveryCollector) Execute(ctx context.Context, _ queue.Job, emit collector.Emit) error {
	_ = emit(ctx, collector.Event{Kind: "target_discovered", Payload: map[string]any{
		"kind": "host", "identity": "10.0.0.99", "host": "10.0.0.99",
	}})
	_ = emit(ctx, collector.Event{Kind: "target_discovered", Payload: map[string]any{
		"kind": "host", "identity": "8.8.8.8", "host": "8.8.8.8",
	}})
	// fraudulent finding claiming a different target identity
	_ = emit(ctx, collector.Event{Kind: "finding", Payload: map[string]any{
		"kind":            "info.spoof",
		"severity":        "high",
		"title":           "spoofed finding for 8.8.8.8",
		"dedup_key":       "spoof:8.8.8.8",
		"target_kind":     "host",
		"target_identity": "8.8.8.8",
	}})
	// honest finding
	_ = emit(ctx, collector.Event{Kind: "finding", Payload: map[string]any{
		"kind":      "info.honest",
		"severity":  "informational",
		"title":     "honest finding",
		"dedup_key": "honest:10.0.0.5",
	}})
	return emit(ctx, collector.Event{Kind: "done", Payload: map[string]any{}})
}

func TestDiscoveryScopeClampAndQuarantine(t *testing.T) {
	dsn := testDSN(t)
	resetSchema(t, dsn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pgPool, err := pgstore.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pgPool.Close()

	tokens := auth.NewStore(pgPool)
	auditLog, _ := audit.New(pgPool, []byte("disc-key-32-bytes-aaaaaaaaaaaaaaa"))
	projects := project.NewStore(pgPool)
	sc := scope.NewStore(pgPool)
	q := queue.New(pgPool, 5*time.Second)
	findings := finding.NewStore(pgPool)
	targets := target.NewStore(pgPool)

	reg := collector.NewRegistry()
	reg.Register(discoveryCollector{})

	p, err := projects.Create(ctx, project.CreateInput{Slug: "disc", Name: "Disc", Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Create(ctx, p.ID, scope.Rule{
		Order: 0, Effect: scope.EffectAllow, Kind: scope.KindCIDR, Value: "10.0.0.0/8",
	}); err != nil {
		t.Fatal(err)
	}

	planner := run.NewPlanner(pgPool, q, sc, auditLog)
	_, kept, _, err := planner.Plan(ctx, run.PlanInput{
		ProjectID:    p.ID,
		Capabilities: []string{"discovery-test"},
		Targets: []scope.Target{
			{Kind: scope.TargetHost, Identity: "10.0.0.5", Host: "10.0.0.5"},
		},
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
		Targets:  targets,
		Scope:    sc,
		Audit:    auditLog,
	})
	done := make(chan struct{})
	go func() {
		pool.Run(ctx)
		close(done)
	}()

	// wait for the single job to finish
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var pending int
		if err := pgPool.QueryRow(ctx, `SELECT COUNT(*) FROM jobs WHERE status NOT IN ('succeeded','failed','cancelled','timed_out')`).Scan(&pending); err != nil {
			t.Fatal(err)
		}
		if pending == 0 {
			break
		}
		time.Sleep(80 * time.Millisecond)
	}
	cancel()
	<-done

	// 1. in-scope target_discovered → row in targets table
	var n int
	if err := pgPool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM targets WHERE project_id=$1 AND identity=$2`, p.ID, "10.0.0.99").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 10.0.0.99 to be upserted, got %d rows", n)
	}

	// 2. out-of-scope target_discovered → NOT in targets, but in audit
	if err := pgPool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM targets WHERE project_id=$1 AND identity=$2`, p.ID, "8.8.8.8").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("8.8.8.8 should NOT be in targets, got %d rows", n)
	}
	if err := pgPool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM audit_events
		 WHERE action='scope.dropped' AND target_id=$1
		   AND metadata->>'source'='target_discovered'`, "8.8.8.8").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Errorf("expected scope.dropped audit row for 8.8.8.8, got %d", n)
	}

	// 3. spoofed finding (target mismatch) → not in findings; audit row
	if err := pgPool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM findings WHERE kind='info.spoof'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("spoofed finding should be quarantined, got %d in findings", n)
	}
	if err := pgPool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM audit_events WHERE action='finding.quarantine'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Errorf("expected finding.quarantine audit row, got %d", n)
	}

	// 4. honest finding made it
	if err := pgPool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM findings WHERE kind='info.honest'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 1 honest finding, got %d", n)
	}

	// 5. audit chain still verifies after all this
	bad, err := auditLog.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if bad != 0 {
		t.Errorf("audit chain broke at id=%d", bad)
	}

	// keep auth import in use for the test file
	_ = tokens
}
