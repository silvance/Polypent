package api_test

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/silvance/polypent/internal/audit"
	"github.com/silvance/polypent/internal/collector"
	"github.com/silvance/polypent/internal/finding"
	"github.com/silvance/polypent/internal/project"
	"github.com/silvance/polypent/internal/queue"
	"github.com/silvance/polypent/internal/run"
	"github.com/silvance/polypent/internal/scope"
	pgstore "github.com/silvance/polypent/internal/store/postgres"
	"github.com/silvance/polypent/internal/worker"
)

// slowCollector blocks for a configurable interval so we can observe
// the number of jobs simultaneously in flight.
type slowCollector struct {
	inFlight  *atomic.Int32
	maxSeen   *atomic.Int32
	holdFor   time.Duration
	startedCh chan struct{}
}

func (slowCollector) Name() string { return "slow" }

func (s slowCollector) Execute(ctx context.Context, _ queue.Job, emit collector.Emit) error {
	now := s.inFlight.Add(1)
	defer s.inFlight.Add(-1)
	for {
		prev := s.maxSeen.Load()
		if now <= prev {
			break
		}
		if s.maxSeen.CompareAndSwap(prev, now) {
			break
		}
	}
	if s.startedCh != nil {
		select {
		case s.startedCh <- struct{}{}:
		default:
		}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(s.holdFor):
	}
	return emit(ctx, collector.Event{Kind: "done", Payload: map[string]any{}})
}

// TestPerProjectConcurrencyCap plans more jobs than the project's
// max_concurrent_jobs limit and asserts the worker never leases more
// than the cap at once, even though the pool has plenty of workers.
func TestPerProjectConcurrencyCap(t *testing.T) {
	const projectCap = 2
	const totalJobs = 6
	const poolSize = 6

	dsn := testDSN(t)
	resetSchema(t, dsn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pgPool, err := pgstore.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pgPool.Close()

	auditLog, _ := audit.New(pgPool, []byte("cc-key-32-bytes-aaaaaaaaaaaaaaaaa"))
	projects := project.NewStore(pgPool)
	sc := scope.NewStore(pgPool)
	q := queue.New(pgPool, 5*time.Second)
	findings := finding.NewStore(pgPool)

	p, err := projects.Create(ctx, project.CreateInput{Slug: "cap", Name: "Cap", Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	cap := projectCap
	if _, err := projects.Update(ctx, p.ID, project.UpdateInput{MaxConcurrentJobs: &cap}); err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Create(ctx, p.ID, scope.Rule{
		Order: 0, Effect: scope.EffectAllow, Kind: scope.KindCIDR, Value: "10.0.0.0/8",
	}); err != nil {
		t.Fatal(err)
	}

	var inFlight, maxSeen atomic.Int32
	col := slowCollector{
		inFlight: &inFlight,
		maxSeen:  &maxSeen,
		holdFor:  500 * time.Millisecond,
	}
	reg := collector.NewRegistry()
	reg.Register(col)

	planner := run.NewPlanner(pgPool, q, sc, auditLog)
	targets := make([]scope.Target, 0, totalJobs)
	for i := 0; i < totalJobs; i++ {
		ip := "10.0.0." + itoaCC(i+1)
		targets = append(targets, scope.Target{Kind: scope.TargetHost, Identity: ip, Host: ip})
	}
	_, kept, _, err := planner.Plan(ctx, run.PlanInput{
		ProjectID:    p.ID,
		Capabilities: []string{"slow"},
		Targets:      targets,
	})
	if err != nil {
		t.Fatal(err)
	}
	if kept != totalJobs {
		t.Fatalf("expected %d kept jobs, got %d", totalJobs, kept)
	}

	slogger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	pool := worker.New(q, reg, slogger, worker.Options{
		Size:     poolSize,
		Poll:     50 * time.Millisecond,
		Findings: findings,
	})
	done := make(chan struct{})
	go func() {
		pool.Run(ctx)
		close(done)
	}()

	waitJobsTerminal(t, ctx, pgPool, 30*time.Second)
	cancel()
	<-done

	peak := int(maxSeen.Load())
	if peak > projectCap {
		t.Errorf("project cap violated: %d jobs in flight at peak, want <= %d", peak, projectCap)
	}
	if peak == 0 {
		t.Errorf("collector never observed any in-flight jobs (peak=0); test fixture broken")
	}

	// All jobs must have completed.
	var succeeded int
	if err := pgPool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM jobs WHERE status='succeeded'`).Scan(&succeeded); err != nil {
		t.Fatal(err)
	}
	if succeeded != totalJobs {
		t.Errorf("expected %d succeeded jobs, got %d", totalJobs, succeeded)
	}
}

// itoaCC is a local helper so we don't share state across test files.
func itoaCC(i int) string {
	if i == 0 {
		return "0"
	}
	var b [4]byte
	n := 0
	for i > 0 {
		b[n] = byte('0' + i%10)
		i /= 10
		n++
	}
	out := make([]byte, n)
	for j := 0; j < n; j++ {
		out[j] = b[n-1-j]
	}
	return string(out)
}
