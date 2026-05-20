package api_test

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/silvance/polypent/internal/audit"
	"github.com/silvance/polypent/internal/auth"
	"github.com/silvance/polypent/internal/collector"
	"github.com/silvance/polypent/internal/collector/mock"
	"github.com/silvance/polypent/internal/project"
	"github.com/silvance/polypent/internal/queue"
	"github.com/silvance/polypent/internal/run"
	"github.com/silvance/polypent/internal/scope"
	pgstore "github.com/silvance/polypent/internal/store/postgres"
	"github.com/silvance/polypent/internal/worker"
)

// TestQueueChaos is the Phase 3 exit-criterion test.
//
// 50 runs across 3 projects, pool size 8, workers killed mid-flight.
// Assertions:
//   - all jobs reach a terminal state
//   - the number of jobs per run equals the planned count (no duplication)
//   - no job's `attempts` exceeds a sane upper bound (no runaway re-lease)
//   - the audit chain is still intact
func TestQueueChaos(t *testing.T) {
	if testing.Short() {
		t.Skip("chaos test is heavy; skipped under -short")
	}
	dsn := testDSN(t)
	resetSchema(t, dsn)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := pgstore.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	tokens := auth.NewStore(pool)
	auditLog, err := audit.New(pool, []byte("chaos-key-32-bytes-aaaaaaaaaaaaaa"))
	if err != nil {
		t.Fatal(err)
	}
	projects := project.NewStore(pool)
	scopeStore := scope.NewStore(pool)
	// short lease so reclaim actually exercises during the chaos window
	q := queue.New(pool, 600*time.Millisecond)
	planner := run.NewPlanner(pool, q, scopeStore, auditLog)

	reg := collector.NewRegistry()
	reg.Register(mock.New())

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

	// --- seed 3 projects, each with a permissive scope -----------------------
	const projectCount = 3
	const runsPerProject = 17 // ~50 total runs
	const targetsPerRun = 3
	projectIDs := make([]string, 0, projectCount)
	for i := 0; i < projectCount; i++ {
		p, err := projects.Create(ctx, project.CreateInput{
			Slug: pSlug(i), Name: "chaos", Owner: "alice",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := scopeStore.Create(ctx, p.ID, scope.Rule{
			Order: 0, Effect: scope.EffectAllow, Kind: scope.KindCIDR, Value: "10.0.0.0/8",
		}); err != nil {
			t.Fatal(err)
		}
		projectIDs = append(projectIDs, p.ID.String())
	}

	// admin token so we have an actor for audit
	adminTok, err := tokens.Issue(ctx, auth.RoleAdmin, nil, "chaos", 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = adminTok

	// --- plan all runs --------------------------------------------------------
	var planned int
	for i := 0; i < projectCount; i++ {
		for r := 0; r < runsPerProject; r++ {
			targets := make([]scope.Target, 0, targetsPerRun)
			for k := 0; k < targetsPerRun; k++ {
				ip := chaosIP(i, r, k)
				targets = append(targets, scope.Target{Kind: scope.TargetHost, Identity: ip, Host: ip})
			}
			_, kept, _, err := planner.Plan(ctx, run.PlanInput{
				ProjectID:    uuidFromString(t, projectIDs[i]),
				Capabilities: []string{"mock"},
				Parameters:   map[string]any{"steps": 2, "delay_ms": 5},
				Targets:      targets,
			})
			if err != nil {
				t.Fatal(err)
			}
			planned += kept
		}
	}
	t.Logf("planned %d jobs", planned)

	// --- start a pool and aggressively kill+restart it -----------------------
	const poolSize = 8
	const chaosDuration = 5 * time.Second
	var workerGen int32
	startPool := func() (context.CancelFunc, <-chan struct{}) {
		gen := atomic.AddInt32(&workerGen, 1)
		pctx, pcancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			p := worker.New(q, reg, logger, worker.Options{
				WorkerID: "chaos-" + itoa(int(gen)),
				Size:     poolSize,
				Poll:     50 * time.Millisecond,
			})
			p.Run(pctx)
			close(done)
		}()
		return pcancel, done
	}

	stopAll := make(chan struct{})
	var stopWG sync.WaitGroup
	stopWG.Add(1)
	go func() {
		defer stopWG.Done()
		// chaos: every 600ms, kill the live pool and start a new one
		var cancelCurr context.CancelFunc
		var doneCurr <-chan struct{}
		cancelCurr, doneCurr = startPool()
		t := time.NewTicker(600 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stopAll:
				cancelCurr()
				<-doneCurr
				return
			case <-t.C:
				cancelCurr()
				<-doneCurr
				cancelCurr, doneCurr = startPool()
			}
		}
	}()

	// keep churning during the chaos window
	time.Sleep(chaosDuration)

	// final stable pool to drain
	close(stopAll)
	stopWG.Wait()
	cancelFinal, doneFinal := startPool()

	// wait until all jobs are terminal or the deadline is reached
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var pending int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM jobs WHERE status NOT IN ('succeeded','failed','cancelled','timed_out')`).Scan(&pending); err != nil {
			t.Fatal(err)
		}
		if pending == 0 {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	cancelFinal()
	<-doneFinal

	// --- assertions ----------------------------------------------------------
	var total, succeeded, terminal int
	if err := pool.QueryRow(ctx, `
		SELECT
		    COUNT(*),
		    COUNT(*) FILTER (WHERE status='succeeded'),
		    COUNT(*) FILTER (WHERE status IN ('succeeded','failed','cancelled','timed_out'))
		FROM jobs`).Scan(&total, &succeeded, &terminal); err != nil {
		t.Fatal(err)
	}
	t.Logf("totals: total=%d terminal=%d succeeded=%d", total, terminal, succeeded)
	if total != planned {
		t.Errorf("job count = %d, expected %d (planning produced duplicates or losses)", total, planned)
	}
	if terminal != total {
		t.Errorf("%d/%d jobs failed to reach a terminal state", total-terminal, total)
	}
	if succeeded < total*7/10 {
		t.Errorf("only %d/%d jobs succeeded; suspicious", succeeded, total)
	}

	// No job should have been attempted more than a few times — bounded
	// re-lease is the property we want.
	var maxAttempts int
	if err := pool.QueryRow(ctx, `SELECT COALESCE(MAX(attempts), 0) FROM jobs`).Scan(&maxAttempts); err != nil {
		t.Fatal(err)
	}
	t.Logf("max attempts = %d", maxAttempts)
	if maxAttempts > 10 {
		t.Errorf("max attempts = %d, suggests reclaim loop is too aggressive", maxAttempts)
	}

	// audit chain still verifies
	bad, err := auditLog.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bad != 0 {
		t.Errorf("audit chain broke at id=%d", bad)
	}
}

func pSlug(i int) string {
	switch i {
	case 0:
		return "chaos-a"
	case 1:
		return "chaos-b"
	case 2:
		return "chaos-c"
	}
	return "chaos-x"
}

func chaosIP(p, r, k int) string {
	// 10.<project>.<run>.<k>
	return "10." + itoa(p+1) + "." + itoa(r+1) + "." + itoa(k+1)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
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

func uuidFromString(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
