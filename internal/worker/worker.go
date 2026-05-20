// Package worker runs the in-process pool that drives queued jobs to
// completion via registered Collectors.
//
// Each worker leases a job, hands it to the collector for execution, and
// pipes the collector's events into job_events. On crash or graceful
// shutdown, expired leases are reclaimed by ReclaimLoop and another
// worker can pick the job up.
package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/silvance/polypent/internal/collector"
	"github.com/silvance/polypent/internal/queue"
	"github.com/silvance/polypent/internal/run"
)

// Pool is a bounded set of worker goroutines.
type Pool struct {
	q        *queue.Queue
	registry *collector.Registry
	logger   *slog.Logger
	id       string
	size     int
	poll     time.Duration

	wg     sync.WaitGroup
	cancel context.CancelFunc
}

// Options configures the pool.
type Options struct {
	WorkerID string        // prefix; each goroutine appends -N
	Size     int           // number of concurrent workers
	Poll     time.Duration // fallback poll interval when no NOTIFY arrives
}

// New constructs a Pool. Run() actually starts the goroutines.
func New(q *queue.Queue, reg *collector.Registry, logger *slog.Logger, opts Options) *Pool {
	if opts.Size <= 0 {
		opts.Size = 4
	}
	if opts.Poll <= 0 {
		opts.Poll = 1 * time.Second
	}
	if opts.WorkerID == "" {
		opts.WorkerID = "worker-" + uuid.NewString()[:8]
	}
	return &Pool{q: q, registry: reg, logger: logger, id: opts.WorkerID, size: opts.Size, poll: opts.Poll}
}

// Run blocks until ctx is cancelled. Workers and the reclaim loop start
// here; Stop waits for clean shutdown.
func (p *Pool) Run(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	p.cancel = cancel

	// reclaim loop
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		t := time.NewTicker(p.q.LeaseDuration() / 3)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n, err := p.q.ReclaimExpired(ctx); err != nil {
					p.logger.Warn("worker: reclaim", "err", err)
				} else if n > 0 {
					p.logger.Info("worker: reclaimed expired leases", "n", n)
				}
			}
		}
	}()

	for i := 0; i < p.size; i++ {
		p.wg.Add(1)
		workerID := fmt.Sprintf("%s-%d", p.id, i)
		go p.loop(ctx, workerID)
	}

	p.wg.Wait()
}

// Stop signals shutdown and waits for workers to drain.
func (p *Pool) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
}

func (p *Pool) loop(ctx context.Context, workerID string) {
	defer p.wg.Done()
	for {
		if ctx.Err() != nil {
			return
		}
		job, ok, err := p.q.Lease(ctx, workerID)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				p.logger.Warn("worker: lease", "err", err, "worker", workerID)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(p.poll):
			}
			continue
		}
		if !ok {
			select {
			case <-ctx.Done():
				return
			case <-time.After(p.poll):
			}
			continue
		}
		p.execute(ctx, workerID, *job)
	}
}

func (p *Pool) execute(ctx context.Context, workerID string, job queue.Job) {
	log := p.logger.With(
		"worker", workerID,
		"job", job.ID.String(),
		"run", job.RunID.String(),
		"collector", job.Collector,
		"target", job.TargetIdentity,
	)

	c, ok := p.registry.Get(job.Collector)
	if !ok {
		log.Warn("collector not registered")
		_ = p.q.Complete(ctx, job.ID, workerID, queue.StatusFailed,
			fmt.Sprintf("collector %q not registered", job.Collector))
		_ = run.MaybeFinishRun(ctx, p.q.Pool(), job.RunID)
		return
	}

	if err := p.q.MarkRunning(ctx, job.ID, workerID); err != nil {
		log.Warn("mark running", "err", err)
		return
	}

	jobCtx := ctx
	if job.Deadline != nil {
		var cancel context.CancelFunc
		jobCtx, cancel = context.WithDeadline(ctx, *job.Deadline)
		defer cancel()
	}

	emit := func(ctx context.Context, e collector.Event) error {
		return p.q.RecordEvent(ctx, job.ID, e.Kind, e.Payload)
	}

	err := c.Execute(jobCtx, job, emit)
	switch {
	case err == nil:
		_ = p.q.Complete(ctx, job.ID, workerID, queue.StatusSucceeded, "")
		log.Info("job succeeded")
	case errors.Is(err, context.DeadlineExceeded):
		_ = p.q.Complete(ctx, job.ID, workerID, queue.StatusTimedOut, err.Error())
		log.Warn("job timed out")
	case errors.Is(err, context.Canceled):
		// Worker shutdown: do NOT mark the job; leave it for reclaim. The
		// lease will expire and another worker picks it up.
		log.Info("job preempted by shutdown")
	default:
		_ = p.q.Complete(ctx, job.ID, workerID, queue.StatusFailed, err.Error())
		log.Warn("job failed", "err", err)
	}

	if err == nil || !errors.Is(err, context.Canceled) {
		if err := run.MaybeFinishRun(ctx, p.q.Pool(), job.RunID); err != nil {
			log.Warn("finish run", "err", err)
		}
	}
}
