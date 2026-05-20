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
	"os"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/silvance/polypent/internal/artifact"
	"github.com/silvance/polypent/internal/collector"
	"github.com/silvance/polypent/internal/finding"
	"github.com/silvance/polypent/internal/queue"
	"github.com/silvance/polypent/internal/run"
)

// Pool is a bounded set of worker goroutines.
type Pool struct {
	q          *queue.Queue
	registry   *collector.Registry
	logger     *slog.Logger
	id         string
	size       int
	poll       time.Duration
	findings   *finding.Store
	artifacts  artifact.Store
	artifactMD *artifact.MetaStore

	wg     sync.WaitGroup
	cancel context.CancelFunc
}

// Options configures the pool. Findings, Artifacts, and ArtifactMeta are
// optional: when nil, worker simply records raw events without doing the
// finding/artifact ingestion.
type Options struct {
	WorkerID     string
	Size         int
	Poll         time.Duration
	Findings     *finding.Store
	Artifacts    artifact.Store
	ArtifactMeta *artifact.MetaStore
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
	return &Pool{
		q:          q,
		registry:   reg,
		logger:     logger,
		id:         opts.WorkerID,
		size:       opts.Size,
		poll:       opts.Poll,
		findings:   opts.Findings,
		artifacts:  opts.Artifacts,
		artifactMD: opts.ArtifactMeta,
	}
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

	labels := make(map[string]string) // artifact_ref label -> sha256
	emit := p.makeEmit(job, labels, log)

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

// makeEmit builds the per-job emit callback. It routes:
//
//   - "artifact_ref"   ingest the file, record metadata, remember label->sha
//   - "finding"        resolve evidence_refs against labels, upsert finding
//   - everything else  pass-through into job_events
//
// All emissions are also persisted into job_events so the operator has a
// complete trace of what happened.
func (p *Pool) makeEmit(job queue.Job, labels map[string]string, log *slog.Logger) collector.Emit {
	return func(ctx context.Context, e collector.Event) error {
		switch e.Kind {
		case "artifact_ref":
			if err := p.ingestArtifact(ctx, job, labels, e.Payload, log); err != nil {
				log.Warn("ingest artifact", "err", err)
			}
		case "finding":
			if err := p.ingestFinding(ctx, job, labels, e.Payload, log); err != nil {
				log.Warn("ingest finding", "err", err)
			}
		}
		return p.q.RecordEvent(ctx, job.ID, e.Kind, e.Payload)
	}
}

func (p *Pool) ingestArtifact(ctx context.Context, job queue.Job, labels map[string]string, payload map[string]any, log *slog.Logger) error {
	if p.artifacts == nil || p.artifactMD == nil {
		return nil
	}
	path, _ := payload["path"].(string)
	if path == "" {
		return errors.New("artifact_ref: path required")
	}
	mime, _ := payload["mime"].(string)
	label, _ := payload["label"].(string)
	f, err := os.Open(path) //nolint:gosec // operator-controlled collector-supplied path
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer func() { _ = f.Close() }()
	sha, size, err := p.artifacts.Put(ctx, f)
	if err != nil {
		return fmt.Errorf("put: %w", err)
	}
	if err := p.artifactMD.Record(ctx, artifact.Meta{
		SHA256:    sha,
		Size:      size,
		Mime:      mime,
		Label:     label,
		ProjectID: &job.ProjectID,
		JobID:     &job.ID,
	}); err != nil {
		return fmt.Errorf("meta: %w", err)
	}
	if label != "" {
		labels[label] = sha
	}
	// Mutate payload so the recorded event in job_events contains the sha.
	payload["sha256"] = sha
	payload["size"] = size
	log.Info("artifact ingested", "sha256", sha, "label", label, "size", size)
	return nil
}

func (p *Pool) ingestFinding(ctx context.Context, job queue.Job, labels map[string]string, payload map[string]any, log *slog.Logger) error {
	if p.findings == nil {
		return nil
	}
	in := finding.Input{
		ProjectID:      job.ProjectID,
		RunID:          &job.RunID,
		JobID:          &job.ID,
		Collector:      job.Collector,
		TargetKind:     job.TargetKind,
		TargetIdentity: job.TargetIdentity,
	}
	if v, ok := payload["kind"].(string); ok {
		in.Kind = v
	}
	if v, ok := payload["severity"].(string); ok {
		in.Severity = finding.Severity(v)
	}
	if v, ok := payload["title"].(string); ok {
		in.Title = v
	}
	if v, ok := payload["description"].(string); ok {
		in.Description = v
	}
	if v, ok := payload["cvss"].(string); ok {
		in.CVSS = v
	}
	if v, ok := payload["dedup_key"].(string); ok {
		in.DedupKey = v
	}
	if refs, ok := payload["evidence_refs"].([]any); ok {
		for _, r := range refs {
			s, _ := r.(string)
			if s == "" {
				continue
			}
			if sha, ok := labels[s]; ok {
				in.Evidence = append(in.Evidence, sha)
			} else {
				in.Evidence = append(in.Evidence, s) // assume already a sha
			}
		}
	}
	if extra, ok := payload["extra"].(map[string]any); ok {
		in.Extra = extra
	}
	res, err := p.findings.Upsert(ctx, in)
	if err != nil {
		return err
	}
	payload["finding_id"] = res.Finding.ID.String()
	payload["inserted"] = res.Inserted
	log.Info("finding ingested", "id", res.Finding.ID, "inserted", res.Inserted)
	return nil
}
