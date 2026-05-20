// Package mock implements the built-in "mock" collector — a scripted,
// deterministic emitter used to exercise the queue lifecycle in tests and
// to give operators something to run end-to-end before real collectors
// arrive in Phase 4.
//
// The collector emits:
//
//   - a sequence of `progress` events (configurable via params.steps),
//   - one `log` event between each step,
//   - two `finding` events near the end,
//   - a `done` event to mark success.
//
// Job parameters honored:
//
//   - "steps": int (default 3) — number of progress increments
//   - "delay_ms": int (default 0) — delay between events
//   - "fail": bool (default false) — return an error before "done"
package mock

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/silvance/polypent/internal/collector"
	"github.com/silvance/polypent/internal/queue"
)

const Name = "mock"

type Collector struct{}

func New() *Collector { return &Collector{} }

func (Collector) Name() string { return Name }

func (Collector) Execute(ctx context.Context, job queue.Job, emit collector.Emit) error {
	steps := paramInt(job.Parameters, "steps", 3)
	delay := time.Duration(paramInt(job.Parameters, "delay_ms", 0)) * time.Millisecond
	fail := paramBool(job.Parameters, "fail", false)

	for i := 1; i <= steps; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := emit(ctx, collector.Event{
			Kind: "progress",
			Payload: map[string]any{
				"done":  i,
				"total": steps,
				"stage": fmt.Sprintf("step-%d", i),
			},
		}); err != nil {
			return err
		}
		if err := emit(ctx, collector.Event{
			Kind: "log",
			Payload: map[string]any{
				"level":   "info",
				"message": fmt.Sprintf("mock collector step %d/%d for %s", i, steps, job.TargetIdentity),
			},
		}); err != nil {
			return err
		}
		if delay > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
	}

	if fail {
		return errors.New("mock collector: instructed to fail via params.fail=true")
	}

	// Two synthetic findings so downstream tests can observe finding events.
	for i := 0; i < 2; i++ {
		if err := emit(ctx, collector.Event{
			Kind: "finding",
			Payload: map[string]any{
				"kind":      "info.mock",
				"severity":  "informational",
				"title":     fmt.Sprintf("mock finding %d for %s", i+1, job.TargetIdentity),
				"dedup_key": fmt.Sprintf("mock:%s:%d", job.TargetIdentity, i+1),
			},
		}); err != nil {
			return err
		}
	}
	return emit(ctx, collector.Event{
		Kind:    "done",
		Payload: map[string]any{"target": job.TargetIdentity},
	})
}

func paramInt(p map[string]any, k string, def int) int {
	if p == nil {
		return def
	}
	switch v := p[k].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return def
}

func paramBool(p map[string]any, k string, def bool) bool {
	if p == nil {
		return def
	}
	if b, ok := p[k].(bool); ok {
		return b
	}
	return def
}
