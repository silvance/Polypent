// Package collector defines the in-process collector contract and a
// registry of available implementations.
//
// External-process collectors arrive in Phase 4 via the NDJSON / JSON-RPC
// protocol. Phase 3 needs only the in-process Collector interface so the
// worker pool can exercise the queue lifecycle against a mock collector.
package collector

import (
	"context"
	"fmt"
	"sync"

	"github.com/silvance/polypent/internal/queue"
)

// Event is what a collector emits during a job.
type Event struct {
	Kind    string         // progress | log | finding | target_discovered | error
	Payload map[string]any // free-form per kind
}

// Emit is the callback the worker hands to the collector. Implementations
// MUST NOT mutate the event after returning.
type Emit func(ctx context.Context, e Event) error

// Collector is an in-process job executor.
type Collector interface {
	// Name is the catalog key. Stable across builds.
	Name() string
	// Execute runs the job to completion (or context cancellation). It
	// returns nil for a successful run; a non-nil error transitions the
	// job to status=failed with that error message.
	Execute(ctx context.Context, job queue.Job, emit Emit) error
}

// Registry holds named collectors.
type Registry struct {
	mu sync.RWMutex
	m  map[string]Collector
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{m: make(map[string]Collector)} }

// Register adds c under its Name(); duplicates panic so a misconfiguration
// surfaces at boot, not at runtime.
func (r *Registry) Register(c Collector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.m[c.Name()]; exists {
		panic(fmt.Sprintf("collector: %q already registered", c.Name()))
	}
	r.m[c.Name()] = c
}

// Get returns the named collector, or (nil, false).
func (r *Registry) Get(name string) (Collector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.m[name]
	return c, ok
}

// Names returns the registered collector names. Order is not guaranteed.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.m))
	for k := range r.m {
		out = append(out, k)
	}
	return out
}
