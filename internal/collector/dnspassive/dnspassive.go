// Package dnspassive is an in-tree Go collector that performs read-only
// DNS lookups against the system resolver (or a per-collector resolver
// configured in a later phase).
//
// "Passive" here means the collector does not probe arbitrary servers;
// it asks the resolver and records what comes back. No zone transfers,
// no AXFR, no brute-force.
//
// Target shape: kind=dns_name, identity=<name>. For each target, A,
// AAAA, MX, NS, and TXT records are looked up. Each non-empty result
// becomes a finding with a deterministic dedup_key.
package dnspassive

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/silvance/polypent/internal/collector"
	"github.com/silvance/polypent/internal/queue"
)

const Name = "dns.passive"

// Resolver is the minimal interface this collector needs. *net.Resolver
// satisfies it; tests inject fakes.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Collector implements collector.Collector for DNS lookups.
type Collector struct {
	r Resolver
}

// New returns a Collector using the system resolver.
func New() *Collector { return &Collector{r: net.DefaultResolver} }

// NewWithResolver returns a Collector using an injected resolver (tests).
func NewWithResolver(r Resolver) *Collector { return &Collector{r: r} }

func (Collector) Name() string { return Name }

func (c *Collector) Execute(ctx context.Context, job queue.Job, emit collector.Emit) error {
	if job.TargetKind != "dns_name" {
		return fmt.Errorf("dnspassive: unsupported target kind %q", job.TargetKind)
	}
	name := strings.TrimSuffix(job.TargetIdentity, ".")
	if name == "" {
		return fmt.Errorf("dnspassive: empty target")
	}

	_ = emit(ctx, collector.Event{Kind: "log", Payload: map[string]any{
		"level": "info", "message": "resolving " + name,
	}})

	// All lookups in parallel; ctx cancellation propagates.
	type result struct {
		kind   string
		values []string
		err    error
	}
	out := make(chan result, 4)

	go func() {
		hosts, err := c.r.LookupHost(ctx, name)
		out <- result{kind: "host", values: hosts, err: err}
	}()
	go func() {
		mxs, err := c.r.LookupMX(ctx, name)
		vs := make([]string, 0, len(mxs))
		for _, m := range mxs {
			vs = append(vs, fmt.Sprintf("%d %s", m.Pref, strings.TrimSuffix(m.Host, ".")))
		}
		out <- result{kind: "mx", values: vs, err: err}
	}()
	go func() {
		ns, err := c.r.LookupNS(ctx, name)
		vs := make([]string, 0, len(ns))
		for _, n := range ns {
			vs = append(vs, strings.TrimSuffix(n.Host, "."))
		}
		out <- result{kind: "ns", values: vs, err: err}
	}()
	go func() {
		txts, err := c.r.LookupTXT(ctx, name)
		out <- result{kind: "txt", values: txts, err: err}
	}()

	for i := 0; i < 4; i++ {
		r := <-out
		if r.err != nil {
			_ = emit(ctx, collector.Event{Kind: "log", Payload: map[string]any{
				"level":   "info",
				"message": fmt.Sprintf("dns %s lookup error: %v", r.kind, r.err),
				"kind":    r.kind,
			}})
			continue
		}
		if len(r.values) == 0 {
			continue
		}
		sort.Strings(r.values)
		_ = emit(ctx, collector.Event{
			Kind: "finding",
			Payload: map[string]any{
				"kind":      "dns." + r.kind,
				"severity":  "informational",
				"title":     fmt.Sprintf("%s record(s) for %s: %s", strings.ToUpper(r.kind), name, strings.Join(r.values, ", ")),
				"dedup_key": fmt.Sprintf("dnspassive:%s:%s", r.kind, name),
				"extra": map[string]any{
					"name":   name,
					"values": r.values,
				},
			},
		})
	}

	return emit(ctx, collector.Event{Kind: "done", Payload: map[string]any{"name": name}})
}
