// Package porttcp is an in-tree Go collector that performs a bounded
// TCP-connect scan against a single host.
//
// Target: kind=host, identity=<host>. Ports come from job parameters:
//
//	{"ports": "80,443,22-25"}
//
// Output: one finding per OPEN port (closed ports are silent; PolyPent
// doesn't litter the database with "negative" results in Phase 5).
//
// Concurrency: capped at params.concurrency (default 16). Per-host rate
// caps will land in Phase 7 once the scope-cap surface threads through
// the worker.
package porttcp

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/silvance/polypent/internal/collector"
	"github.com/silvance/polypent/internal/queue"
)

const Name = "port.tcp.connect"

// DialFunc is the seam tests inject through; *net.Dialer.DialContext fits.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

type Collector struct {
	dial DialFunc
}

func New() *Collector {
	d := &net.Dialer{Timeout: 3 * time.Second}
	return &Collector{dial: d.DialContext}
}

// NewWithDial returns a Collector with an injected dialer.
func NewWithDial(dial DialFunc) *Collector { return &Collector{dial: dial} }

func (Collector) Name() string { return Name }

func (c *Collector) Execute(ctx context.Context, job queue.Job, emit collector.Emit) error {
	if job.TargetKind != "host" {
		return fmt.Errorf("porttcp: unsupported target kind %q", job.TargetKind)
	}
	host := stripPort(job.TargetIdentity)
	if host == "" {
		return fmt.Errorf("porttcp: empty host")
	}
	portsParam, _ := job.Parameters["ports"].(string)
	if portsParam == "" {
		return fmt.Errorf("porttcp: parameters.ports is required (e.g. \"80,443,22-25\")")
	}
	ports, err := parsePorts(portsParam)
	if err != nil {
		return err
	}
	concurrency := paramInt(job.Parameters, "concurrency", 16)
	if concurrency < 1 {
		concurrency = 1
	}

	_ = emit(ctx, collector.Event{Kind: "log", Payload: map[string]any{
		"level":   "info",
		"message": fmt.Sprintf("scanning %s ports=%d concurrency=%d", host, len(ports), concurrency),
	}})

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var openMu sync.Mutex
	open := []int{}

	for _, p := range ports {
		if err := ctx.Err(); err != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			addr := net.JoinHostPort(host, strconv.Itoa(port))
			conn, err := c.dial(ctx, "tcp", addr)
			if err != nil {
				return
			}
			_ = conn.Close()
			openMu.Lock()
			open = append(open, port)
			openMu.Unlock()
		}(p)
	}
	wg.Wait()

	sort.Ints(open)
	for _, port := range open {
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		_ = emit(ctx, collector.Event{
			Kind: "finding",
			Payload: map[string]any{
				"kind":      "port.open",
				"severity":  "informational",
				"title":     fmt.Sprintf("TCP %s open", addr),
				"dedup_key": "porttcp:open:" + addr,
				"extra": map[string]any{
					"host": host,
					"port": port,
				},
			},
		})
	}

	return emit(ctx, collector.Event{Kind: "done", Payload: map[string]any{
		"host":      host,
		"scanned":   len(ports),
		"open":      len(open),
		"openPorts": open,
	}})
}

// parsePorts accepts comma-separated tokens, each either an integer port
// or a "lo-hi" range. Result is de-duplicated and sorted.
func parsePorts(s string) ([]int, error) {
	seen := map[int]struct{}{}
	for _, raw := range strings.Split(s, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if i := strings.Index(raw, "-"); i > 0 {
			a, errA := strconv.Atoi(raw[:i])
			b, errB := strconv.Atoi(raw[i+1:])
			if errA != nil || errB != nil || a < 1 || b > 65535 || a > b {
				return nil, fmt.Errorf("porttcp: invalid range %q", raw)
			}
			for p := a; p <= b; p++ {
				seen[p] = struct{}{}
			}
			continue
		}
		p, err := strconv.Atoi(raw)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("porttcp: invalid port %q", raw)
		}
		seen[p] = struct{}{}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("porttcp: ports parsed to empty set")
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

func stripPort(host string) string {
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i:], "]") {
		return host[:i]
	}
	return host
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
