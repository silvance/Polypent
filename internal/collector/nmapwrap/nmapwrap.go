// Package nmapwrap is a Phase 6 third-party-wrapper template: a Go
// collector that drives the external `nmap` binary, ingests its XML
// output, normalizes the results into findings, and surfaces the raw
// XML as an artifact.
//
// Target: kind=host, identity=<host>. Required parameter:
//
//	{"ports": "22,80,443,8000-8005"}
//
// Additional optional parameter:
//
//	{"args": ["-Pn", "-sS"]}    extra flags forwarded to nmap
//
// The collector deliberately does not let the operator inject the
// `-iL` (input file list) flag or any target argument; the planner
// owns target selection, not the collector.
package nmapwrap

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/silvance/polypent/internal/collector"
	"github.com/silvance/polypent/internal/queue"
)

const Name = "nmap"

// Collector drives an external nmap-compatible binary.
type Collector struct {
	binary string
	// stdoutOnly: when true, the collector reads XML on the binary's
	// stdout (the normal nmap behavior with `-oX -`). When false, the
	// binary is expected to write `out.xml` to its CWD — reserved for
	// future hardening.
	stdoutOnly bool
}

// New returns a Collector that invokes the system `nmap` binary.
func New() *Collector {
	return &Collector{binary: "nmap", stdoutOnly: true}
}

// NewWithBinary lets tests point at a stand-in.
func NewWithBinary(binary string) *Collector {
	return &Collector{binary: binary, stdoutOnly: true}
}

func (Collector) Name() string { return Name }

func (c *Collector) Execute(ctx context.Context, job queue.Job, emit collector.Emit) error {
	if job.TargetKind != "host" {
		return fmt.Errorf("nmap: unsupported target kind %q", job.TargetKind)
	}
	host := job.TargetIdentity
	if host == "" {
		return fmt.Errorf("nmap: empty host")
	}
	ports, _ := job.Parameters["ports"].(string)
	if ports == "" {
		return fmt.Errorf("nmap: parameters.ports required")
	}

	args := []string{"-oX", "-", "-p", ports}
	if extras, ok := job.Parameters["args"].([]any); ok {
		for _, e := range extras {
			if s, ok := e.(string); ok && s != "" && !strings.HasPrefix(s, "-iL") {
				args = append(args, s)
			}
		}
	}
	args = append(args, host)

	_ = emit(ctx, collector.Event{Kind: "log", Payload: map[string]any{
		"level":   "info",
		"message": fmt.Sprintf("invoking %s %s", c.binary, strings.Join(args, " ")),
	}})

	cmd := exec.CommandContext(ctx, c.binary, args...) //nolint:gosec // binary path is operator-configured
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("nmap: run: %w", err)
	}

	// Persist raw XML as evidence.
	tmp, err := writeTemp(out)
	if err != nil {
		return fmt.Errorf("nmap: tempfile: %w", err)
	}
	_ = emit(ctx, collector.Event{Kind: "artifact_ref", Payload: map[string]any{
		"path":  tmp,
		"mime":  "application/xml",
		"label": "nmap-xml",
	}})

	openPorts, services, err := ParseXML(out)
	if err != nil {
		return fmt.Errorf("nmap: parse: %w", err)
	}

	for _, p := range openPorts {
		title := fmt.Sprintf("TCP %s:%d open", host, p)
		svc, banner := "", ""
		if s, ok := services[p]; ok {
			svc = s.Name
			banner = s.Banner
			if svc != "" {
				title += " — " + svc
			}
		}
		_ = emit(ctx, collector.Event{
			Kind: "finding",
			Payload: map[string]any{
				"kind":          "port.open",
				"severity":      "informational",
				"title":         title,
				"description":   banner,
				"dedup_key":     fmt.Sprintf("nmap:open:%s:%d", host, p),
				"evidence_refs": []string{"nmap-xml"},
				"extra": map[string]any{
					"host":    host,
					"port":    p,
					"service": svc,
					"banner":  banner,
				},
			},
		})
	}

	return emit(ctx, collector.Event{Kind: "done", Payload: map[string]any{
		"host":    host,
		"open":    len(openPorts),
		"scanned": ports,
	}})
}

// Service is what we learn about a port from the nmap XML.
type Service struct {
	Name   string
	Banner string
}

// ParseXML extracts open-port numbers and per-port service descriptors
// from nmap's `-oX -` output. Closed/filtered ports are skipped.
//
// Only a small subset of nmap's schema is consumed; we do not model
// host scripts, OS detection, or NSE output yet — they accrete as
// concrete operator needs emerge.
func ParseXML(data []byte) ([]int, map[int]Service, error) {
	var root struct {
		XMLName xml.Name `xml:"nmaprun"`
		Hosts   []struct {
			Ports struct {
				Port []struct {
					Protocol string `xml:"protocol,attr"`
					PortID   int    `xml:"portid,attr"`
					State    struct {
						State string `xml:"state,attr"`
					} `xml:"state"`
					Service struct {
						Name    string `xml:"name,attr"`
						Product string `xml:"product,attr"`
						Version string `xml:"version,attr"`
						Banner  string `xml:"extrainfo,attr"`
					} `xml:"service"`
				} `xml:"port"`
			} `xml:"ports"`
		} `xml:"host"`
	}
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, nil, err
	}
	open := []int{}
	svcs := map[int]Service{}
	for _, h := range root.Hosts {
		for _, p := range h.Ports.Port {
			if p.Protocol != "tcp" {
				continue
			}
			if p.State.State != "open" {
				continue
			}
			open = append(open, p.PortID)
			svcs[p.PortID] = Service{
				Name:   p.Service.Name,
				Banner: strings.TrimSpace(strings.Join([]string{p.Service.Product, p.Service.Version, p.Service.Banner}, " ")),
			}
		}
	}
	return open, svcs, nil
}

func writeTemp(b []byte) (string, error) {
	f, err := os.CreateTemp("", "polypent-nmap-*.xml")
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(b); err != nil {
		return "", err
	}
	return f.Name(), nil
}

// silence unused linter when time is referenced only via subcommands
// added in later phases.
var _ = time.Now
