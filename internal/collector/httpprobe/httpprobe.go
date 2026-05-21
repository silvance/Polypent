// Package httpprobe is an in-tree Go collector that probes a single
// HTTP/HTTPS target and captures structured evidence.
//
// Target shapes accepted:
//
//   - kind=url       identity holds an absolute URL
//   - kind=host      identity holds host[:port]; the collector constructs
//     http://host:port/ if Port < 443, https otherwise
//
// Emits:
//
//   - log         pre-request line ("about to GET ...")
//   - artifact_ref the captured response (status + headers + truncated body)
//   - finding     info.http.live with the status code in the title
//   - finding     info.http.tls with the negotiated TLS version + cipher,
//     when the connection used TLS
//   - done        terminal event with timing summary
//
// All findings carry deterministic dedup_keys so re-running against the
// same URL refreshes last_seen_at rather than inserting a duplicate.
package httpprobe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/silvance/polypent/internal/collector"
	"github.com/silvance/polypent/internal/queue"
)

const Name = "http.probe"

// MaxBodyBytes caps the body captured to the artifact. Larger bodies are
// truncated; the artifact label records the truncation.
const MaxBodyBytes = 256 << 10 // 256 KiB

type Collector struct {
	client *http.Client
}

func New() *Collector {
	return &Collector{
		client: &http.Client{
			Timeout: 30 * time.Second,
			// We do NOT follow redirects; an out-of-scope redirect is a
			// scope violation if blindly followed. Phase 5 surfaces the
			// redirect as part of the response artifact and a finding.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				// Keep TLS strict by default. Operators who need to
				// probe self-signed targets configure a per-collector
				// flavor in a later phase; in Phase 5 we don't ship
				// the foot-gun.
				TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
				DisableKeepAlives: true,
			},
		},
	}
}

func (Collector) Name() string { return Name }

func (c *Collector) Execute(ctx context.Context, job queue.Job, emit collector.Emit) error {
	target, err := buildURL(job)
	if err != nil {
		return err
	}

	_ = emit(ctx, collector.Event{
		Kind: "log",
		Payload: map[string]any{
			"level":   "info",
			"message": "about to GET " + target,
		},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return fmt.Errorf("httpprobe: build request: %w", err)
	}
	req.Header.Set("User-Agent", "PolyPent/"+Name)

	start := time.Now()
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("httpprobe: request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
	truncated := len(body) > MaxBodyBytes
	if truncated {
		body = body[:MaxBodyBytes]
	}
	elapsed := time.Since(start)

	// Persist the response as an evidence artifact via artifact_ref.
	// The supervisor's emit pipeline opens the file, hashes it, and
	// records metadata; the upcoming finding's evidence_refs label
	// resolves to that sha.
	tmp, err := writeResponseToTemp(target, resp, body, truncated)
	if err != nil {
		return fmt.Errorf("httpprobe: tempfile: %w", err)
	}
	_ = emit(ctx, collector.Event{
		Kind: "artifact_ref",
		Payload: map[string]any{
			"path":  tmp,
			"mime":  "message/http",
			"label": "response-1",
		},
	})

	_ = emit(ctx, collector.Event{
		Kind: "finding",
		Payload: map[string]any{
			"kind":          "info.http.live",
			"severity":      "informational",
			"title":         fmt.Sprintf("HTTP %d at %s", resp.StatusCode, target),
			"description":   summary(resp, elapsed, truncated),
			"dedup_key":     "httpprobe:live:" + target,
			"evidence_refs": []string{"response-1"},
			"extra": map[string]any{
				"status_code":  resp.StatusCode,
				"server":       resp.Header.Get("Server"),
				"content_type": resp.Header.Get("Content-Type"),
				"elapsed_ms":   elapsed.Milliseconds(),
				"truncated":    truncated,
				"redirect_to":  resp.Header.Get("Location"),
			},
		},
	})

	if resp.TLS != nil {
		_ = emit(ctx, collector.Event{
			Kind: "finding",
			Payload: map[string]any{
				"kind":      "info.http.tls",
				"severity":  "informational",
				"title":     fmt.Sprintf("%s @ %s using %s / %s", tlsName(resp.TLS.Version), target, tls.CipherSuiteName(resp.TLS.CipherSuite), resp.TLS.ServerName),
				"dedup_key": "httpprobe:tls:" + target,
				"extra": map[string]any{
					"version_id":   resp.TLS.Version,
					"cipher_id":    resp.TLS.CipherSuite,
					"server_name":  resp.TLS.ServerName,
					"chain_length": len(resp.TLS.PeerCertificates),
				},
			},
		})
	}

	return emit(ctx, collector.Event{
		Kind: "done",
		Payload: map[string]any{
			"status":     resp.StatusCode,
			"elapsed_ms": elapsed.Milliseconds(),
			"tls":        resp.TLS != nil,
		},
	})
}

func buildURL(job queue.Job) (string, error) {
	switch job.TargetKind {
	case "url":
		u, err := url.Parse(job.TargetIdentity)
		if err != nil {
			return "", fmt.Errorf("httpprobe: parse url: %w", err)
		}
		if !u.IsAbs() {
			return "", fmt.Errorf("httpprobe: url not absolute: %s", job.TargetIdentity)
		}
		return u.String(), nil
	case "host":
		// host[:port] → http(s)://host:port/
		raw := job.TargetIdentity
		port := ""
		if i := strings.LastIndex(raw, ":"); i > 0 && !strings.Contains(raw[i:], "]") {
			port = raw[i+1:]
		}
		scheme := "http"
		if port == "443" || port == "8443" {
			scheme = "https"
		}
		return fmt.Sprintf("%s://%s/", scheme, raw), nil
	}
	return "", fmt.Errorf("httpprobe: unsupported target kind %q", job.TargetKind)
}

func writeResponseToTemp(target string, resp *http.Response, body []byte, truncated bool) (string, error) {
	f, err := os.CreateTemp("", "polypent-httpprobe-*.http")
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	_, _ = fmt.Fprintf(f, "GET %s\n", target)
	_, _ = fmt.Fprintf(f, "%s %s\n", resp.Proto, resp.Status)
	for k, vs := range resp.Header {
		for _, v := range vs {
			_, _ = fmt.Fprintf(f, "%s: %s\n", k, v)
		}
	}
	_, _ = f.Write([]byte("\n"))
	_, _ = f.Write(body)
	if truncated {
		_, _ = f.Write([]byte("\n[... truncated ...]\n"))
	}
	return f.Name(), nil
}

func summary(resp *http.Response, elapsed time.Duration, truncated bool) string {
	parts := []string{
		fmt.Sprintf("status=%d", resp.StatusCode),
		fmt.Sprintf("proto=%s", resp.Proto),
		fmt.Sprintf("elapsed=%s", elapsed.Round(time.Millisecond)),
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		parts = append(parts, "content-type="+ct)
	}
	if truncated {
		parts = append(parts, "body-truncated")
	}
	return strings.Join(parts, "; ")
}

func tlsName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return fmt.Sprintf("TLS 0x%04x", v)
}
