// Package tlsinspect is an in-tree Go collector that performs a TLS
// handshake against a target host:port and records the negotiated
// version, cipher, and full peer certificate chain.
//
// Target: kind=host, identity=host:port. The collector does no
// application-layer traffic beyond the TLS hello; it does not GET a
// page or speak STARTTLS. For HTTP-specific work, use http.probe.
package tlsinspect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/silvance/polypent/internal/collector"
	"github.com/silvance/polypent/internal/queue"
)

const Name = "tls.inspect"

// dialFunc is the connection-establishment seam tests inject through.
// The default uses a stdlib *net.Dialer.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

type Collector struct {
	dial            dialFunc
	insecureForTest bool
}

func New() *Collector {
	d := &net.Dialer{Timeout: 10 * time.Second}
	return &Collector{dial: d.DialContext}
}

// NewWithDial returns a Collector with an injected dialer; for tests
// against an httptest TLS server (which uses a self-signed cert),
// pass insecure=true.
func NewWithDial(dial dialFunc, insecure bool) *Collector {
	return &Collector{dial: dial, insecureForTest: insecure}
}

func (Collector) Name() string { return Name }

func (c *Collector) Execute(ctx context.Context, job queue.Job, emit collector.Emit) error {
	if job.TargetKind != "host" {
		return fmt.Errorf("tlsinspect: unsupported target kind %q", job.TargetKind)
	}
	addr := job.TargetIdentity
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("tlsinspect: address: %w", err)
	}

	_ = emit(ctx, collector.Event{Kind: "log", Payload: map[string]any{
		"level": "info", "message": "dialing " + addr,
	}})

	rawConn, err := c.dial(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("tlsinspect: dial: %w", err)
	}
	defer func() { _ = rawConn.Close() }()

	cfg := &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,  // we WANT to learn what the server allows
		InsecureSkipVerify: c.insecureForTest, //nolint:gosec // strictly opt-in for tests
	}
	tlsConn := tls.Client(rawConn, cfg)
	hsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		return fmt.Errorf("tlsinspect: handshake: %w", err)
	}
	state := tlsConn.ConnectionState()
	now := time.Now()

	// Version + cipher finding.
	versionSeverity := "informational"
	if state.Version < tls.VersionTLS12 {
		versionSeverity = "medium"
	}
	_ = emit(ctx, collector.Event{
		Kind: "finding",
		Payload: map[string]any{
			"kind":      "tls.version",
			"severity":  versionSeverity,
			"title":     fmt.Sprintf("TLS handshake at %s: %s / %s", addr, versionName(state.Version), tls.CipherSuiteName(state.CipherSuite)),
			"dedup_key": "tlsinspect:version:" + addr,
			"extra": map[string]any{
				"version_id": state.Version,
				"cipher_id":  state.CipherSuite,
			},
		},
	})

	// One finding per cert in the chain.
	for i, cert := range state.PeerCertificates {
		expired := now.After(cert.NotAfter)
		notYet := now.Before(cert.NotBefore)
		severity := "informational"
		switch {
		case expired:
			severity = "high"
		case notYet:
			severity = "medium"
		case cert.NotAfter.Sub(now) < 14*24*time.Hour:
			severity = "low"
		}
		_ = emit(ctx, collector.Event{
			Kind: "finding",
			Payload: map[string]any{
				"kind":      "tls.cert",
				"severity":  severity,
				"title":     fmt.Sprintf("chain[%d] %s issued by %s", i, cert.Subject.CommonName, cert.Issuer.CommonName),
				"dedup_key": fmt.Sprintf("tlsinspect:cert:%s:%x", addr, cert.SerialNumber),
				"extra": map[string]any{
					"subject":    cert.Subject.String(),
					"issuer":     cert.Issuer.String(),
					"not_before": cert.NotBefore.UTC(),
					"not_after":  cert.NotAfter.UTC(),
					"serial":     fmt.Sprintf("%x", cert.SerialNumber),
					"dns_names":  cert.DNSNames,
					"expired":    expired,
					"is_ca":      cert.IsCA,
				},
			},
		})
	}

	return emit(ctx, collector.Event{Kind: "done", Payload: map[string]any{
		"version_id": state.Version,
		"cipher_id":  state.CipherSuite,
		"chain":      len(state.PeerCertificates),
	}})
}

func versionName(v uint16) string {
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

// suppress unused linter when x509 is only referenced indirectly through
// state.PeerCertificates' element type.
var _ = (*x509.Certificate)(nil)
