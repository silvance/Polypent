package nmapwrap

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/silvance/polypent/internal/collector"
	"github.com/silvance/polypent/internal/queue"
)

const sampleXML = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2p1" extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="81">
        <state state="closed"/>
      </port>
      <port protocol="udp" portid="53">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>`

func TestParseXMLExtractsOpenTCPOnly(t *testing.T) {
	open, svcs, err := ParseXML([]byte(sampleXML))
	if err != nil {
		t.Fatal(err)
	}
	sort.Ints(open)
	if !reflect.DeepEqual(open, []int{22, 80}) {
		t.Errorf("open ports = %v, want [22 80]", open)
	}
	if svcs[22].Name != "ssh" {
		t.Errorf("port 22 service = %q", svcs[22].Name)
	}
	if svcs[80].Banner == "" {
		t.Errorf("port 80 banner is empty: %+v", svcs[80])
	}
}

type rec struct {
	mu sync.Mutex
	ev []collector.Event
}

func (r *rec) emit(_ context.Context, e collector.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ev = append(r.ev, e)
	return nil
}

// TestExecuteWithFakeBinary builds a tiny shell script that mimics
// `nmap -oX -` by ignoring its arguments and printing sampleXML, then
// runs the wrapper against it. Two open-port findings should appear.
func TestExecuteWithFakeBinary(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "fake-nmap")
	body := "#!/bin/sh\ncat <<'EOF'\n" + sampleXML + "\nEOF\n"
	if err := os.WriteFile(fake, []byte(body), 0o755); err != nil { //nolint:gosec // test artifact
		t.Fatal(err)
	}

	c := NewWithBinary(fake)
	r := &rec{}
	job := queue.Job{
		ID:             uuid.New(),
		TargetKind:     "host",
		TargetIdentity: "10.0.0.5",
		Parameters:     map[string]any{"ports": "22,80,81"},
	}
	if err := c.Execute(context.Background(), job, r.emit); err != nil {
		t.Fatalf("execute: %v", err)
	}

	var findings int
	var artifactRef bool
	for _, e := range r.ev {
		switch e.Kind {
		case "finding":
			findings++
		case "artifact_ref":
			artifactRef = true
		}
	}
	if findings != 2 {
		t.Errorf("findings: want 2 (22, 80), got %d", findings)
	}
	if !artifactRef {
		t.Errorf("no artifact_ref event emitted")
	}
}
