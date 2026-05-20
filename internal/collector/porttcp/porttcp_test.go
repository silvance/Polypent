package porttcp

import (
	"context"
	"net"
	"reflect"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/silvance/polypent/internal/collector"
	"github.com/silvance/polypent/internal/queue"
)

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

func TestParsePorts(t *testing.T) {
	cases := map[string][]int{
		"80":            {80},
		"22,80,443":     {22, 80, 443},
		"22-24":         {22, 23, 24},
		"22,80,100-102": {22, 80, 100, 101, 102},
		"80,80":         {80}, // dedup
	}
	for in, want := range cases {
		got, err := parsePorts(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v want %v", in, got, want)
		}
	}
	for _, bad := range []string{"", "abc", "0", "70000", "10-9", ","} {
		if _, err := parsePorts(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestScanReportsOnlyOpenPorts(t *testing.T) {
	// Stand up two listeners on random localhost ports.
	l1, _ := net.Listen("tcp", "127.0.0.1:0")
	defer func() { _ = l1.Close() }()
	l2, _ := net.Listen("tcp", "127.0.0.1:0")
	defer func() { _ = l2.Close() }()
	p1 := l1.Addr().(*net.TCPAddr).Port
	p2 := l2.Addr().(*net.TCPAddr).Port
	// also pick a "closed" port by listening then closing.
	l3, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := l3.Addr().(*net.TCPAddr).Port
	_ = l3.Close()

	portStr := scanPortString(p1, p2, closedPort)

	c := New()
	r := &rec{}
	job := queue.Job{
		ID:             uuid.New(),
		TargetKind:     "host",
		TargetIdentity: "127.0.0.1",
		Parameters:     map[string]any{"ports": portStr, "concurrency": 4},
	}
	if err := c.Execute(context.Background(), job, r.emit); err != nil {
		t.Fatal(err)
	}
	openFindings := 0
	for _, e := range r.ev {
		if e.Kind == "finding" {
			openFindings++
		}
	}
	if openFindings != 2 {
		t.Errorf("expected 2 open findings, got %d (ports were %d %d %d): %+v", openFindings, p1, p2, closedPort, r.ev)
	}
}

func scanPortString(a, b, c int) string {
	return itoa(a) + "," + itoa(b) + "," + itoa(c)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	n := 0
	for i > 0 {
		buf[n] = byte('0' + i%10)
		i /= 10
		n++
	}
	out := make([]byte, n)
	for j := 0; j < n; j++ {
		out[j] = buf[n-1-j]
	}
	return string(out)
}
