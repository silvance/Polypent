package dnspassive

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/silvance/polypent/internal/collector"
	"github.com/silvance/polypent/internal/queue"
)

type fakeResolver struct {
	hosts []string
	mx    []*net.MX
	ns    []*net.NS
	txt   []string
	err   error
}

func (f *fakeResolver) LookupHost(_ context.Context, _ string) ([]string, error) {
	return f.hosts, f.err
}
func (f *fakeResolver) LookupMX(_ context.Context, _ string) ([]*net.MX, error) {
	return f.mx, f.err
}
func (f *fakeResolver) LookupNS(_ context.Context, _ string) ([]*net.NS, error) {
	return f.ns, f.err
}
func (f *fakeResolver) LookupTXT(_ context.Context, _ string) ([]string, error) {
	return f.txt, f.err
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

func (r *rec) byKindFinding(t string) (collector.Event, bool) {
	for _, e := range r.ev {
		if e.Kind == "finding" {
			if k, _ := e.Payload["kind"].(string); k == t {
				return e, true
			}
		}
	}
	return collector.Event{}, false
}

func TestDNSPassiveEmitsFindings(t *testing.T) {
	fr := &fakeResolver{
		hosts: []string{"10.0.0.1", "10.0.0.2"},
		mx:    []*net.MX{{Host: "mail.example.com.", Pref: 10}},
		ns:    []*net.NS{{Host: "ns1.example.com."}, {Host: "ns2.example.com."}},
		txt:   []string{"v=spf1 -all"},
	}
	c := NewWithResolver(fr)
	r := &rec{}
	job := queue.Job{
		ID:             uuid.New(),
		RunID:          uuid.New(),
		ProjectID:      uuid.New(),
		TargetKind:     "dns_name",
		TargetIdentity: "example.com",
	}
	if err := c.Execute(context.Background(), job, r.emit); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"dns.host", "dns.mx", "dns.ns", "dns.txt"} {
		if _, ok := r.byKindFinding(k); !ok {
			t.Errorf("missing finding kind %q; events=%+v", k, r.ev)
		}
	}
	// dedup_key shape
	host, _ := r.byKindFinding("dns.host")
	if dk, _ := host.Payload["dedup_key"].(string); dk != "dnspassive:host:example.com" {
		t.Errorf("dedup_key = %q", dk)
	}
}

func TestDNSPassiveNoRecordsNoFindings(t *testing.T) {
	c := NewWithResolver(&fakeResolver{})
	r := &rec{}
	job := queue.Job{
		ID:             uuid.New(),
		TargetKind:     "dns_name",
		TargetIdentity: "no-records.example",
	}
	if err := c.Execute(context.Background(), job, r.emit); err != nil {
		t.Fatal(err)
	}
	for _, e := range r.ev {
		if e.Kind == "finding" {
			t.Errorf("unexpected finding with empty resolver: %+v", e)
		}
	}
}
