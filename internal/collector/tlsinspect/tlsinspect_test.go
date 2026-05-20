package tlsinspect

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestInspectAgainstHttptestTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	c := NewWithDial((&net.Dialer{}).DialContext, true)
	r := &rec{}
	job := queue.Job{
		ID:             uuid.New(),
		TargetKind:     "host",
		TargetIdentity: u.Host,
	}
	if err := c.Execute(context.Background(), job, r.emit); err != nil {
		t.Fatalf("execute: %v", err)
	}
	var versionSeen, certSeen, doneSeen bool
	for _, e := range r.ev {
		switch e.Kind {
		case "finding":
			if k, _ := e.Payload["kind"].(string); k == "tls.version" {
				versionSeen = true
			} else if k == "tls.cert" {
				certSeen = true
			}
		case "done":
			doneSeen = true
		}
	}
	if !versionSeen || !certSeen || !doneSeen {
		t.Errorf("missing events: version=%v cert=%v done=%v ev=%+v", versionSeen, certSeen, doneSeen, r.ev)
	}
}
