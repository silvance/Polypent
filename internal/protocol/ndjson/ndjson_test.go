package ndjson

import (
	"context"
	"io"
	"strings"
	"testing"
)

func TestReaderHappyPath(t *testing.T) {
	body := strings.Join([]string{
		`{"type":"hello","payload":{"name":"x","version":"1","protocol_version":"polypent-ndjson/1"}}`,
		`{"type":"progress","payload":{"done":1,"total":3,"stage":"resolve"}}`,
		`{"type":"finding","payload":{"kind":"info","severity":"informational","title":"hi","dedup_key":"a"}}`,
		`{"type":"done","payload":{"summary":{"ok":true}}}`,
	}, "\n") + "\n"

	r := NewReader(strings.NewReader(body), 0)
	ctx := context.Background()
	types := []EventType{EventHello, EventProgress, EventFinding, EventDone}
	for i, want := range types {
		env, err := r.Next(ctx)
		if err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
		if env.Type != want {
			t.Errorf("event %d: got %q want %q", i, env.Type, want)
		}
	}
	if _, err := r.Next(ctx); err != io.EOF {
		t.Errorf("expected EOF, got %v", err)
	}
}

func TestReaderRejectsTooLong(t *testing.T) {
	huge := strings.Repeat("a", 200)
	body := `{"type":"log","payload":{"message":"` + huge + `"}}` + "\n"
	r := NewReader(strings.NewReader(body), 50)
	if _, err := r.Next(context.Background()); err == nil {
		t.Fatal("expected error on oversize line")
	}
}

func TestReaderRequiresType(t *testing.T) {
	r := NewReader(strings.NewReader(`{"payload":{}}`+"\n"), 0)
	if _, err := r.Next(context.Background()); err == nil {
		t.Fatal("expected error on missing type")
	}
}

func TestDecodePayload(t *testing.T) {
	body := `{"type":"progress","payload":{"done":1,"total":2,"stage":"go"}}` + "\n"
	env, err := NewReader(strings.NewReader(body), 0).Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var p ProgressPayload
	if err := DecodePayload(env, &p); err != nil {
		t.Fatal(err)
	}
	if p.Done != 1 || p.Total != 2 || p.Stage != "go" {
		t.Errorf("decoded: %+v", p)
	}
}
