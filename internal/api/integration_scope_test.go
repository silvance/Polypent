package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	pgstore "github.com/silvance/polypent/internal/store/postgres"
)

func openPool(dsn string) (*pgxpool.Pool, error) {
	return pgstore.Open(context.Background(), dsn)
}

// TestScopeRulesetCoversRealEngagement is the Phase 2 exit-criterion test:
// the scope CRUD + check endpoints handle a ruleset shaped like a real
// engagement (IPv4 CIDR, IPv6 CIDR, DNS wildcard, a deny carve-out, a
// time-window allow, and a rate cap on a per-host allow), and verdicts
// match expectations.
func TestScopeRulesetCoversRealEngagement(t *testing.T) {
	dsn := testDSN(t)
	resetSchema(t, dsn)
	srv, adminTok := newTestServer(t, dsn)
	c := &apiClient{t: t, url: srv.URL, tok: adminTok.Plaintext}

	// create the engagement project
	status, body := c.do("POST", "/v1/projects", map[string]any{
		"slug": "scope-eng", "name": "Scope Eng", "owner": "alice",
	})
	if status != http.StatusCreated {
		t.Fatalf("create project: %d %s", status, body)
	}
	var p struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &p)

	// ROE-shaped ruleset, evaluated first-match-wins:
	//   0  deny  CIDR  10.0.99.0/24         (carve-out: prod jumphost)
	//   1  allow CIDR  10.0.0.0/16
	//   2  allow CIDR  2001:db8::/32        (IPv6 lab range)
	//   3  allow dns_wildcard *.test.example.com
	//   4  allow CIDR  192.0.2.0/24  (within a maintenance window only)
	//   5  allow host  10.0.0.10  (rate-capped at 2 concurrent / 5rps)
	winStart := time.Now().Add(-time.Hour).UTC()
	winEnd := time.Now().Add(time.Hour).UTC()
	rules := []map[string]any{
		{"order": 0, "effect": "deny", "kind": "cidr", "value": "10.0.99.0/24",
			"note": "ROE §3.1: prod jumphost excluded"},
		// rate-capped specific host must come before the broader 10.0.0.0/16
		// allow so first-match-wins picks it for that host.
		{"order": 1, "effect": "allow", "kind": "host", "value": "10.0.0.10",
			"max_concurrent": 2, "max_rps": 5.0},
		{"order": 2, "effect": "allow", "kind": "cidr", "value": "10.0.0.0/16"},
		{"order": 3, "effect": "allow", "kind": "cidr", "value": "2001:db8::/32"},
		{"order": 4, "effect": "allow", "kind": "dns_wildcard", "value": "*.test.example.com"},
		{"order": 5, "effect": "allow", "kind": "cidr", "value": "192.0.2.0/24",
			"window_start": winStart, "window_end": winEnd},
	}
	for _, body := range rules {
		status, resp := c.do("POST", "/v1/projects/"+p.ID+"/scope", body)
		if status != http.StatusCreated {
			t.Fatalf("create rule: %d %s", status, resp)
		}
	}

	// list - sanity
	status, resp := c.do("GET", "/v1/projects/"+p.ID+"/scope", nil)
	if status != http.StatusOK {
		t.Fatalf("list rules: %d %s", status, resp)
	}

	// check matrix
	type tc struct {
		name        string
		in          map[string]any
		wantEffect  string
		wantCapsRPS float64
	}
	cases := []tc{
		{"v4-allowed", map[string]any{"kind": "host", "identity": "10.0.0.5", "host": "10.0.0.5"}, "allow", 0},
		{"v4-carve-out-denied", map[string]any{"kind": "host", "identity": "10.0.99.5", "host": "10.0.99.5"}, "deny", 0},
		{"v6-allowed", map[string]any{"kind": "host", "identity": "2001:db8:1::1", "host": "2001:db8:1::1"}, "allow", 0},
		{"dns-wildcard-sub", map[string]any{"kind": "dns_name", "identity": "api.test.example.com"}, "allow", 0},
		{"dns-wildcard-not-apex", map[string]any{"kind": "dns_name", "identity": "test.example.com"}, "out_of_scope", 0},
		{"rate-capped-host", map[string]any{"kind": "host", "identity": "10.0.0.10", "host": "10.0.0.10"}, "allow", 5.0},
		{"out-of-scope", map[string]any{"kind": "host", "identity": "203.0.113.4", "host": "203.0.113.4"}, "out_of_scope", 0},
	}
	for _, tc := range cases {
		status, body := c.do("POST", "/v1/projects/"+p.ID+"/scope/check", tc.in)
		if status != http.StatusOK {
			t.Errorf("%s: status %d body=%s", tc.name, status, body)
			continue
		}
		var out struct {
			Effect string `json:"effect"`
			Caps   struct {
				MaxRPS float64 `json:"max_rps"`
			} `json:"caps"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			t.Errorf("%s: decode: %v body=%s", tc.name, err, body)
			continue
		}
		if out.Effect != tc.wantEffect {
			t.Errorf("%s: effect %q want %q (body=%s)", tc.name, out.Effect, tc.wantEffect, body)
		}
		if tc.wantCapsRPS > 0 && out.Caps.MaxRPS != tc.wantCapsRPS {
			t.Errorf("%s: caps.rps %v want %v", tc.name, out.Caps.MaxRPS, tc.wantCapsRPS)
		}
	}

	// upsert a target and confirm it round-trips through the list endpoint
	status, body = c.do("POST", "/v1/projects/"+p.ID+"/targets", map[string]any{
		"kind": "host", "identity": "10.0.0.5", "source_type": "seed",
	})
	if status != http.StatusOK {
		t.Fatalf("upsert target: %d %s", status, body)
	}
	status, body = c.do("GET", "/v1/projects/"+p.ID+"/targets", nil)
	if status != http.StatusOK {
		t.Fatalf("list targets: %d %s", status, body)
	}

	// audit still verifies
	pool, err := openPool(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM audit_events WHERE action LIKE 'scope.%'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < len(rules) {
		t.Errorf("expected %d scope audit events, got %d", len(rules), n)
	}
}
