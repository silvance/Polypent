package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/silvance/polypent/internal/manifest"
)

// TestRunManifestSignedAndVerifies plans a run with the in-tree mock
// collector, waits for it to finish, fetches the run manifest, and
// verifies the HMAC signature reproduces from the canonical bytes.
//
// This is the Phase-7 (partial) signed-manifest deliverable.
func TestRunManifestSignedAndVerifies(t *testing.T) {
	fs := newFullStack(t)
	c := &apiClient{t: t, url: fs.srv.URL, tok: fs.adminTok.Plaintext}

	// project + permissive scope
	status, body := c.do("POST", "/v1/projects", map[string]any{
		"slug": "mft", "name": "Manifest", "owner": "alice",
	})
	if status != http.StatusCreated {
		t.Fatalf("project: %d %s", status, body)
	}
	var p struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &p)
	status, body = c.do("POST", "/v1/projects/"+p.ID+"/scope", map[string]any{
		"order": 0, "effect": "allow", "kind": "cidr", "value": "10.0.0.0/8",
	})
	if status != http.StatusCreated {
		t.Fatalf("scope: %d %s", status, body)
	}

	// run the mock collector — no python/network required
	status, body = c.do("POST", "/v1/projects/"+p.ID+"/runs", map[string]any{
		"capabilities": []string{"mock"},
		"targets": []map[string]any{
			{"kind": "host", "identity": "10.0.0.5", "host": "10.0.0.5"},
		},
		"parameters": map[string]any{"steps": 1},
	})
	if status != http.StatusCreated {
		t.Fatalf("run: %d %s", status, body)
	}
	var r struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &r)
	waitRunTerminal(t, c, r.ID, 10*time.Second)

	// fetch + verify the manifest
	status, body = c.do("GET", "/v1/runs/"+r.ID+"/manifest", nil)
	if status != http.StatusOK {
		t.Fatalf("manifest: %d %s", status, body)
	}
	var signed manifest.Signed
	if err := json.Unmarshal(body, &signed); err != nil {
		t.Fatalf("decode: %v body=%s", err, body)
	}

	key := []byte("p4-mkey-32-bytes-aaaaaaaaaaaaaaaaa")
	ok, err := manifest.Verify(signed.Manifest, signed.Signature, key)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("manifest signature did not verify")
	}

	// sanity: the manifest reflects what happened
	if signed.Manifest.ProjectSlug != "mft" {
		t.Errorf("slug: %q", signed.Manifest.ProjectSlug)
	}
	if len(signed.Manifest.Jobs) != 1 {
		t.Errorf("jobs: want 1, got %d", len(signed.Manifest.Jobs))
	}
	if len(signed.Manifest.Findings) < 1 {
		t.Errorf("findings: want >=1, got %d", len(signed.Manifest.Findings))
	}
	if len(signed.Manifest.Scope) != 1 || signed.Manifest.Scope[0].Value != "10.0.0.0/8" {
		t.Errorf("scope snapshot: %+v", signed.Manifest.Scope)
	}

	// Tamper detection: flipping one byte breaks verification.
	tampered := signed.Manifest
	tampered.Status = "failed"
	ok, _ = manifest.Verify(tampered, signed.Signature, key)
	if ok {
		t.Fatal("verify must fail after mutation")
	}
}
