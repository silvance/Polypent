package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	pgstore "github.com/silvance/polypent/internal/store/postgres"
)

func TestSecretsVaultRoundTripAndConfidentiality(t *testing.T) {
	dsn := testDSN(t)
	resetSchema(t, dsn)
	srv, adminTok := newTestServer(t, dsn)
	c := &apiClient{t: t, url: srv.URL, tok: adminTok.Plaintext}

	// project
	status, body := c.do("POST", "/v1/projects", map[string]any{
		"slug": "sec", "name": "Secrets", "owner": "alice",
	})
	if status != http.StatusCreated {
		t.Fatalf("project: %d %s", status, body)
	}
	var p struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &p)

	// PUT a secret
	status, body = c.do("PUT", "/v1/projects/"+p.ID+"/secrets/AWS_KEY", map[string]any{
		"value": "AKIATESTVALUEAAAAA",
	})
	if status != http.StatusOK {
		t.Fatalf("put: %d %s", status, body)
	}
	if !strings.Contains(string(body), "AWS_KEY") {
		t.Errorf("PUT response should echo key: %s", body)
	}

	// LIST shows the key but NEVER the value
	status, body = c.do("GET", "/v1/projects/"+p.ID+"/secrets", nil)
	if status != http.StatusOK {
		t.Fatalf("list: %d %s", status, body)
	}
	if strings.Contains(string(body), "AKIATESTVALUEAAAAA") {
		t.Errorf("LIST must NOT contain plaintext value: %s", body)
	}
	if !strings.Contains(string(body), "AWS_KEY") {
		t.Errorf("LIST should list the key name: %s", body)
	}

	// The stored ciphertext in the DB is not the plaintext.
	pgPool, err := pgstore.Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pgPool.Close()
	var ciphertext []byte
	if err := pgPool.QueryRow(context.Background(),
		`SELECT ciphertext FROM project_secrets WHERE key='AWS_KEY'`).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ciphertext), "AKIATESTVALUEAAAAA") {
		t.Fatalf("ciphertext leaks plaintext: %x", ciphertext)
	}

	// Audit log should NOT contain the plaintext anywhere.
	var auditRows int
	if err := pgPool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM audit_events
		 WHERE action='secret.put' AND metadata::text LIKE '%AKIA%'`).Scan(&auditRows); err != nil {
		t.Fatal(err)
	}
	if auditRows != 0 {
		t.Errorf("audit event leaked plaintext (%d rows)", auditRows)
	}

	// Rotate (re-PUT) and verify ciphertext changes
	old := append([]byte(nil), ciphertext...)
	status, _ = c.do("PUT", "/v1/projects/"+p.ID+"/secrets/AWS_KEY", map[string]any{"value": "rotated-value"})
	if status != http.StatusOK {
		t.Fatalf("re-put: %d", status)
	}
	var nextCT []byte
	_ = pgPool.QueryRow(context.Background(),
		`SELECT ciphertext FROM project_secrets WHERE key='AWS_KEY'`).Scan(&nextCT)
	if string(nextCT) == string(old) {
		t.Errorf("ciphertext should change on rotation")
	}

	// DELETE
	status, _ = c.do("DELETE", "/v1/projects/"+p.ID+"/secrets/AWS_KEY", nil)
	if status != http.StatusNoContent {
		t.Errorf("delete: %d", status)
	}
	status, _ = c.do("DELETE", "/v1/projects/"+p.ID+"/secrets/AWS_KEY", nil)
	if status != http.StatusNotFound {
		t.Errorf("re-delete should be 404, got %d", status)
	}

	// Reject bad keys
	status, _ = c.do("PUT", "/v1/projects/"+p.ID+"/secrets/has%20space", map[string]any{"value": "x"})
	if status < 400 {
		t.Errorf("bad key should be rejected, got %d", status)
	}
}
