package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/silvance/polypent/internal/auth"
)

func TestTokenListAndRevoke(t *testing.T) {
	dsn := testDSN(t)
	resetSchema(t, dsn)
	srv, adminTok := newTestServer(t, dsn)
	admin := &apiClient{t: t, url: srv.URL, tok: adminTok.Plaintext}

	// create a project so we can issue project-scoped tokens
	status, body := admin.do("POST", "/v1/projects", map[string]any{
		"slug": "tok", "name": "Tokens", "owner": "alice",
	})
	if status != http.StatusCreated {
		t.Fatalf("project: %d %s", status, body)
	}
	var p struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &p)

	// issue an operator token
	status, body = admin.do("POST", "/v1/tokens", map[string]any{
		"role": "operator", "project_id": p.ID, "name": "alice-cli",
	})
	if status != http.StatusCreated {
		t.Fatalf("issue: %d %s", status, body)
	}
	var issued struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	_ = json.Unmarshal(body, &issued)

	// list (admin sees all -> at least bootstrap + operator)
	status, body = admin.do("GET", "/v1/tokens", nil)
	if status != http.StatusOK {
		t.Fatalf("list: %d %s", status, body)
	}
	var out struct {
		Tokens []auth.Summary `json:"tokens"`
	}
	_ = json.Unmarshal(body, &out)
	if len(out.Tokens) < 2 {
		t.Fatalf("expected >=2 tokens, got %d", len(out.Tokens))
	}
	for _, s := range out.Tokens {
		if s.RevokedAt != nil {
			t.Errorf("token %s should not be revoked yet", s.ID)
		}
	}

	// operator token may revoke itself
	op := &apiClient{t: t, url: srv.URL, tok: issued.Token}
	status, body = op.do("POST", "/v1/tokens/"+issued.ID+"/revoke", map[string]any{})
	if status != http.StatusNoContent {
		t.Fatalf("self-revoke: %d %s", status, body)
	}

	// now the operator token must be rejected on subsequent calls
	status, _ = op.do("GET", "/v1/tokens", nil)
	if status != http.StatusUnauthorized {
		t.Errorf("revoked token should be 401, got %d", status)
	}

	// the admin still sees both, with revoked_at set on the operator one
	status, body = admin.do("GET", "/v1/tokens", nil)
	if status != http.StatusOK {
		t.Fatalf("admin list after revoke: %d %s", status, body)
	}
	_ = json.Unmarshal(body, &out)
	var found bool
	for _, s := range out.Tokens {
		if s.ID.String() == issued.ID {
			if s.RevokedAt == nil {
				t.Errorf("expected revoked_at set on %s", s.ID)
			}
			found = true
		}
	}
	if !found {
		t.Errorf("issued operator token not in list")
	}

	// revoking a non-existent id returns 404
	status, _ = admin.do("POST", "/v1/tokens/00000000-0000-0000-0000-000000000000/revoke", map[string]any{})
	if status != http.StatusNotFound {
		t.Errorf("expected 404 for unknown id, got %d", status)
	}
}
