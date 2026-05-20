package api

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/silvance/polypent/internal/audit"
	"github.com/silvance/polypent/internal/auth"
)

type issueTokenInput struct {
	Role       auth.Role  `json:"role"`
	ProjectID  *uuid.UUID `json:"project_id,omitempty"`
	Name       string     `json:"name"`
	TTLSeconds int        `json:"ttl_seconds,omitempty"`
}

type issueTokenOutput struct {
	ID        uuid.UUID  `json:"id"`
	Token     string     `json:"token"`
	Role      auth.Role  `json:"role"`
	ProjectID *uuid.UUID `json:"project_id,omitempty"`
	Name      string     `json:"name"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func (s *Server) handleIssueToken(w http.ResponseWriter, r *http.Request) {
	pr, ok := auth.FromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var in issueTokenInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !in.Role.Valid() {
		writeError(w, http.StatusBadRequest, "invalid role")
		return
	}

	// Authorization:
	//   - admin may issue any token
	//   - owner may issue project-scoped non-admin tokens for THEIR project
	switch pr.Role {
	case auth.RoleAdmin:
		// no further restrictions
	case auth.RoleOwner:
		if in.Role == auth.RoleAdmin {
			writeError(w, http.StatusForbidden, "owner may not issue admin tokens")
			return
		}
		if in.ProjectID == nil || pr.ProjectID == nil || *in.ProjectID != *pr.ProjectID {
			writeError(w, http.StatusForbidden, "owner may only issue tokens for their own project")
			return
		}
	default:
		writeError(w, http.StatusForbidden, "insufficient role")
		return
	}

	ttl := time.Duration(in.TTLSeconds) * time.Second
	tok, err := s.deps.Tokens.Issue(r.Context(), in.Role, in.ProjectID, in.Name, ttl)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.deps.Audit.Append(r.Context(), audit.Event{
		ProjectID:    in.ProjectID,
		ActorTokenID: &pr.TokenID,
		Action:       "token.issue",
		TargetKind:   "token",
		TargetID:     tok.ID.String(),
		Metadata:     map[string]any{"role": string(in.Role), "name": in.Name},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "audit append failed")
		return
	}
	writeJSON(w, http.StatusCreated, issueTokenOutput{
		ID:        tok.ID,
		Token:     tok.Plaintext,
		Role:      tok.Role,
		ProjectID: tok.ProjectID,
		Name:      tok.Name,
		ExpiresAt: tok.ExpiresAt,
	})
}
