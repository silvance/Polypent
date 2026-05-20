package api

import (
	"net/http"

	"github.com/silvance/polypent/internal/audit"
	"github.com/silvance/polypent/internal/auth"
	"github.com/silvance/polypent/internal/target"
)

type targetUpsertInput struct {
	Kind       string         `json:"kind"`
	Identity   string         `json:"identity"`
	Attributes map[string]any `json:"attributes,omitempty"`
	SourceType string         `json:"source_type,omitempty"`
	SourceID   string         `json:"source_id,omitempty"`
}

func (s *Server) handleUpsertTarget(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseUUIDPath(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid project id")
		return
	}
	if !s.authorizeScopeWrite(w, r, projectID) {
		return
	}
	var in targetUpsertInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	t, err := s.deps.Targets.Upsert(r.Context(), projectID, target.UpsertInput{
		Kind:       in.Kind,
		Identity:   in.Identity,
		Attributes: in.Attributes,
		SourceType: in.SourceType,
		SourceID:   in.SourceID,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	pr, _ := auth.FromContext(r.Context())
	if _, err := s.deps.Audit.Append(r.Context(), audit.Event{
		ProjectID:    &projectID,
		ActorTokenID: &pr.TokenID,
		Action:       "target.upsert",
		TargetKind:   "target",
		TargetID:     t.ID.String(),
		Metadata:     map[string]any{"kind": t.Kind, "identity": t.Identity},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "audit append failed")
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) handleListTargets(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseUUIDPath(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid project id")
		return
	}
	if !s.authorizeProjectRead(w, r, projectID) {
		return
	}
	ts, err := s.deps.Targets.List(r.Context(), projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"targets": ts})
}
