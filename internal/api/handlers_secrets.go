package api

import (
	"errors"
	"net/http"

	"github.com/silvance/polypent/internal/audit"
	"github.com/silvance/polypent/internal/auth"
	"github.com/silvance/polypent/internal/secrets"
)

type secretPutInput struct {
	Value string `json:"value"`
}

func (s *Server) handlePutSecret(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseUUIDPath(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid project id")
		return
	}
	if !s.authorizeScopeWrite(w, r, projectID) {
		return
	}
	key := r.PathValue("key")
	var in secretPutInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.Value == "" {
		writeError(w, http.StatusBadRequest, "value required")
		return
	}
	pr, _ := auth.FromContext(r.Context())
	sum, err := s.deps.Secrets.Put(r.Context(), projectID, key, []byte(in.Value), &pr.TokenID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.deps.Audit.Append(r.Context(), audit.Event{
		ProjectID:    &projectID,
		ActorTokenID: &pr.TokenID,
		Action:       "secret.put",
		TargetKind:   "secret",
		TargetID:     key,
		Metadata:     map[string]any{"key": key},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "audit append failed")
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseUUIDPath(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid project id")
		return
	}
	if !s.authorizeProjectRead(w, r, projectID) {
		return
	}
	out, err := s.deps.Secrets.List(r.Context(), projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"secrets": out})
}

func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseUUIDPath(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid project id")
		return
	}
	if !s.authorizeScopeWrite(w, r, projectID) {
		return
	}
	key := r.PathValue("key")
	if err := s.deps.Secrets.Delete(r.Context(), projectID, key); err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	pr, _ := auth.FromContext(r.Context())
	if _, err := s.deps.Audit.Append(r.Context(), audit.Event{
		ProjectID:    &projectID,
		ActorTokenID: &pr.TokenID,
		Action:       "secret.delete",
		TargetKind:   "secret",
		TargetID:     key,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "audit append failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
