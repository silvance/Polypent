package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/silvance/polypent/internal/audit"
	"github.com/silvance/polypent/internal/auth"
	"github.com/silvance/polypent/internal/project"
)

func (s *Server) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.FromContext(r.Context())
	if !ok || p.Role != auth.RoleAdmin {
		writeError(w, http.StatusForbidden, "only admin tokens may create projects")
		return
	}

	var in project.CreateInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := in.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	created, err := s.deps.Projects.Create(r.Context(), in)
	if err != nil {
		if errors.Is(err, project.ErrSlugConflict) {
			writeError(w, http.StatusConflict, "slug already in use")
			return
		}
		writeError(w, http.StatusInternalServerError, "create failed")
		return
	}
	if _, err := s.deps.Audit.Append(r.Context(), audit.Event{
		ProjectID:    &created.ID,
		ActorTokenID: &p.TokenID,
		Action:       "project.create",
		TargetKind:   "project",
		TargetID:     created.ID.String(),
		Metadata:     map[string]any{"slug": created.Slug},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "audit append failed")
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleListProjects(w http.ResponseWriter, r *http.Request) {
	// Admin sees all; project-scoped sees only its own project.
	pr, _ := auth.FromContext(r.Context())
	all, err := s.deps.Projects.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	if pr.Role != auth.RoleAdmin && pr.ProjectID != nil {
		filtered := all[:0]
		for _, p := range all {
			if p.ID == *pr.ProjectID {
				filtered = append(filtered, p)
			}
		}
		all = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{"projects": all})
}

func (s *Server) handleGetProject(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUIDPath(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	pr, _ := auth.FromContext(r.Context())
	if pr.Role != auth.RoleAdmin && (pr.ProjectID == nil || *pr.ProjectID != id) {
		writeError(w, http.StatusForbidden, "not your project")
		return
	}
	p, err := s.deps.Projects.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, project.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get failed")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleUpdateProject(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUIDPath(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	pr, _ := auth.FromContext(r.Context())
	if pr.Role != auth.RoleAdmin && pr.Role != auth.RoleOwner {
		writeError(w, http.StatusForbidden, "admin or owner required")
		return
	}
	if pr.Role == auth.RoleOwner && (pr.ProjectID == nil || *pr.ProjectID != id) {
		writeError(w, http.StatusForbidden, "not your project")
		return
	}

	var in project.UpdateInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := s.deps.Projects.Update(r.Context(), id, in)
	if err != nil {
		if errors.Is(err, project.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	if _, err := s.deps.Audit.Append(r.Context(), audit.Event{
		ProjectID:    &updated.ID,
		ActorTokenID: &pr.TokenID,
		Action:       "project.update",
		TargetKind:   "project",
		TargetID:     updated.ID.String(),
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "audit append failed")
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func parseUUIDPath(r *http.Request, name string) (uuid.UUID, bool) {
	raw := r.PathValue(name)
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, false
	}
	return id, true
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
