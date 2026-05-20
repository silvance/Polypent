package api

import (
	"errors"
	"io"
	"net/http"

	"github.com/silvance/polypent/internal/artifact"
	"github.com/silvance/polypent/internal/auth"
)

func (s *Server) handleGetArtifact(w http.ResponseWriter, r *http.Request) {
	sha := r.PathValue("sha")
	meta, err := s.deps.ArtifactMeta.Get(r.Context(), sha)
	if err != nil {
		if errors.Is(err, artifact.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "stat failed")
		return
	}

	// Authorization: callers must have read access on the artifact's
	// owning project (admin always permitted).
	pr, ok := auth.FromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if pr.Role != auth.RoleAdmin {
		if meta.ProjectID == nil || pr.ProjectID == nil || *pr.ProjectID != *meta.ProjectID {
			writeError(w, http.StatusForbidden, "not your artifact")
			return
		}
	}

	rc, err := s.deps.Artifacts.Open(r.Context(), sha)
	if err != nil {
		if errors.Is(err, artifact.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "open failed")
		return
	}
	defer func() { _ = rc.Close() }()
	if meta.Mime != "" {
		w.Header().Set("Content-Type", meta.Mime)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.Header().Set("X-Content-SHA256", sha)
	_, _ = io.Copy(w, rc)
}
