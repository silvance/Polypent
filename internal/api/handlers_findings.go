package api

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/silvance/polypent/internal/finding"
)

func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseUUIDPath(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid project id")
		return
	}
	if !s.authorizeProjectRead(w, r, projectID) {
		return
	}
	filter := finding.ListFilter{
		Severity: finding.Severity(r.URL.Query().Get("severity")),
		Kind:     r.URL.Query().Get("kind"),
	}
	if rid := r.URL.Query().Get("run_id"); rid != "" {
		if id, err := uuid.Parse(rid); err == nil {
			filter.RunID = &id
		}
	}
	findings, err := s.deps.Findings.ListByProject(r.Context(), projectID, filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": findings})
}
