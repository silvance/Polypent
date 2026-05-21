package api

import (
	"errors"
	"net/http"

	"github.com/silvance/polypent/internal/audit"
	"github.com/silvance/polypent/internal/auth"
	"github.com/silvance/polypent/internal/manifest"
	"github.com/silvance/polypent/internal/run"
	"github.com/silvance/polypent/internal/version"
)

func (s *Server) handleGetRunManifest(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUIDPath(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid run id")
		return
	}
	rn, err := s.deps.Runs.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, run.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get failed")
		return
	}
	if !s.authorizeProjectRead(w, r, rn.ProjectID) {
		return
	}

	m, err := manifest.Build(r.Context(), s.deps.Queue.Pool(), id, version.Version)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sig, err := manifest.Sign(m, s.deps.AuditKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	pr, _ := auth.FromContext(r.Context())
	if _, err := s.deps.Audit.Append(r.Context(), audit.Event{
		ProjectID:    &rn.ProjectID,
		ActorTokenID: &pr.TokenID,
		Action:       "run.manifest",
		TargetKind:   "run",
		TargetID:     id.String(),
		Metadata:     map[string]any{"signature": sig},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "audit append failed")
		return
	}

	writeJSON(w, http.StatusOK, manifest.Signed{
		Manifest:  m,
		Signature: sig,
		KeyID:     "audit-signing-key",
	})
}
