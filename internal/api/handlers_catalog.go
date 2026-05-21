package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/silvance/polypent/internal/audit"
	"github.com/silvance/polypent/internal/auth"
	"github.com/silvance/polypent/internal/catalog"
	"github.com/silvance/polypent/internal/external"
)

type catalogUpsertInput struct {
	Name         string   `json:"name"`
	Language     string   `json:"language,omitempty"`
	Version      string   `json:"version,omitempty"`
	BinaryPath   string   `json:"binary_path"`
	Transport    string   `json:"transport,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Description  string   `json:"description,omitempty"`
	CPUHint      int      `json:"cpu_hint,omitempty"`
	MemoryMBHint int      `json:"memory_mb_hint,omitempty"`
	RateHint     int      `json:"rate_hint,omitempty"`
	TimeoutSec   int      `json:"timeout_sec,omitempty"`
}

func (s *Server) handleListCatalog(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth.FromContext(r.Context()); !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	entries, err := s.deps.Catalog.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"collectors": entries})
}

func (s *Server) handleUpsertCatalog(w http.ResponseWriter, r *http.Request) {
	pr, ok := auth.FromContext(r.Context())
	if !ok || pr.Role != auth.RoleAdmin {
		writeError(w, http.StatusForbidden, "admin required")
		return
	}
	var in catalogUpsertInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	entry, err := s.deps.Catalog.Upsert(r.Context(), catalog.Entry{
		Name:         in.Name,
		Language:     in.Language,
		Version:      in.Version,
		BinaryPath:   in.BinaryPath,
		Transport:    catalog.Transport(in.Transport),
		Capabilities: in.Capabilities,
		Description:  in.Description,
		CPUHint:      in.CPUHint,
		MemoryMBHint: in.MemoryMBHint,
		RateHint:     in.RateHint,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Register the new collector in the live in-process registry so the
	// worker pool can dispatch to it without a restart. If a name was
	// previously registered, we keep the existing one; admins can restart
	// to pick up new binaries for the same name (a future "hot-reload"
	// endpoint would be a Phase 7+ refinement).
	if _, exists := s.deps.Collectors.Get(entry.Name); !exists {
		if entry.Transport == catalog.TransportNDJSON {
			timeout := time.Duration(in.TimeoutSec) * time.Second
			s.deps.Collectors.Register(external.NewSupervisor(entry.Name, entry.BinaryPath, nil, timeout))
		}
	}

	if _, err := s.deps.Audit.Append(r.Context(), audit.Event{
		ActorTokenID: &pr.TokenID,
		Action:       "catalog.upsert",
		TargetKind:   "collector",
		TargetID:     entry.Name,
		Metadata: map[string]any{
			"binary_path": entry.BinaryPath,
			"transport":   string(entry.Transport),
		},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "audit append failed")
		return
	}
	writeJSON(w, http.StatusCreated, entry)
}

func (s *Server) handleDeleteCatalog(w http.ResponseWriter, r *http.Request) {
	pr, ok := auth.FromContext(r.Context())
	if !ok || pr.Role != auth.RoleAdmin {
		writeError(w, http.StatusForbidden, "admin required")
		return
	}
	name := r.PathValue("name")
	if err := s.deps.Catalog.Delete(r.Context(), name); err != nil {
		if errors.Is(err, catalog.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if _, err := s.deps.Audit.Append(r.Context(), audit.Event{
		ActorTokenID: &pr.TokenID,
		Action:       "catalog.delete",
		TargetKind:   "collector",
		TargetID:     name,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "audit append failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
