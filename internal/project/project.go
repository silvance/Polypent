// Package project models PolyPent projects: the top-level container for
// an engagement. Every other entity is scoped to exactly one project.
package project

import (
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"
)

// Project is the persisted entity.
type Project struct {
	ID            uuid.UUID  `json:"id"`
	Slug          string     `json:"slug"`
	Name          string     `json:"name"`
	Owner         string     `json:"owner"`
	Description   string     `json:"description"`
	ROEHash       string     `json:"roe_hash"`
	ContractStart *time.Time `json:"contract_start,omitempty"`
	ContractEnd   *time.Time `json:"contract_end,omitempty"`
	RetentionDays int        `json:"retention_days"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// CreateInput is the API surface for creating a project.
type CreateInput struct {
	Slug          string     `json:"slug"`
	Name          string     `json:"name"`
	Owner         string     `json:"owner"`
	Description   string     `json:"description"`
	ROEHash       string     `json:"roe_hash"`
	ContractStart *time.Time `json:"contract_start,omitempty"`
	ContractEnd   *time.Time `json:"contract_end,omitempty"`
	RetentionDays int        `json:"retention_days"`
}

// UpdateInput captures the patchable fields. nil = leave alone.
type UpdateInput struct {
	Name          *string    `json:"name,omitempty"`
	Owner         *string    `json:"owner,omitempty"`
	Description   *string    `json:"description,omitempty"`
	ROEHash       *string    `json:"roe_hash,omitempty"`
	ContractStart *time.Time `json:"contract_start,omitempty"`
	ContractEnd   *time.Time `json:"contract_end,omitempty"`
	RetentionDays *int       `json:"retention_days,omitempty"`
}

var slugRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Validate checks the create input. Returns ErrInvalid on failure.
func (in CreateInput) Validate() error {
	if !slugRe.MatchString(in.Slug) {
		return errors.New("slug: must be 1-63 chars, lowercase alphanumeric or '-', cannot start/end with '-'")
	}
	if in.Name == "" {
		return errors.New("name: required")
	}
	if in.Owner == "" {
		return errors.New("owner: required")
	}
	if in.RetentionDays != 0 && in.RetentionDays < 1 {
		return errors.New("retention_days: must be positive")
	}
	if in.ContractStart != nil && in.ContractEnd != nil && in.ContractEnd.Before(*in.ContractStart) {
		return errors.New("contract_end: must be on or after contract_start")
	}
	return nil
}
