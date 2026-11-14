package vex

import (
	"encoding/json"
	"fmt"
	"time"
)

// OpenVEXContext is the official OpenVEX v0.2.0 JSON-LD context URL.
const OpenVEXContext = "https://openvex.dev/ns/v0.2.0"

// Status constants as defined by the OpenVEX specification.
const (
	StatusNotAffected        = "not_affected"
	StatusAffected           = "affected"
	StatusFixed              = "fixed"
	StatusUnderInvestigation = "under_investigation"
)

// Justification constants for StatusNotAffected.
const (
	JustificationVulnerableCodeNotPresent                    = "vulnerable_code_not_present"
	JustificationVulnerableCodeNotInExecutePath              = "vulnerable_code_not_in_execute_path"
	JustificationVulnerableCodeCannotBeControlledByAdversary = "vulnerable_code_cannot_be_controlled_by_adversary"
	JustificationInlineMitigationsAlreadyExist               = "inline_mitigations_already_exist"
)

// VulnerabilityIdent describes the specific CVE or vulnerability ID.
type VulnerabilityIdent struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// Statement describes the status of a vulnerability relative to one or more products.
type Statement struct {
	Vulnerability   VulnerabilityIdent `json:"vulnerability"`
	Products        []string           `json:"products"`
	Status          string             `json:"status"`
	Justification   string             `json:"justification,omitempty"`
	ImpactStatement string             `json:"impact_statement,omitempty"`
	StatusNotes     string             `json:"status_notes,omitempty"`
}

// OpenVEXDocument represents a complete OpenVEX document (v0.2.0).
type OpenVEXDocument struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id"`
	Author     string      `json:"author"`
	Role       string      `json:"role,omitempty"`
	Timestamp  string      `json:"timestamp"`
	Version    int         `json:"version"`
	Tooling    string      `json:"tooling,omitempty"`
	Statements []Statement `json:"statements"`
}

// NewOpenVEXDocument initializes a compliant OpenVEX document.
func NewOpenVEXDocument(author string) *OpenVEXDocument {
	now := time.Now().UTC()
	docID := fmt.Sprintf("https://bonjoski.github.io/vex/doc-%d", now.UnixNano())
	if author == "" {
		author = "bomhound-vex / sovereign-agent-security"
	}

	return &OpenVEXDocument{
		Context:    OpenVEXContext,
		ID:         docID,
		Author:     author,
		Role:       "Document Creator",
		Timestamp:  now.Format(time.RFC3339),
		Version:    1,
		Tooling:    "bomhound-vex/1.0",
		Statements: make([]Statement, 0),
	}
}

// ToJSON serializes the OpenVEX document into indented JSON.
func (d *OpenVEXDocument) ToJSON() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}
