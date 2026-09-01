// Package audit provides local, deterministic snapshots, semantic diffs, and
// policy checks for Whodis reports. It performs no background network work.
package audit

import (
	"encoding/json"
	"time"

	"github.com/Alex9001/whodis/v2"
)

const (
	SnapshotSchemaVersion = 1
	DiffSchemaVersion     = 1
	PolicySchemaVersion   = 1
	CheckSchemaVersion    = 1
)

type GeneratorInfo struct {
	Name    string `json:"name" yaml:"name"`
	Version string `json:"version" yaml:"version"`
}

// ReplayRequest is the secret-free subset required to repeat a snapshot.
type ReplayRequest struct {
	Operation     whodis.Operation           `json:"operation" yaml:"operation"`
	Target        string                     `json:"target" yaml:"target"`
	Timeout       string                     `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	Registration  RegistrationOptions        `json:"registration,omitempty" yaml:"registration,omitempty"`
	DNS           whodis.DNSOptions          `json:"dns,omitempty" yaml:"dns,omitempty"`
	Diagnose      ReplayDiagnoseOptions      `json:"diagnose,omitempty" yaml:"diagnose,omitempty"`
	Investigation ReplayInvestigationOptions `json:"investigation,omitempty" yaml:"investigation,omitempty"`
}

type RegistrationOptions struct {
	Protocol         whodis.Protocol     `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	Fallback         whodis.FallbackMode `json:"fallback,omitempty" yaml:"fallback,omitempty"`
	Server           string              `json:"server,omitempty" yaml:"server,omitempty"`
	RefreshBootstrap bool                `json:"refresh_bootstrap,omitempty" yaml:"refresh_bootstrap,omitempty"`
}

type ReplayDiagnoseOptions struct {
	Trace        bool `json:"trace,omitempty" yaml:"trace,omitempty"`
	Remote       bool `json:"remote,omitempty" yaml:"remote,omitempty"`
	MaxAddresses int  `json:"max_addresses,omitempty" yaml:"max_addresses,omitempty"`
}

type ReplayInvestigationOptions struct {
	RelatedLimit         int      `json:"related_limit,omitempty" yaml:"related_limit,omitempty"`
	LinkProviders        []string `json:"link_providers,omitempty" yaml:"link_providers,omitempty"`
	ExternalLinkTemplate string   `json:"external_link_template,omitempty" yaml:"external_link_template,omitempty"`
}

// ReplayOptions controls exceptional network configuration restored from a
// snapshot. Custom endpoints are disabled by default because snapshots may be
// imported from untrusted sources.
type ReplayOptions struct {
	AllowCustomEndpoints bool
}

// Snapshot contains one complete ordered batch and the safe request needed to
// reproduce it. Snapshot files are immutable once stored.
type Snapshot struct {
	SchemaVersion int                `json:"snapshot_schema_version" yaml:"snapshot_schema_version"`
	ID            string             `json:"id" yaml:"id"`
	Label         string             `json:"label,omitempty" yaml:"label,omitempty"`
	CreatedAt     time.Time          `json:"created_at" yaml:"created_at"`
	Generator     GeneratorInfo      `json:"generator" yaml:"generator"`
	Requests      []ReplayRequest    `json:"requests" yaml:"requests"`
	Batch         whodis.BatchReport `json:"batch" yaml:"batch"`
}

type Metadata struct {
	ID         string             `json:"id" yaml:"id"`
	Label      string             `json:"label,omitempty" yaml:"label,omitempty"`
	CreatedAt  time.Time          `json:"created_at" yaml:"created_at"`
	Operations []whodis.Operation `json:"operations" yaml:"operations"`
	Targets    []string           `json:"targets" yaml:"targets"`
	Path       string             `json:"path,omitempty" yaml:"path,omitempty"`
}

type ChangeKind string

const (
	ChangeAdded   ChangeKind = "added"
	ChangeRemoved ChangeKind = "removed"
	ChangeChanged ChangeKind = "changed"
)

type SnapshotRef struct {
	ID        string    `json:"id,omitempty" yaml:"id,omitempty"`
	Label     string    `json:"label,omitempty" yaml:"label,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty" yaml:"created_at,omitempty"`
}

type Change struct {
	Path   string     `json:"path" yaml:"path"`
	Kind   ChangeKind `json:"kind" yaml:"kind"`
	Before []string   `json:"before,omitempty" yaml:"before,omitempty"`
	After  []string   `json:"after,omitempty" yaml:"after,omitempty"`
}

type ChangeSet struct {
	SchemaVersion int         `json:"diff_schema_version" yaml:"diff_schema_version"`
	Before        SnapshotRef `json:"before" yaml:"before"`
	After         SnapshotRef `json:"after" yaml:"after"`
	Changes       []Change    `json:"changes,omitempty" yaml:"changes,omitempty"`
	Warnings      []string    `json:"warnings,omitempty" yaml:"warnings,omitempty"`
}

type DiffOptions struct {
	IncludeTTL bool
}

type Scrutiny string

const (
	ScrutinyBasic    Scrutiny = "basic"
	ScrutinyStandard Scrutiny = "standard"
	ScrutinyStrict   Scrutiny = "strict"
)

type CheckStatus string

const (
	CheckPass    CheckStatus = "pass"
	CheckFail    CheckStatus = "fail"
	CheckUnknown CheckStatus = "unknown"
	CheckSkipped CheckStatus = "skipped"
)

type Rule struct {
	ID       string          `json:"id" yaml:"id"`
	Type     string          `json:"type" yaml:"type"`
	Severity whodis.Severity `json:"severity" yaml:"severity"`
	Config   json.RawMessage `json:"config,omitempty" yaml:"-"`
}

type Policy struct {
	SchemaVersion int    `json:"policy_schema_version" yaml:"policy_schema_version"`
	Name          string `json:"name" yaml:"name"`
	Rules         []Rule `json:"rules,omitempty" yaml:"rules,omitempty"`
}

type RuleResult struct {
	RuleID      string            `json:"rule_id" yaml:"rule_id"`
	ReportIndex *int              `json:"report_index,omitempty" yaml:"report_index,omitempty"`
	Subject     *whodis.Subject   `json:"subject,omitempty" yaml:"subject,omitempty"`
	Status      CheckStatus       `json:"status" yaml:"status"`
	Severity    whodis.Severity   `json:"severity" yaml:"severity"`
	Message     string            `json:"message" yaml:"message"`
	Evidence    map[string]string `json:"evidence,omitempty" yaml:"evidence,omitempty"`
}

type CheckSummary struct {
	Passed   int `json:"passed" yaml:"passed"`
	Failed   int `json:"failed" yaml:"failed"`
	Unknown  int `json:"unknown" yaml:"unknown"`
	Skipped  int `json:"skipped" yaml:"skipped"`
	Warnings int `json:"warnings" yaml:"warnings"`
}

type CheckReport struct {
	SchemaVersion int                     `json:"check_schema_version" yaml:"check_schema_version"`
	Scrutiny      Scrutiny                `json:"scrutiny" yaml:"scrutiny"`
	EvaluatedAt   time.Time               `json:"evaluated_at" yaml:"evaluated_at"`
	Subjects      []whodis.Subject        `json:"subjects" yaml:"subjects"`
	Results       []RuleResult            `json:"results" yaml:"results"`
	Changes       *ChangeSet              `json:"changes,omitempty" yaml:"changes,omitempty"`
	Errors        []whodis.OperationError `json:"errors,omitempty" yaml:"errors,omitempty"`
	Summary       CheckSummary            `json:"summary" yaml:"summary"`
}
