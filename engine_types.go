package whodis

import (
	"context"
	"time"
)

// ReportSchemaVersion is the version of Whodis's public JSON report schema.
// Version 3 is operation-oriented: independent registration, DNS, and
// diagnostic results can coexist without one failed provider erasing another.
const ReportSchemaVersion = 3

// Operation identifies one engine operation.
type Operation string

const (
	OperationRegistration Operation = "registration"
	OperationDNSQuery     Operation = "dns.query"
	OperationDNSInventory Operation = "dns.inventory"
	OperationDNSCompare   Operation = "dns.compare"
	OperationDNSTrace     Operation = "dns.trace"
	OperationDNSTransfer  Operation = "dns.transfer"
	OperationDiagnose     Operation = "diagnose"
)

// Severity is the deterministic outcome of a diagnostic finding.
type Severity string

const (
	SeverityPass    Severity = "pass"
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
)

// OperationError is a serializable, provider-scoped failure. Reports may
// contain errors and useful results at the same time.
type OperationError struct {
	Operation Operation `json:"operation" yaml:"operation"`
	Provider  string    `json:"provider,omitempty" yaml:"provider,omitempty"`
	Kind      ErrorKind `json:"kind" yaml:"kind"`
	Message   string    `json:"message" yaml:"message"`
}

// Finding is one deterministic diagnostic observation. Whodis intentionally
// does not collapse findings into an opaque overall score.
type Finding struct {
	ID       string            `json:"id" yaml:"id"`
	Severity Severity          `json:"severity" yaml:"severity"`
	Title    string            `json:"title" yaml:"title"`
	Summary  string            `json:"summary" yaml:"summary"`
	Evidence map[string]string `json:"evidence,omitempty" yaml:"evidence,omitempty"`
}

// ProgressEvent is emitted at stable operation boundaries. Callbacks are
// serialized by Engine.RunBatch and should return quickly.
type ProgressEvent struct {
	RequestID string    `json:"request_id,omitempty" yaml:"request_id,omitempty"`
	Operation Operation `json:"operation" yaml:"operation"`
	Target    string    `json:"target" yaml:"target"`
	Stage     string    `json:"stage" yaml:"stage"`
	Completed int       `json:"completed,omitempty" yaml:"completed,omitempty"`
	Total     int       `json:"total,omitempty" yaml:"total,omitempty"`
}

// Request is the stable public input to Engine.Run.
type Request struct {
	ID           string              `json:"id,omitempty" yaml:"id,omitempty"`
	Operation    Operation           `json:"operation" yaml:"operation"`
	Target       string              `json:"target" yaml:"target"`
	Registration LookupOptions       `json:"registration,omitempty" yaml:"registration,omitempty"`
	DNS          DNSOptions          `json:"dns,omitempty" yaml:"dns,omitempty"`
	Diagnose     DiagnoseOptions     `json:"diagnose,omitempty" yaml:"diagnose,omitempty"`
	Timeout      time.Duration       `json:"-" yaml:"-"`
	OnProgress   func(ProgressEvent) `json:"-" yaml:"-"`
}

// Report is the renderer-independent v3 result returned by Engine.Run.
type Report struct {
	SchemaVersion int                 `json:"schema_version" yaml:"schema_version"`
	Operation     Operation           `json:"operation" yaml:"operation"`
	Query         Target              `json:"query" yaml:"query"`
	RetrievedAt   time.Time           `json:"retrieved_at" yaml:"retrieved_at"`
	Registration  *LookupResult       `json:"registration,omitempty" yaml:"registration,omitempty"`
	DNS           *DNSOperationResult `json:"dns,omitempty" yaml:"dns,omitempty"`
	Diagnosis     *DiagnosisReport    `json:"diagnosis,omitempty" yaml:"diagnosis,omitempty"`
	Findings      []Finding           `json:"findings,omitempty" yaml:"findings,omitempty"`
	Errors        []OperationError    `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// BatchRequest controls a bounded group of independent engine requests.
type BatchRequest struct {
	Requests   []Request
	Workers    int
	OnProgress func(ProgressEvent)
}

// BatchReport preserves request order and partial failures.
type BatchReport struct {
	SchemaVersion int      `json:"schema_version" yaml:"schema_version"`
	Reports       []Report `json:"reports" yaml:"reports"`
}

// RegistrationProvider is the dependency-injection boundary for normalized
// registration lookup implementations.
type RegistrationProvider interface {
	Lookup(context.Context, string, LookupOptions) (LookupResult, error)
}

// DNSProvider is the dependency-injection boundary for DNS operations.
type DNSProvider interface {
	Query(context.Context, string, DNSOptions) (*DNSOperationResult, error)
	Inventory(context.Context, string, DNSOptions) (*DNSOperationResult, error)
	Compare(context.Context, string, DNSOptions) (*DNSOperationResult, error)
	Trace(context.Context, string, DNSOptions) (*DNSOperationResult, error)
	Transfer(context.Context, string, DNSOptions) (*DNSOperationResult, error)
}

// DiagnoseProvider is the dependency-injection boundary for domain checks.
type DiagnoseProvider interface {
	Diagnose(context.Context, string, DiagnoseOptions) (*DiagnosisReport, error)
}

// EngineOptions configures a reusable, concurrency-safe engine.
type EngineOptions struct {
	Client       *Client
	Registration RegistrationProvider
	DNS          DNSProvider
	Diagnose     DiagnoseProvider
	Timeout      time.Duration
}
