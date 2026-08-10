// Package whodis provides protocol-aware registration-data lookups.
//
// Its public API intentionally has no terminal or GUI dependency, so the same
// Client can power the command-line tool, native desktop app, and other clients.
package whodis

import (
	"context"
	"time"
)

// Kind is the kind of registration object represented by a Target.
type Kind string

const (
	KindDomain Kind = "domain"
	KindIP     Kind = "ip"
	KindASN    Kind = "asn"
)

// Protocol is a registration-data transport.
type Protocol string

const (
	ProtocolAuto   Protocol = "auto"
	ProtocolRDAP   Protocol = "rdap"
	ProtocolWHOIS  Protocol = "whois"
	ProtocolRWHOIS Protocol = "rwhois"
)

// FallbackMode controls whether Whodis tries the other protocol after its
// knowledge-based primary route fails.
type FallbackMode string

const (
	FallbackUnavailable FallbackMode = "unavailable"
	FallbackNone        FallbackMode = "none"
	FallbackAnyError    FallbackMode = "any-error"
)

// DNSMode controls optional DNS enrichment for a lookup. A zero-value
// LookupOptions leaves DNS disabled; DNSAuto remains available for callers
// that want domain-only discovery without special-casing non-domain targets.
type DNSMode string

const (
	DNSAuto DNSMode = "auto"
	DNSOff  DNSMode = "off"
	DNSScan DNSMode = "scan"
	DNSAXFR DNSMode = "axfr"
)

// Target is a validated, canonical lookup input.
type Target struct {
	Original  string `json:"original" yaml:"original"`
	Canonical string `json:"canonical" yaml:"canonical"`
	Kind      Kind   `json:"kind" yaml:"kind"`
}

// RouteDecision records why an authority and protocol were selected.
type RouteDecision struct {
	Protocol        Protocol `json:"protocol" yaml:"protocol"`
	Endpoint        string   `json:"endpoint" yaml:"endpoint"`
	Alternates      []string `json:"alternates,omitempty" yaml:"alternates,omitempty"`
	DiscoverySource string   `json:"discovery_source" yaml:"discovery_source"`
	Reason          string   `json:"reason" yaml:"reason"`
}

// Event is a dated registration event such as registration or expiration.
type Event struct {
	Action string `json:"action" yaml:"action"`
	Date   string `json:"date" yaml:"date"`
}

// Entity contains public contact or organization information. Fields that are
// redacted by a registry remain absent rather than being invented.
type Entity struct {
	Roles        []string `json:"roles,omitempty" yaml:"roles,omitempty"`
	Handle       string   `json:"handle,omitempty" yaml:"handle,omitempty"`
	Name         string   `json:"name,omitempty" yaml:"name,omitempty"`
	Organization string   `json:"organization,omitempty" yaml:"organization,omitempty"`
	Email        string   `json:"email,omitempty" yaml:"email,omitempty"`
	Phone        string   `json:"phone,omitempty" yaml:"phone,omitempty"`
}

// Notice is a registry-supplied legal or service notice.
type Notice struct {
	Title       string   `json:"title,omitempty" yaml:"title,omitempty"`
	Description []string `json:"description,omitempty" yaml:"description,omitempty"`
	Links       []string `json:"links,omitempty" yaml:"links,omitempty"`
}

// Object is Whodis's stable normalized registration-data model. Extras keeps
// protocol or registry-specific values that do not fit the common fields.
type Object struct {
	Kind         Kind                `json:"kind" yaml:"kind"`
	Handle       string              `json:"handle,omitempty" yaml:"handle,omitempty"`
	Name         string              `json:"name,omitempty" yaml:"name,omitempty"`
	UnicodeName  string              `json:"unicode_name,omitempty" yaml:"unicode_name,omitempty"`
	Status       []string            `json:"status,omitempty" yaml:"status,omitempty"`
	Events       []Event             `json:"events,omitempty" yaml:"events,omitempty"`
	Nameservers  []string            `json:"nameservers,omitempty" yaml:"nameservers,omitempty"`
	Entities     []Entity            `json:"entities,omitempty" yaml:"entities,omitempty"`
	Registrar    string              `json:"registrar,omitempty" yaml:"registrar,omitempty"`
	Registry     string              `json:"registry,omitempty" yaml:"registry,omitempty"`
	DNSSEC       string              `json:"dnssec,omitempty" yaml:"dnssec,omitempty"`
	StartAddress string              `json:"start_address,omitempty" yaml:"start_address,omitempty"`
	EndAddress   string              `json:"end_address,omitempty" yaml:"end_address,omitempty"`
	CIDR         []string            `json:"cidr,omitempty" yaml:"cidr,omitempty"`
	Country      string              `json:"country,omitempty" yaml:"country,omitempty"`
	NetworkType  string              `json:"network_type,omitempty" yaml:"network_type,omitempty"`
	ASN          string              `json:"asn,omitempty" yaml:"asn,omitempty"`
	ASNName      string              `json:"asn_name,omitempty" yaml:"asn_name,omitempty"`
	ASNType      string              `json:"asn_type,omitempty" yaml:"asn_type,omitempty"`
	Notices      []Notice            `json:"notices,omitempty" yaml:"notices,omitempty"`
	Extras       map[string][]string `json:"extras,omitempty" yaml:"extras,omitempty"`
}

// Source is one registry response used to construct a result.
type Source struct {
	Protocol  Protocol `json:"protocol" yaml:"protocol"`
	Endpoint  string   `json:"endpoint" yaml:"endpoint"`
	Authority string   `json:"authority,omitempty" yaml:"authority,omitempty"`
	Raw       string   `json:"-" yaml:"-"`
}

// DNSRecord is one public DNS resource record. Value is canonical DNS RDATA
// text, suitable for display and zone-file-oriented export.
type DNSRecord struct {
	Name  string `json:"name" yaml:"name"`
	Type  string `json:"type" yaml:"type"`
	TTL   uint32 `json:"ttl" yaml:"ttl"`
	Value string `json:"value" yaml:"value"`
}

// DNSResult records records discovered alongside registration data. Complete
// is true only when an untruncated authoritative AXFR completed successfully.
// Pattern scans intentionally remain incomplete: DNS has no reliable general
// mechanism to enumerate arbitrary owner names in a zone.
type DNSResult struct {
	Method      string      `json:"method" yaml:"method"`
	Complete    bool        `json:"complete" yaml:"complete"`
	Nameservers []string    `json:"nameservers,omitempty" yaml:"nameservers,omitempty"`
	Records     []DNSRecord `json:"records,omitempty" yaml:"records,omitempty"`
	Warnings    []string    `json:"warnings,omitempty" yaml:"warnings,omitempty"`
}

// LookupResult is the serializable response returned by Client.Lookup.
type LookupResult struct {
	SchemaVersion int            `json:"schema_version" yaml:"schema_version"`
	Query         Target         `json:"query" yaml:"query"`
	Route         RouteDecision  `json:"route" yaml:"route"`
	FallbackFrom  *RouteDecision `json:"fallback_from,omitempty" yaml:"fallback_from,omitempty"`
	RetrievedAt   time.Time      `json:"retrieved_at" yaml:"retrieved_at"`
	Object        Object         `json:"object" yaml:"object"`
	Sources       []Source       `json:"sources" yaml:"sources"`
	DNS           *DNSResult     `json:"dns,omitempty" yaml:"dns,omitempty"`
}

// LookupOptions controls one lookup. A zero-value options struct uses the
// knowledge-based automatic protocol router, unavailable-only fallback, and
// no live DNS enrichment.
type LookupOptions struct {
	Protocol         Protocol
	Fallback         FallbackMode
	Server           string
	Timeout          time.Duration
	RefreshBootstrap bool
	DNSMode          DNSMode
	DNSResolver      string
}

// BatchLookupOptions controls a concurrent group of independent lookups.
// Workers defaults to four when it is zero. Per-item lookup errors are
// returned in BatchResult rather than stopping the rest of the batch.
type BatchLookupOptions struct {
	LookupOptions LookupOptions
	Workers       int
	// OnProgress is called once for each completed item. Calls are serialized
	// in completion order and never overlap. The callback may be nil.
	OnProgress func(BatchProgress)
}

// BatchProgress describes one completed item in an active batch lookup.
// Index is the item's original input position, while Completed counts all
// items completed so far regardless of input order.
type BatchProgress struct {
	Index     int
	Completed int
	Total     int
	Item      BatchItem
}

// BatchError is the safe-to-serialize form of a lookup failure.
type BatchError struct {
	Kind    ErrorKind `json:"kind" yaml:"kind"`
	Message string    `json:"message" yaml:"message"`
}

// BatchItem retains the original input so an invalid target and a successful
// canonicalized target can be displayed together without losing attribution.
// Exactly one of Result and Error is set after LookupBatch completes.
type BatchItem struct {
	Input  string        `json:"input" yaml:"input"`
	Result *LookupResult `json:"result,omitempty" yaml:"result,omitempty"`
	Error  *BatchError   `json:"error,omitempty" yaml:"error,omitempty"`
}

// BatchResult is the serializable response returned by Client.LookupBatch.
// Embedded LookupResult values retain their own schema version.
type BatchResult struct {
	SchemaVersion int         `json:"schema_version" yaml:"schema_version"`
	Items         []BatchItem `json:"items" yaml:"items"`
}

// HasErrors reports whether any item in the completed batch failed.
func (r BatchResult) HasErrors() bool {
	for _, item := range r.Items {
		if item.Error != nil {
			return true
		}
	}
	return false
}

// ProjectionField is a stable, script-friendly view of a normalized result.
type ProjectionField string

const (
	FieldExpiration   ProjectionField = "expiration"
	FieldRegistration ProjectionField = "registration"
	FieldUpdated      ProjectionField = "updated"
	FieldRegistrar    ProjectionField = "registrar"
	FieldRegistry     ProjectionField = "registry"
	FieldStatus       ProjectionField = "status"
	FieldNameservers  ProjectionField = "nameservers"
	FieldDNSSEC       ProjectionField = "dnssec"
	FieldProtocol     ProjectionField = "protocol"
)

// BatchRenderOptions controls rendering of batch results. Fields selects the
// compact projection mode; an empty list renders complete lookup results.
type BatchRenderOptions struct {
	RenderOptions
	Fields []ProjectionField
}

// ClientOptions configures a reusable lookup client.
type ClientOptions struct {
	Timeout        time.Duration
	CacheDirectory string
	Adapters       []ProtocolAdapter
}

// ProtocolAdapter is the extension point for registration-data protocols.
// Implementations are supplied to NewClient rather than loaded through Go's
// platform-limited plugin mechanism.
type ProtocolAdapter interface {
	Protocol() Protocol
	Lookup(ctx context.Context, target Target, route RouteDecision) (Object, []Source, error)
}
