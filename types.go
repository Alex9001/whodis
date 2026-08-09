// Package whodis provides protocol-aware registration-data lookups.
//
// Its public API intentionally has no terminal or GUI dependency, so the same
// Client can power the command-line tool and a future desktop application.
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
	ProtocolAuto  Protocol = "auto"
	ProtocolRDAP  Protocol = "rdap"
	ProtocolWHOIS Protocol = "whois"
)

// FallbackMode controls whether Whodis tries the other protocol after its
// knowledge-based primary route fails.
type FallbackMode string

const (
	FallbackUnavailable FallbackMode = "unavailable"
	FallbackNone        FallbackMode = "none"
	FallbackAnyError    FallbackMode = "any-error"
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

// LookupResult is the serializable response returned by Client.Lookup.
type LookupResult struct {
	SchemaVersion int            `json:"schema_version" yaml:"schema_version"`
	Query         Target         `json:"query" yaml:"query"`
	Route         RouteDecision  `json:"route" yaml:"route"`
	FallbackFrom  *RouteDecision `json:"fallback_from,omitempty" yaml:"fallback_from,omitempty"`
	RetrievedAt   time.Time      `json:"retrieved_at" yaml:"retrieved_at"`
	Object        Object         `json:"object" yaml:"object"`
	Sources       []Source       `json:"sources" yaml:"sources"`
}

// LookupOptions controls one lookup. A zero-value options struct uses the
// knowledge-based automatic protocol router and unavailable-only fallback.
type LookupOptions struct {
	Protocol         Protocol
	Fallback         FallbackMode
	Server           string
	Timeout          time.Duration
	RefreshBootstrap bool
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
