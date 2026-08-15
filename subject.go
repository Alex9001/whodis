package whodis

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	mdns "github.com/miekg/dns"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// SubjectKind identifies the grammar and routing rules that apply to a
// request target. It deliberately distinguishes DNS owner names from
// registrable domains.
type SubjectKind string

const (
	SubjectRegistrableDomain SubjectKind = "registrable_domain"
	SubjectDNSName           SubjectKind = "dns_name"
	SubjectIP                SubjectKind = "ip"
	SubjectPrefix            SubjectKind = "prefix"
	SubjectASN               SubjectKind = "asn"
)

// Subject preserves the user's input while exposing the exact canonical name
// and, when available, the registrable domain used for registration routing.
type Subject struct {
	Original           string      `json:"original" yaml:"original"`
	Canonical          string      `json:"canonical" yaml:"canonical"`
	Kind               SubjectKind `json:"kind" yaml:"kind"`
	RegistrationDomain string      `json:"registration_domain,omitempty" yaml:"registration_domain,omitempty"`
}

// ParseSubject applies operation-specific target rules. Registration and
// composite operations accept URLs and derive the registrable domain; DNS
// operations accept general owner names such as _dmarc, SRV labels, wildcards,
// and the root zone.
func ParseSubject(input string, operation Operation) (Subject, error) {
	original := strings.TrimSpace(input)
	if original == "" {
		return Subject{}, lookupError(ErrorInvalidInput, "a target is required", nil)
	}
	if operation == "" {
		operation = OperationRegistration
	}

	value, err := targetValue(original)
	if err != nil {
		return Subject{}, err
	}

	switch operation {
	case OperationDNSQuery, OperationDNSCompare:
		return parseDNSSubject(original, value, true)
	case OperationDNSTrace:
		return parseDNSSubject(original, value, false)
	case OperationDNSInventory, OperationDNSTransfer:
		subject, parseErr := parseDNSSubject(original, value, false)
		if parseErr != nil || subject.Kind != SubjectDNSName {
			return Subject{}, lookupError(ErrorInvalidInput, fmt.Sprintf("%s requires a domain or zone", operation), parseErr)
		}
		return subject, nil
	case OperationInspect, OperationDiagnose:
		subject, parseErr := parseRegistrationSubject(original, value)
		if parseErr != nil || subject.Kind != SubjectRegistrableDomain {
			return Subject{}, lookupError(ErrorInvalidInput, fmt.Sprintf("%s requires a domain or URL", operation), parseErr)
		}
		return subject, nil
	case OperationRegistration:
		return parseRegistrationSubject(original, value)
	default:
		return Subject{}, lookupError(ErrorInvalidInput, "unknown operation "+string(operation), nil)
	}
}

// ParseDNSName canonicalizes a general DNS owner name. Unlike ParseTarget it
// accepts service labels, wildcards, and the root zone.
func ParseDNSName(input string) (string, error) {
	value := strings.TrimSpace(input)
	if value == "." {
		return ".", nil
	}
	value = strings.TrimSuffix(value, ".")
	if value == "" || strings.ContainsAny(value, " /@:") {
		return "", lookupError(ErrorInvalidInput, "invalid DNS owner name", nil)
	}
	labels := strings.Split(value, ".")
	for index, label := range labels {
		if label == "" {
			return "", lookupError(ErrorInvalidInput, "invalid DNS owner name", nil)
		}
		if label == "*" || strings.HasPrefix(label, "_") {
			labels[index] = strings.ToLower(label)
			continue
		}
		ascii, err := idna.Lookup.ToASCII(label)
		if err != nil || ascii == "" {
			return "", lookupError(ErrorInvalidInput, "invalid internationalized DNS name", err)
		}
		labels[index] = strings.ToLower(ascii)
	}
	canonical := strings.Join(labels, ".")
	if _, ok := mdns.IsDomainName(mdns.Fqdn(canonical)); !ok || len(canonical) > 253 {
		return "", lookupError(ErrorInvalidInput, "invalid DNS owner name", nil)
	}
	return canonical, nil
}

func targetValue(original string) (string, error) {
	if !strings.Contains(original, "://") {
		return original, nil
	}
	parsed, err := url.Parse(original)
	if err != nil {
		return "", lookupError(ErrorInvalidInput, "invalid URL", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", lookupError(ErrorInvalidInput, "URL scheme must be http or https", nil)
	}
	host := parsed.Hostname()
	if host == "" {
		return "", lookupError(ErrorInvalidInput, "URL does not contain a hostname", nil)
	}
	return host, nil
}

func parseRegistrationSubject(original, value string) (Subject, error) {
	upper := strings.ToUpper(value)
	if strings.HasPrefix(upper, "AS") {
		n, err := strconv.ParseUint(upper[2:], 10, 32)
		if err != nil {
			return Subject{}, lookupError(ErrorInvalidInput, "invalid ASN", err)
		}
		return Subject{Original: original, Canonical: strconv.FormatUint(n, 10), Kind: SubjectASN}, nil
	}
	if n, err := strconv.ParseUint(value, 10, 32); err == nil {
		return Subject{Original: original, Canonical: strconv.FormatUint(n, 10), Kind: SubjectASN}, nil
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return Subject{Original: original, Canonical: address.String(), Kind: SubjectIP}, nil
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return Subject{Original: original, Canonical: prefix.Masked().String(), Kind: SubjectPrefix}, nil
	}
	canonical, err := ParseDNSName(value)
	if err != nil || canonical == "." || strings.Contains(canonical, "_") || strings.Contains(canonical, "*") {
		return Subject{}, lookupError(ErrorInvalidInput, "invalid registration target", err)
	}
	registrable := canonical
	if value, suffixErr := publicsuffix.EffectiveTLDPlusOne(canonical); suffixErr == nil {
		registrable = value
	}
	return Subject{Original: original, Canonical: canonical, Kind: SubjectRegistrableDomain, RegistrationDomain: registrable}, nil
}

func parseDNSSubject(original, value string, reverseIP bool) (Subject, error) {
	if address, err := netip.ParseAddr(value); err == nil {
		if !reverseIP {
			return Subject{}, lookupError(ErrorInvalidInput, "this DNS operation requires a DNS name", nil)
		}
		reverse, reverseErr := mdns.ReverseAddr(address.String())
		if reverseErr != nil {
			return Subject{}, lookupError(ErrorInvalidInput, "could not construct reverse DNS name", reverseErr)
		}
		return Subject{Original: original, Canonical: reverse, Kind: SubjectDNSName}, nil
	}
	canonical, err := ParseDNSName(value)
	if err != nil {
		return Subject{}, err
	}
	return Subject{Original: original, Canonical: canonical, Kind: SubjectDNSName}, nil
}

func subjectTarget(subject Subject) Target {
	kind := KindDomain
	switch subject.Kind {
	case SubjectIP, SubjectPrefix:
		kind = KindIP
	case SubjectASN:
		kind = KindASN
	}
	canonical := subject.Canonical
	if subject.RegistrationDomain != "" {
		canonical = subject.RegistrationDomain
	}
	return Target{Original: subject.Original, Canonical: canonical, Kind: kind}
}
