package guiapi

import "testing"

func TestParseTargetExtractsHTTPHost(t *testing.T) {
	parsed, err := parseTarget("https://Example.COM:8443/path?q=value#fragment")
	if err != nil {
		t.Fatalf("parseTarget() error = %v", err)
	}
	if parsed.Normalized != "example.com" || parsed.Subject.Canonical != "example.com" || parsed.Subject.Kind != "registrable_domain" {
		t.Fatalf("parseTarget() = %+v", parsed)
	}
}

func TestParseTargetRejectsUnsupportedURLScheme(t *testing.T) {
	if _, err := parseTarget("ftp://example.com/file"); err == nil {
		t.Fatal("parseTarget() accepted ftp URL")
	}
}

// Regression for the askjeeves.com bug: AS-prefixed domains must parse as
// domains at the GUI JSON-RPC layer, and real ASNs must stay ASNs.
func TestParseTargetASPrefixGrammar(t *testing.T) {
	parsed, err := parseTarget("askjeeves.com")
	if err != nil || parsed.Subject.Kind != "registrable_domain" {
		t.Fatalf("askjeeves.com should be a registrable_domain, got %+v err %v", parsed, err)
	}
	parsed, err = parseTarget("aspen.com")
	if err != nil || parsed.Subject.Kind != "registrable_domain" {
		t.Fatalf("aspen.com should be a registrable_domain, got %+v err %v", parsed, err)
	}
	parsed, err = parseTarget("AS")
	if err != nil || parsed.Subject.Kind != "registrable_domain" || parsed.Subject.Canonical != "as" {
		t.Fatalf("AS should be the .as DNS name, got %+v err %v", parsed, err)
	}
	parsed, err = parseTarget("AS15169")
	if err != nil || parsed.Subject.Kind != "asn" || parsed.Subject.Canonical != "15169" {
		t.Fatalf("AS15169 should stay an ASN, got %+v err %v", parsed, err)
	}
}
