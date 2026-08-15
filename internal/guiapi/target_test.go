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
