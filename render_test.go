package whodis

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func sampleResult() LookupResult {
	return LookupResult{
		SchemaVersion: 1,
		Query:         Target{Original: "example.com", Canonical: "example.com", Kind: KindDomain},
		Route:         RouteDecision{Protocol: ProtocolRDAP, Endpoint: "https://rdap.example/", DiscoverySource: "fixture"},
		RetrievedAt:   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Object:        Object{Kind: KindDomain, Name: "example.com", Status: []string{"active"}, Nameservers: []string{"ns1.example.com"}},
		Sources:       []Source{{Protocol: ProtocolRDAP, Raw: "{\"objectClassName\":\"domain\"}"}},
	}
}

func TestRenderFormats(t *testing.T) {
	for _, format := range []Format{FormatPretty, FormatPlain, FormatJSON, FormatYAML, FormatMarkdown, FormatRaw} {
		t.Run(string(format), func(t *testing.T) {
			var output bytes.Buffer
			if err := Render(&output, sampleResult(), format, RenderOptions{Color: "never", Width: 60}); err != nil {
				t.Fatal(err)
			}
			if output.Len() == 0 {
				t.Fatal("empty output")
			}
		})
	}
	var output bytes.Buffer
	_ = Render(&output, sampleResult(), FormatPretty, RenderOptions{Color: "never", Width: 60})
	if strings.Contains(output.String(), "\x1b[") {
		t.Fatal("color escape sequence leaked into colorless output")
	}
	if !strings.Contains(output.String(), "┌") || !strings.Contains(output.String(), "┬") || !strings.Contains(output.String(), "┼") {
		t.Fatal("pretty output is not a terminal grid")
	}
}
