package whodis

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderReportIncludesRemoteDNSAndUsesASCIIForPlain(t *testing.T) {
	report := Report{SchemaVersion: ReportSchemaVersion, Operation: OperationDNSQuery, Query: Target{Canonical: "example.test"}, DNS: &DNSOperationResult{
		Mode:   "query",
		Remote: []RemoteDNSMeasurement{{Location: "Seattle, US", Resolver: "1.1.1.1", Status: "finished", Answers: []DNSRecord{{Type: "A", Value: "192.0.2.1"}}}},
	}}
	var output bytes.Buffer
	if err := RenderReport(&output, report, FormatPlain, RenderOptions{Width: 72}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Globalping DNS") || !strings.Contains(output.String(), "Seattle, US") || strings.ContainsAny(output.String(), "┌┬┐│") {
		t.Fatalf("plain report = %q", output.String())
	}
}

func TestRenderReportJSONUsesSchemaV3(t *testing.T) {
	report := Report{SchemaVersion: ReportSchemaVersion, Operation: OperationDNSQuery, Query: Target{Canonical: "example.test"}}
	var output bytes.Buffer
	if err := RenderReport(&output, report, FormatJSON, RenderOptions{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"schema_version": 3`) || !strings.Contains(output.String(), `"operation": "dns.query"`) {
		t.Fatalf("JSON report = %s", output.String())
	}
}
