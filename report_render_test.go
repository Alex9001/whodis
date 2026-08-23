package whodis

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"
)

func TestRenderReportIncludesRemoteDNSAndUsesASCIIForPlain(t *testing.T) {
	report := Report{SchemaVersion: ReportSchemaVersion, Operation: OperationDNSQuery, Subject: Subject{Canonical: "example.test"}, DNS: &DNSOperationResult{
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

func TestRenderReportJSONUsesSchemaV5(t *testing.T) {
	report := Report{SchemaVersion: ReportSchemaVersion, Operation: OperationRegistration, Subject: Subject{Canonical: "example.test"}, Registration: &RegistrationResult{Object: Object{Name: "example.test"}}}
	var output bytes.Buffer
	if err := RenderReport(&output, report, FormatJSON, RenderOptions{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"schema_version": 5`) || !strings.Contains(output.String(), `"operation": "registration"`) || !strings.Contains(output.String(), `"subject"`) {
		t.Fatalf("JSON report = %s", output.String())
	}
}

func TestRenderBatchReportNDJSONAndCSV(t *testing.T) {
	reports := []Report{
		{SchemaVersion: ReportSchemaVersion, Operation: OperationRegistration, Subject: Subject{Canonical: "one.test", Kind: SubjectRegistrableDomain}, Registration: &RegistrationResult{Route: RouteDecision{Protocol: ProtocolRDAP}, Object: Object{Registrar: "One Registrar"}}},
		{SchemaVersion: ReportSchemaVersion, Operation: OperationDNSQuery, Subject: Subject{Canonical: "two.test", Kind: SubjectDNSName}, DNS: &DNSOperationResult{Messages: []DNSMessage{{Answer: []DNSRecord{{Name: "two.test", Type: "A", Value: "192.0.2.2"}}}}}},
	}
	batch := BatchReport{SchemaVersion: ReportSchemaVersion, Reports: reports}
	var ndjson bytes.Buffer
	if err := RenderBatchReport(&ndjson, batch, FormatNDJSON, RenderOptions{}); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(ndjson.String()), "\n"); len(lines) != 2 || !strings.Contains(lines[0], `"one.test"`) || !strings.Contains(lines[1], `"two.test"`) {
		t.Fatalf("NDJSON = %q", ndjson.String())
	}
	var csvOutput bytes.Buffer
	if err := RenderBatchReport(&csvOutput, batch, FormatCSV, RenderOptions{}); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&csvOutput).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[0][0] != "TARGET" || rows[1][0] != "one.test" || rows[2][14] != "1" {
		t.Fatalf("CSV rows = %#v", rows)
	}
}

func TestReportCSVCountsUniqueRecordsAndFindings(t *testing.T) {
	record := DNSRecord{Name: "example.test", Type: "A", Value: "192.0.2.1"}
	finding := Finding{ID: "dns.inventory", Severity: SeverityPass, Title: "DNS inventory", Summary: "records found"}
	report := Report{
		SchemaVersion: ReportSchemaVersion,
		Operation:     OperationDiagnose,
		Subject:       Subject{Canonical: "example.test"},
		Findings:      []Finding{finding},
		Diagnosis: &DiagnosisReport{
			Findings: []Finding{finding},
			DNS:      &DNSOperationResult{Messages: []DNSMessage{{Answer: []DNSRecord{record, record}}}},
			Delegation: &DNSOperationResult{
				Transfer: &DNSResult{Records: []DNSRecord{record}},
				Remote:   []RemoteDNSMeasurement{{Answers: []DNSRecord{record}}},
			},
		},
	}
	var output bytes.Buffer
	if err := RenderReport(&output, report, FormatCSV, RenderOptions{}); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&output).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if rows[1][14] != "1" || strings.Count(rows[1][15], "DNS inventory") != 1 {
		t.Fatalf("CSV row = %#v", rows[1])
	}
}

func TestReportTableWrapsInsteadOfTruncating(t *testing.T) {
	report := Report{SchemaVersion: ReportSchemaVersion, Operation: OperationDNSQuery, Subject: Subject{Canonical: "example.test"}, Errors: []OperationError{{Operation: OperationDNSQuery, Kind: ErrorUnavailable, Message: "a deliberately long provider message whose final marker is PRESERVED"}}}
	var output bytes.Buffer
	if err := RenderReport(&output, report, FormatPretty, RenderOptions{Width: 42}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "…") || !strings.Contains(output.String(), "PRESERVED") {
		t.Fatalf("wrapped output = %q", output.String())
	}
}

func TestRenderReportDeduplicatesInventoryTTLAging(t *testing.T) {
	report := Report{SchemaVersion: ReportSchemaVersion, Operation: OperationDNSInventory, Subject: Subject{Canonical: "example.test"}, DNS: &DNSOperationResult{
		Mode: "inventory",
		Inventory: &DNSResult{Records: []DNSRecord{
			{Name: "webmail.example.test", Type: "CNAME", TTL: 154, Value: "same-target.example.test"},
			{Name: "webmail.example.test", Type: "CNAME", TTL: 155, Value: "same-target.example.test"},
			{Name: "webmail.example.test", Type: "CNAME", TTL: 155, Value: "distinct-target.example.test"},
		}},
	}}
	var output bytes.Buffer
	if err := RenderReport(&output, report, FormatPretty, RenderOptions{Width: 120}); err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(output.String(), "same-target.example.test"); count != 1 {
		t.Fatalf("aged inventory record occurs %d times, want once:\n%s", count, output.String())
	}
	if count := strings.Count(output.String(), "distinct-target.example.test"); count != 1 {
		t.Fatalf("distinct inventory record occurs %d times, want once:\n%s", count, output.String())
	}
}

func TestRenderReportMarkdownIncludesEveryWorkstationSection(t *testing.T) {
	report := Report{
		SchemaVersion: ReportSchemaVersion,
		Operation:     OperationDiagnose,
		Subject:       Subject{Canonical: "example.test"},
		DNS: &DNSOperationResult{
			Mode:        "compare",
			Differences: []DNSDifference{{Resolver: "second", Missing: []string{"A 192.0.2.1"}}},
			Trace:       []DNSTraceHop{{Zone: "test", Server: "root.test", Rcode: "NOERROR", DNSSEC: "secure"}},
			Transfer:    &DNSResult{Method: "AXFR", Complete: true, Records: []DNSRecord{{Name: "example.test", Type: "MX", Value: "10 mail.example.test"}}},
			Warnings:    []string{"DNS warning marker"},
		},
		Diagnosis: &DiagnosisReport{
			Domain:       "example.test",
			Reachability: []AddressProbe{{Address: "192.0.2.1", Network: "tcp", Method: "connect", Reachable: true}},
			HTTP:         []HTTPProbe{{URL: "https://example.test", Status: 200, Healthy: true}},
			TLS:          []TLSProbe{{ServerName: "example.test", Address: "192.0.2.1:443", Version: "TLS 1.3", NotAfter: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Verified: true}},
			Mail:         []MailProbe{{Host: "mail.example.test", Reachable: true, STARTTLS: true}},
			Services:     []ServiceProbe{{Source: "SRV", Name: "_sip._tcp.example.test", Target: "sip.example.test", Port: 5061, Reachable: true}},
			Path:         []PathHop{{Hop: 1, Address: "192.0.2.254"}},
			Policies:     map[string][]string{"DMARC": {"p=reject"}},
			Warnings:     []string{"diagnosis warning marker"},
		},
		Errors: []OperationError{{Operation: OperationDiagnose, Provider: "diagnose", Kind: ErrorUnavailable, Message: "partial error marker"}},
	}
	var output bytes.Buffer
	if err := RenderReport(&output, report, FormatMarkdown, RenderOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"Resolver differences", "Delegation trace", "transfer", "DNS warning marker", "Reachability", "HTTP", "TLS", "Mail", "Advertised services", "Network path", "Mail policies", "diagnosis warning marker", "Partial errors", "partial error marker"} {
		if !strings.Contains(output.String(), marker) {
			t.Fatalf("Markdown omitted %q:\n%s", marker, output.String())
		}
	}
}

func TestRenderInvestigationAcrossHumanAndTabularFormats(t *testing.T) {
	report := Report{
		SchemaVersion: ReportSchemaVersion,
		Operation:     OperationInvestigate,
		Subject:       Subject{Canonical: "example.test", Kind: SubjectRegistrableDomain},
		Investigation: &InvestigationReport{
			Domain: "example.test", Summary: "Web: WordPress · Network: Amazon Web Services · DNS: Cloudflare DNS · Mail: Microsoft 365",
			Components: []StackComponent{
				{Category: StackWebApplication, Name: "WordPress", Role: "CMS", Confidence: ConfidenceHigh, Evidence: []InvestigationEvidence{{Source: "http", Field: "markup", Value: "WordPress assets"}}},
				{Category: StackNetwork, Name: "Amazon Web Services", Role: "Network owner", Confidence: ConfidenceHigh},
				{Category: StackDNS, Name: "Cloudflare DNS", Role: "Authoritative DNS", Confidence: ConfidenceHigh},
				{Category: StackMail, Name: "Microsoft 365", Role: "Inbound mail", Confidence: ConfidenceHigh},
			},
			Networks:     []NetworkObservation{{Address: "192.0.2.1", Provider: "Amazon Web Services", Operator: "Amazon Technologies Inc."}},
			Related:      []RelatedObservation{{Provider: "otx", Hostname: "neighbor.test", Address: "192.0.2.1", Current: RelatedStale}},
			RelatedTotal: 7,
			Links:        []InvestigationLink{{Label: "Open in AlienVault OTX", Type: "domain", Value: "example.test", URL: "https://otx.alienvault.com/indicator/domain/example.test"}},
		},
	}
	for _, format := range []Format{FormatPretty, FormatPlain, FormatMarkdown} {
		var output bytes.Buffer
		if err := RenderReport(&output, report, format, RenderOptions{Width: 100}); err != nil {
			t.Fatal(err)
		}
		for _, marker := range []string{"Stack summary", "WordPress", "Amazon Web Services", "Related", "neighbor.test", "AlienVault OTX"} {
			if !strings.Contains(output.String(), marker) {
				t.Fatalf("%s output omitted %q:\n%s", format, marker, output.String())
			}
		}
	}
	var output bytes.Buffer
	if err := RenderReport(&output, report, FormatCSV, RenderOptions{}); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&output).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	columns := make(map[string]int)
	for index, name := range rows[0] {
		columns[name] = index
	}
	if rows[1][columns["STACK_SUMMARY"]] == "" || !strings.Contains(rows[1][columns["TECHNOLOGIES"]], "WordPress") || rows[1][columns["NETWORK_PROVIDER"]] != "Amazon Web Services" || rows[1][columns["RELATED_COUNT"]] != "7" {
		t.Fatalf("investigation CSV row = %#v", rows[1])
	}
}
