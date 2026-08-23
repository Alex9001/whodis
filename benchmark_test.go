package whodis

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func benchmarkReport() Report {
	return Report{
		SchemaVersion: ReportSchemaVersion,
		Operation:     OperationInvestigate,
		Subject:       Subject{Original: "example.com", Canonical: "example.com", Kind: SubjectRegistrableDomain},
		Registration:  &RegistrationResult{Object: Object{Name: "example.com", Status: []string{"client transfer prohibited"}}},
		DNS: &DNSOperationResult{Mode: "inventory", Inventory: &DNSResult{Records: []DNSRecord{
			{Name: "example.com", Type: "A", TTL: 300, Value: "93.184.216.34"},
			{Name: "example.com", Type: "MX", TTL: 300, Value: "10 mail.example.com"},
		}}},
		Investigation: &InvestigationReport{Domain: "example.com", Summary: "Web: WordPress · Hosting: Example", Components: []StackComponent{
			{Category: StackWebApplication, Name: "WordPress", Confidence: ConfidenceHigh, Summary: strings.Repeat("Evidence-backed technology summary. ", 8)},
		}},
	}
}

func BenchmarkNewEngine(b *testing.B) {
	warm := NewEngine(EngineOptions{})
	_ = warm.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		engine := NewEngine(EngineOptions{})
		_ = engine.Close()
	}
}

func BenchmarkHomepageAnalysisOneMiB(b *testing.B) {
	body := []byte("<html><head><meta name=\"generator\" content=\"WordPress 6.8\"></head><body>" + strings.Repeat("<img src=\"/wp-content/uploads/a.jpg\">", 26000) + "</body></html>")
	if len(body) > maximumInvestigationBody {
		body = body[:maximumInvestigationBody]
	}
	observation := webInvestigationObservation{URL: "https://example.com/", Status: 200, Body: body}
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		analyzeHomepage(observation)
	}
}

func BenchmarkReportRenderers(b *testing.B) {
	report := benchmarkReport()
	for _, format := range []Format{FormatPretty, FormatTree, FormatJSON, FormatYAML, FormatMarkdown} {
		b.Run(string(format), func(b *testing.B) {
			b.ReportAllocs()
			for index := 0; index < b.N; index++ {
				var output bytes.Buffer
				if err := RenderReport(&output, report, format, RenderOptions{Width: 120}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkBatchFakeProvider(b *testing.B) {
	engine := NewEngine(EngineOptions{Registration: engineRegistrationFixture{}, DNS: engineDNSFixture{}, Diagnose: engineDiagnoseFixture{}})
	requests := make([]Request, 1000)
	for index := range requests {
		requests[index] = Request{Operation: OperationRegistration, Target: "example.test"}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := engine.RunBatch(context.Background(), BatchRequest{Requests: requests, Workers: 4}); err != nil {
			b.Fatal(err)
		}
	}
}
