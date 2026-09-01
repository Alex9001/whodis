package audit

import (
	"testing"
	"time"

	"github.com/Alex9001/whodis/v2"
)

func BenchmarkEvaluateThousandReports(b *testing.B) {
	report := whodis.Report{
		SchemaVersion: whodis.ReportSchemaVersion,
		Operation:     whodis.OperationInspect,
		Subject:       whodis.Subject{Canonical: "example.test"},
		Registration: &whodis.RegistrationResult{Object: whodis.Object{Events: []whodis.Event{{
			Action: "expiration", Date: time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339),
		}}}},
		DNS: &whodis.DNSOperationResult{Inventory: &whodis.DNSResult{Records: []whodis.DNSRecord{{Name: "example.test", Type: "NS", Value: "ns1.example.test"}}}},
	}
	reports := make([]whodis.Report, 1000)
	for index := range reports {
		reports[index] = report
	}
	batch := whodis.BatchReport{SchemaVersion: whodis.ReportSchemaVersion, Reports: reports}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := Evaluate(batch, nil, EvaluateOptions{Scrutiny: ScrutinyStandard}); err != nil {
			b.Fatal(err)
		}
	}
}
