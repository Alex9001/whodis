package guiapi

import (
	"encoding/csv"
	"strings"
	"testing"

	"github.com/Alex9001/whodis"
)

func TestRenderExportCSVUsesNormalizedFieldsAndEscapesValues(t *testing.T) {
	batch := whodis.BatchResult{SchemaVersion: 1, Items: []whodis.BatchItem{{
		Input: "example.com",
		Result: &whodis.LookupResult{
			Route: whodis.RouteDecision{Protocol: whodis.ProtocolRDAP},
			Object: whodis.Object{
				Registrar: "Example, Inc.",
				Events:    []whodis.Event{{Action: "expiration", Date: "2030-01-02T03:04:05Z"}},
			},
		},
	}}}
	rendered, err := renderExport(batch, exportParams{Format: "csv"})
	if err != nil {
		t.Fatalf("renderExport() error = %v", err)
	}
	rows, err := csv.NewReader(strings.NewReader(rendered.Content)).ReadAll()
	if err != nil {
		t.Fatalf("CSV parse error = %v", err)
	}
	if len(rows) != 2 || len(rows[1]) != 5 {
		t.Fatalf("CSV rows = %#v", rows)
	}
	if rows[1][1] != "2030-01-02T03:04:05Z" || rows[1][2] != "Example, Inc." || rows[1][3] != "rdap" {
		t.Fatalf("CSV data row = %#v", rows[1])
	}
	if rendered.MIME != "text/csv" || rendered.Extension != "csv" {
		t.Fatalf("export metadata = %+v", rendered)
	}
}

func TestRenderExportRejectsUnknownField(t *testing.T) {
	_, err := renderExport(whodis.BatchResult{}, exportParams{Format: "csv", Fields: []string{"made-up"}})
	if err == nil {
		t.Fatal("renderExport() accepted an unknown field")
	}
}

func TestRenderReportExportCSVFlattensSchemaV3(t *testing.T) {
	batch := whodis.BatchReport{SchemaVersion: whodis.ReportSchemaVersion, Reports: []whodis.Report{{
		Operation: whodis.OperationDiagnose,
		Query:     whodis.Target{Canonical: "example.com"},
		Registration: &whodis.LookupResult{Object: whodis.Object{
			Registrar: "Example, Inc.", Events: []whodis.Event{{Action: "expiration", Date: "2030-01-02T03:04:05Z"}},
		}},
		Diagnosis: &whodis.DiagnosisReport{Findings: []whodis.Finding{{ID: "dns.inventory"}}, DNS: &whodis.DNSOperationResult{
			Inventory: &whodis.DNSResult{Records: []whodis.DNSRecord{{Name: "example.com", Type: "A", Value: "192.0.2.1"}}},
		}},
	}}}
	rendered, err := renderReportExport(batch, exportParams{Format: "csv"})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(rendered.Content)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[1][0] != "example.com" || rows[1][2] != "2030-01-02T03:04:05Z" || rows[1][3] != "Example, Inc." || rows[1][4] != "1" || rows[1][5] != "1" {
		t.Fatalf("CSV rows = %#v", rows)
	}
}
