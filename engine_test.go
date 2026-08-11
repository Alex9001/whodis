package whodis

import (
	"context"
	"errors"
	"testing"
	"time"
)

type engineRegistrationFixture struct {
	result LookupResult
	err    error
}

type blockingRegistrationFixture struct{}

func (blockingRegistrationFixture) Lookup(ctx context.Context, _ string, _ LookupOptions) (LookupResult, error) {
	<-ctx.Done()
	return LookupResult{}, ctx.Err()
}

func TestEngineCanceledBatchPreservesEveryInputSlot(t *testing.T) {
	engine := NewEngine(EngineOptions{
		Registration: blockingRegistrationFixture{},
		DNS:          engineDNSFixture{},
		Diagnose:     engineDiagnoseFixture{},
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	batch, err := engine.RunBatch(ctx, BatchRequest{Workers: 1, Requests: []Request{
		{Operation: OperationRegistration, Target: "one.example"},
		{Operation: OperationRegistration, Target: "two.example"},
		{Operation: OperationRegistration, Target: "three.example"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Reports) != 3 {
		t.Fatalf("reports = %d, want 3", len(batch.Reports))
	}
	for index, report := range batch.Reports {
		if report.SchemaVersion != ReportSchemaVersion || report.Query.Canonical == "" || len(report.Errors) != 1 {
			t.Fatalf("report %d = %#v", index, report)
		}
	}
}

func (fixture engineRegistrationFixture) Lookup(context.Context, string, LookupOptions) (LookupResult, error) {
	return fixture.result, fixture.err
}

type engineDNSFixture struct {
	result *DNSOperationResult
	err    error
}

func (fixture engineDNSFixture) Query(context.Context, string, DNSOptions) (*DNSOperationResult, error) {
	return fixture.result, fixture.err
}
func (fixture engineDNSFixture) Inventory(context.Context, string, DNSOptions) (*DNSOperationResult, error) {
	return fixture.result, fixture.err
}
func (fixture engineDNSFixture) Compare(context.Context, string, DNSOptions) (*DNSOperationResult, error) {
	return fixture.result, fixture.err
}
func (fixture engineDNSFixture) Trace(context.Context, string, DNSOptions) (*DNSOperationResult, error) {
	return fixture.result, fixture.err
}
func (fixture engineDNSFixture) Transfer(context.Context, string, DNSOptions) (*DNSOperationResult, error) {
	return fixture.result, fixture.err
}

type engineDiagnoseFixture struct {
	result *DiagnosisReport
	err    error
}

func (fixture engineDiagnoseFixture) Diagnose(context.Context, string, DiagnoseOptions) (*DiagnosisReport, error) {
	return fixture.result, fixture.err
}

func TestEngineInventoryPreservesDNSWhenRegistrationFails(t *testing.T) {
	dnsResult := &DNSOperationResult{Mode: "inventory", Inventory: &DNSResult{Records: []DNSRecord{{Name: "example.test", Type: "A", Value: "192.0.2.1"}}}}
	engine := NewEngine(EngineOptions{
		Registration: engineRegistrationFixture{err: lookupError(ErrorUnavailable, "registry offline", nil)},
		DNS:          engineDNSFixture{result: dnsResult},
		Diagnose:     engineDiagnoseFixture{},
	})
	report, err := engine.Run(context.Background(), Request{Operation: OperationDNSInventory, Target: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != ReportSchemaVersion || report.DNS != dnsResult || report.Registration != nil {
		t.Fatalf("unexpected partial report: %#v", report)
	}
	if len(report.Errors) != 1 || report.Errors[0].Operation != OperationRegistration {
		t.Fatalf("registration error was not scoped: %#v", report.Errors)
	}
}

func TestEngineDiagnosePreservesRegistrationWhenChecksFail(t *testing.T) {
	registration := LookupResult{SchemaVersion: 2, Object: Object{Name: "example.test"}}
	diagnosis := &DiagnosisReport{Domain: "example.test", Findings: []Finding{{ID: "dns.inventory", Severity: SeverityError}}}
	engine := NewEngine(EngineOptions{
		Registration: engineRegistrationFixture{result: registration},
		DNS:          engineDNSFixture{},
		Diagnose:     engineDiagnoseFixture{result: diagnosis, err: errors.New("probe budget expired")},
	})
	report, err := engine.Run(context.Background(), Request{Operation: OperationDiagnose, Target: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Registration == nil || report.Diagnosis != diagnosis || len(report.Findings) != 1 {
		t.Fatalf("unexpected diagnosis report: %#v", report)
	}
	if len(report.Errors) != 1 || report.Errors[0].Operation != OperationDiagnose {
		t.Fatalf("diagnosis error was not retained: %#v", report.Errors)
	}
}

func TestEngineRejectsDNSForNonDomain(t *testing.T) {
	engine := NewEngine(EngineOptions{Registration: engineRegistrationFixture{}, DNS: engineDNSFixture{}, Diagnose: engineDiagnoseFixture{}})
	_, err := engine.Run(context.Background(), Request{Operation: OperationDNSQuery, Target: "192.0.2.1"})
	var typed *LookupError
	if !errors.As(err, &typed) || typed.Kind != ErrorInvalidInput {
		t.Fatalf("error = %v, want invalid input", err)
	}
}

func TestEngineBatchAttributesInvalidDefaultRegistrationInput(t *testing.T) {
	engine := NewEngine(EngineOptions{Registration: engineRegistrationFixture{}, DNS: engineDNSFixture{}, Diagnose: engineDiagnoseFixture{}})
	batch, err := engine.RunBatch(context.Background(), BatchRequest{Requests: []Request{{Target: "not a target /"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Reports) != 1 || batch.Reports[0].Operation != OperationRegistration || batch.Reports[0].Query.Original != "not a target /" || len(batch.Reports[0].Errors) != 1 || batch.Reports[0].Errors[0].Provider != "registration" {
		t.Fatalf("batch report = %#v", batch)
	}
}
