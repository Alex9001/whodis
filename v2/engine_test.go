package whodis

import (
	"context"
	"errors"
	"testing"
	"time"
)

type engineRegistrationFixture struct {
	result RegistrationResult
	err    error
}

type blockingRegistrationFixture struct{}

func (blockingRegistrationFixture) Lookup(ctx context.Context, _ Subject, _ LookupOptions) (RegistrationResult, error) {
	<-ctx.Done()
	return RegistrationResult{}, ctx.Err()
}

type gatedRegistrationFixture struct {
	started chan struct{}
	release <-chan struct{}
}

func (fixture gatedRegistrationFixture) Lookup(ctx context.Context, _ Subject, _ LookupOptions) (RegistrationResult, error) {
	select {
	case fixture.started <- struct{}{}:
	case <-ctx.Done():
		return RegistrationResult{}, ctx.Err()
	}
	select {
	case <-fixture.release:
		return RegistrationResult{}, nil
	case <-ctx.Done():
		return RegistrationResult{}, ctx.Err()
	}
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
		if report.SchemaVersion != ReportSchemaVersion || report.Subject.Canonical == "" || len(report.Errors) != 1 {
			t.Fatalf("report %d = %#v", index, report)
		}
	}
}

func TestNilEngineBatchReturnsError(t *testing.T) {
	var engine *Engine
	if _, err := engine.RunBatch(context.Background(), BatchRequest{Requests: []Request{{Target: "example.test"}}}); err == nil {
		t.Fatal("nil Engine.RunBatch did not return an error")
	}
}

func TestRegistrationCoalescingKeepsDifferentRequestTimeoutsIndependent(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	engine := NewEngine(EngineOptions{
		Registration: gatedRegistrationFixture{started: started, release: release},
		DNS:          engineDNSFixture{},
		Diagnose:     engineDiagnoseFixture{},
	})
	defer engine.Close()

	done := make(chan error, 1)
	go func() {
		_, err := engine.RunBatch(context.Background(), BatchRequest{Workers: 2, Requests: []Request{
			{Operation: OperationRegistration, Target: "example.test", Timeout: time.Second},
			{Operation: OperationRegistration, Target: "example.test", Timeout: 2 * time.Second},
		}})
		done <- err
	}()
	for count := 0; count < 2; count++ {
		select {
		case <-started:
		case <-time.After(500 * time.Millisecond):
			close(release)
			t.Fatal("requests with different deadlines were incorrectly coalesced")
		}
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRegistrationCancellationDoesNotPoisonIndependentCaller(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	engine := NewEngine(EngineOptions{
		Registration: gatedRegistrationFixture{started: started, release: release},
		DNS:          engineDNSFixture{},
		Diagnose:     engineDiagnoseFixture{},
	})
	defer engine.Close()

	firstContext, cancelFirst := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() {
		_, err := engine.Run(firstContext, Request{Operation: OperationRegistration, Target: "example.test", Timeout: time.Second})
		firstDone <- err
	}()
	select {
	case <-started:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("first registration lookup did not start")
	}

	secondDone := make(chan error, 1)
	go func() {
		_, err := engine.Run(context.Background(), Request{Operation: OperationRegistration, Target: "example.test", Timeout: time.Second})
		secondDone <- err
	}()
	select {
	case <-started:
	case <-time.After(500 * time.Millisecond):
		cancelFirst()
		close(release)
		t.Fatal("second registration lookup was coupled to the first")
	}

	cancelFirst()
	if err := <-firstDone; err == nil {
		t.Fatal("canceled registration lookup unexpectedly succeeded")
	}
	close(release)
	if err := <-secondDone; err != nil {
		t.Fatalf("independent registration lookup failed: %v", err)
	}
}

func (fixture engineRegistrationFixture) Lookup(context.Context, Subject, LookupOptions) (RegistrationResult, error) {
	return fixture.result, fixture.err
}

type engineDNSFixture struct {
	result *DNSOperationResult
	err    error
	target chan<- string
}

func (fixture engineDNSFixture) Query(context.Context, string, DNSOptions) (*DNSOperationResult, error) {
	return fixture.result, fixture.err
}
func (fixture engineDNSFixture) Inventory(_ context.Context, target string, _ DNSOptions) (*DNSOperationResult, error) {
	if fixture.target != nil {
		fixture.target <- target
	}
	return fixture.result, fixture.err
}
func (fixture engineDNSFixture) Compare(context.Context, string, DNSOptions) (*DNSOperationResult, error) {
	return fixture.result, fixture.err
}
func (fixture engineDNSFixture) Trace(context.Context, string, DNSOptions) (*DNSOperationResult, error) {
	return fixture.result, fixture.err
}
func (fixture engineDNSFixture) Transfer(_ context.Context, target string, _ DNSOptions) (*DNSOperationResult, error) {
	if fixture.target != nil {
		fixture.target <- target
	}
	return fixture.result, fixture.err
}

type engineDiagnoseFixture struct {
	result *DiagnosisReport
	err    error
}

func (fixture engineDiagnoseFixture) Diagnose(context.Context, string, DiagnoseOptions) (*DiagnosisReport, error) {
	return fixture.result, fixture.err
}

type engineInvestigationFixture struct {
	result    *InvestigationReport
	err       error
	diagnosis chan<- *DiagnosisReport
}

func (fixture engineInvestigationFixture) Investigate(_ context.Context, _ Subject, diagnosis *DiagnosisReport, _ InvestigationOptions) (*InvestigationReport, error) {
	if fixture.diagnosis != nil {
		fixture.diagnosis <- diagnosis
	}
	return fixture.result, fixture.err
}

func TestEngineInspectPreservesDNSWhenRegistrationFails(t *testing.T) {
	dnsResult := &DNSOperationResult{Mode: "inventory", Inventory: &DNSResult{Records: []DNSRecord{{Name: "example.test", Type: "A", Value: "192.0.2.1"}}}}
	engine := NewEngine(EngineOptions{
		Registration: engineRegistrationFixture{err: lookupError(ErrorUnavailable, "registry offline", nil)},
		DNS:          engineDNSFixture{result: dnsResult},
		Diagnose:     engineDiagnoseFixture{},
	})
	report, err := engine.Run(context.Background(), Request{Operation: OperationInspect, Target: "example.test"})
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
	registration := RegistrationResult{Object: Object{Name: "example.test"}}
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
	if report.Registration == nil || report.Diagnosis == nil || len(report.Diagnosis.Findings) != 0 || len(report.Findings) != 1 {
		t.Fatalf("unexpected diagnosis report: %#v", report)
	}
	if len(report.Errors) != 1 || report.Errors[0].Operation != OperationDiagnose {
		t.Fatalf("diagnosis error was not retained: %#v", report.Errors)
	}
}

func TestEngineInvestigateComposesDiagnosisAndProviderErrors(t *testing.T) {
	diagnosis := &DiagnosisReport{Domain: "example.test", Findings: []Finding{{ID: "dns.inventory", Severity: SeverityPass}}}
	observedDiagnosis := make(chan *DiagnosisReport, 1)
	investigation := &InvestigationReport{
		Domain: "example.test", Summary: "Web: WordPress",
		Findings:       []Finding{{ID: "web.homepage.response", Severity: SeverityPass}},
		ProviderErrors: []OperationError{{Operation: OperationInvestigate, Provider: "otx", Kind: ErrorRateLimited, Message: "rate limited"}},
	}
	engine := NewEngine(EngineOptions{
		Registration:  engineRegistrationFixture{result: RegistrationResult{Object: Object{Name: "example.test"}}},
		DNS:           engineDNSFixture{},
		Diagnose:      engineDiagnoseFixture{result: diagnosis},
		Investigation: engineInvestigationFixture{result: investigation, diagnosis: observedDiagnosis},
	})
	report, err := engine.Run(context.Background(), Request{Operation: OperationInvestigate, Target: "example.test", Investigation: InvestigationOptions{RelatedLimit: 25}})
	if err != nil {
		t.Fatal(err)
	}
	if <-observedDiagnosis != diagnosis || report.Registration == nil || report.Diagnosis == nil || report.Investigation == nil || report.Investigation.Summary != "Web: WordPress" || len(report.Findings) != 2 {
		t.Fatalf("unexpected investigation report: %#v", report)
	}
	if len(report.Investigation.Findings) != 0 || len(report.Investigation.ProviderErrors) != 0 || len(report.Errors) != 1 || report.Errors[0].Provider != "otx" {
		t.Fatalf("provider errors were not lifted to the report: %#v", report)
	}
}

func TestEngineTurnsIPAddressIntoReverseDNSQuery(t *testing.T) {
	engine := NewEngine(EngineOptions{Registration: engineRegistrationFixture{}, DNS: engineDNSFixture{}, Diagnose: engineDiagnoseFixture{}})
	report, err := engine.Run(context.Background(), Request{Operation: OperationDNSQuery, Target: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Subject.Canonical != "1.2.0.192.in-addr.arpa." {
		t.Fatalf("reverse subject = %q", report.Subject.Canonical)
	}
}

func TestEnginePreservesExactDelegatedDNSZone(t *testing.T) {
	targets := make(chan string, 2)
	engine := NewEngine(EngineOptions{Registration: engineRegistrationFixture{}, DNS: engineDNSFixture{result: &DNSOperationResult{Mode: "inventory"}, target: targets}, Diagnose: engineDiagnoseFixture{}})
	for _, operation := range []Operation{OperationDNSInventory, OperationDNSTransfer} {
		if _, err := engine.Run(context.Background(), Request{Operation: operation, Target: "delegated.sub.example.com"}); err != nil {
			t.Fatal(err)
		}
		if target := <-targets; target != "delegated.sub.example.com" {
			t.Fatalf("%s target = %q", operation, target)
		}
	}
}

func TestEngineBatchAttributesInvalidDefaultRegistrationInput(t *testing.T) {
	engine := NewEngine(EngineOptions{Registration: engineRegistrationFixture{}, DNS: engineDNSFixture{}, Diagnose: engineDiagnoseFixture{}})
	batch, err := engine.RunBatch(context.Background(), BatchRequest{Requests: []Request{{Target: "not a target /"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Reports) != 1 || batch.Reports[0].Operation != OperationRegistration || batch.Reports[0].Subject.Original != "not a target /" || len(batch.Reports[0].Errors) != 1 || batch.Reports[0].Errors[0].Provider != "registration" {
		t.Fatalf("batch report = %#v", batch)
	}
}

func TestEngineStreamPreservesInputIndexes(t *testing.T) {
	engine := NewEngine(EngineOptions{Registration: engineRegistrationFixture{}, DNS: engineDNSFixture{}, Diagnose: engineDiagnoseFixture{}})
	requests := make(chan Request, 3)
	for _, target := range []string{"one.example", "two.example", "three.example"} {
		requests <- Request{Operation: OperationRegistration, Target: target}
	}
	close(requests)
	seen := map[int]string{}
	err := engine.RunStream(context.Background(), requests, StreamOptions{Workers: 2}, func(item StreamItem) error {
		seen[item.Index] = item.Report.Subject.Canonical
		return nil
	})
	if err != nil || seen[0] != "one.example" || seen[1] != "two.example" || seen[2] != "three.example" {
		t.Fatalf("stream = %#v, %v", seen, err)
	}
}

func TestEngineStreamStopsWhenEmitterFails(t *testing.T) {
	engine := NewEngine(EngineOptions{Registration: engineRegistrationFixture{}, DNS: engineDNSFixture{}, Diagnose: engineDiagnoseFixture{}})
	requests := make(chan Request, 8)
	for index := 0; index < cap(requests); index++ {
		requests <- Request{Operation: OperationRegistration, Target: "example.test"}
	}
	close(requests)
	wanted := errors.New("writer failed")
	if err := engine.RunStream(context.Background(), requests, StreamOptions{Workers: 4}, func(StreamItem) error { return wanted }); !errors.Is(err, wanted) {
		t.Fatalf("RunStream error = %v", err)
	}
}

func TestEngineStreamReturnsParentCancellation(t *testing.T) {
	engine := NewEngine(EngineOptions{Registration: blockingRegistrationFixture{}, DNS: engineDNSFixture{}, Diagnose: engineDiagnoseFixture{}})
	requests := make(chan Request, 1)
	requests <- Request{Operation: OperationRegistration, Target: "example.test", Timeout: time.Second}
	close(requests)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := engine.RunStream(ctx, requests, StreamOptions{Workers: 1}, func(StreamItem) error { return nil }); err == nil {
		t.Fatal("canceled stream returned nil")
	}
}
