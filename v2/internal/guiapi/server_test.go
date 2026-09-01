package guiapi

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Alex9001/whodis/v2"
)

type fakeEngine struct{}

func (fakeEngine) RunBatch(_ context.Context, request whodis.BatchRequest) (whodis.BatchReport, error) {
	reports := make([]whodis.Report, len(request.Requests))
	for index, item := range request.Requests {
		reports[index] = whodis.Report{
			SchemaVersion: whodis.ReportSchemaVersion,
			Operation:     item.Operation,
			Subject:       whodis.Subject{Original: item.Target, Canonical: item.Target, Kind: whodis.SubjectDNSName},
			DNS:           &whodis.DNSOperationResult{Mode: "query", Messages: []whodis.DNSMessage{{Name: item.Target, Type: "A", Rcode: "NOERROR"}}},
		}
		if request.OnProgress != nil {
			request.OnProgress(whodis.ProgressEvent{Operation: item.Operation, Target: item.Target, Stage: "completed", Completed: index + 1, Total: len(request.Requests)})
		}
	}
	return whodis.BatchReport{SchemaVersion: whodis.ReportSchemaVersion, Reports: reports}, nil
}

type cancelAwareEngine struct {
	started  chan struct{}
	canceled chan struct{}
}

func (engine cancelAwareEngine) RunBatch(ctx context.Context, _ whodis.BatchRequest) (whodis.BatchReport, error) {
	close(engine.started)
	<-ctx.Done()
	close(engine.canceled)
	return whodis.BatchReport{}, ctx.Err()
}

func TestServerHelloParseAndRun(t *testing.T) {
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":"hello-1","method":"hello"}`,
		`{"jsonrpc":"2.0","id":"parse-1","method":"parse","params":{"input":"https://example.com/path"}}`,
		`{"jsonrpc":"2.0","id":"run-1","method":"run","params":{"targets":["https://example.com/path"],"operation":"registration"}}`,
	}, "\n") + "\n"
	var output bytes.Buffer
	server := NewServerWithEngine("1.2.3", fakeEngine{}, strings.NewReader(input), &output, &bytes.Buffer{})
	if err := server.Serve(); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("response lines = %d, want hello, parse, progress, run:\n%s", len(lines), output.String())
	}
	var run struct {
		Result runResult `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[3]), &run); err != nil {
		t.Fatal(err)
	}
	if run.Result.Token == "" || len(run.Result.Items) != 1 {
		t.Fatalf("run result = %+v", run.Result)
	}
}

func TestServerProtocolV5Run(t *testing.T) {
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":"hello-1","method":"hello"}`,
		`{"jsonrpc":"2.0","id":"run-1","method":"run","params":{"targets":["example.test"],"operation":"dns.query","dns":{"types":["A"]}}}`,
	}, "\n") + "\n"
	var output bytes.Buffer
	server := NewServerWithEngine("1.0.0", fakeEngine{}, strings.NewReader(input), &output, &bytes.Buffer{})
	if err := server.Serve(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("response lines = %d, want hello, progress, run:\n%s", len(lines), output.String())
	}
	var hello struct {
		Result helloResult `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &hello); err != nil || hello.Result.ProtocolVersion != 5 {
		t.Fatalf("hello = (%+v, %v)", hello, err)
	}
	if !containsString(hello.Result.Capabilities, "investigate") || !containsString(hello.Result.Capabilities, "homepage_profile") || !containsString(hello.Result.Capabilities, "research_links") || !containsString(hello.Result.Capabilities, "schema_v5") || len(hello.Result.InvestigationLinkProviders) < 10 {
		t.Fatalf("hello capabilities = %#v", hello.Result.Capabilities)
	}
	var completed struct {
		Result runResult `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[2]), &completed); err != nil {
		t.Fatal(err)
	}
	if completed.Result.Token == "" || len(completed.Result.Items) != 1 || completed.Result.Items[0].Report.SchemaVersion != whodis.ReportSchemaVersion {
		t.Fatalf("run result = %+v", completed.Result)
	}
}

func TestValidateRunParamsKeepsEnrichmentExplicitAndInvestigationOnly(t *testing.T) {
	valid := runParams{
		Targets: []string{"example.test"}, Operation: whodis.OperationInvestigate,
		Investigation: whodis.InvestigationOptions{Enrichments: []string{"otx"}, RelatedLimit: 25, ExternalLinkTemplate: "off"},
	}
	if err := validateRunParams(valid); err != nil {
		t.Fatalf("valid investigation was rejected: %v", err)
	}
	invalid := []runParams{
		{Targets: []string{"example.test"}, Operation: whodis.OperationRegistration, Investigation: whodis.InvestigationOptions{RelatedLimit: 25}},
		{Targets: []string{"example.test"}, Operation: whodis.OperationRegistration, Investigation: whodis.InvestigationOptions{LinkProviders: []string{"all"}}},
		{Targets: []string{"example.test"}, Operation: whodis.OperationInvestigate, Investigation: whodis.InvestigationOptions{Enrichments: []string{"unknown"}}},
		{Targets: []string{"example.test"}, Operation: whodis.OperationInvestigate, Investigation: whodis.InvestigationOptions{LinkProviders: []string{"unknown"}}},
		{Targets: []string{"example.test"}, Operation: whodis.OperationInvestigate, Investigation: whodis.InvestigationOptions{ExternalLinkTemplate: "http://unsafe.example/{type}/{value}"}},
	}
	for _, params := range invalid {
		if err := validateRunParams(params); err == nil {
			t.Fatalf("invalid GUI params were accepted: %#v", params)
		}
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestReportItemsExposeRawOnce(t *testing.T) {
	report := whodis.Report{
		SchemaVersion: whodis.ReportSchemaVersion,
		Operation:     whodis.OperationRegistration,
		Subject:       whodis.Subject{Original: "example.test", Canonical: "example.test"},
		Registration: &whodis.RegistrationResult{Sources: []whodis.Source{{
			Protocol: whodis.ProtocolWHOIS, Endpoint: "whois.example.test", Raw: "Domain Name: EXAMPLE.TEST\n",
		}}},
	}
	items := reportItems([]string{"example.test"}, []whodis.Report{report})
	if len(items) != 1 || len(items[0].RawSources) != 1 || items[0].RawSources[0].Content == "" {
		t.Fatalf("report items = %#v", items)
	}
	if items[0].Report.Registration.Sources[0].Raw != "" {
		t.Fatal("presentation report duplicated the raw response")
	}
	if report.Registration.Sources[0].Raw == "" {
		t.Fatal("stored report was mutated while preparing presentation")
	}
}

func TestMergeRetryResultPreservesSuccessfulReports(t *testing.T) {
	baseBatch := whodis.BatchReport{SchemaVersion: whodis.ReportSchemaVersion, Reports: []whodis.Report{
		{Operation: whodis.OperationRegistration, Subject: whodis.Subject{Canonical: "good.test"}},
		{Operation: whodis.OperationRegistration, Subject: whodis.Subject{Canonical: "failed.test"}, Errors: []whodis.OperationError{{Message: "offline"}}},
	}}
	base := &storedResult{reportBatch: &baseBatch, inputs: []string{"good.test", "failed.test"}}
	retried := whodis.BatchReport{SchemaVersion: whodis.ReportSchemaVersion, Reports: []whodis.Report{
		{Operation: whodis.OperationRegistration, Subject: whodis.Subject{Canonical: "failed.test"}},
	}}
	merged, inputs := mergeRetryResult(retried, runParams{Targets: []string{"failed.test"}, ReplaceIndices: []int{1}}, base)
	if len(merged.Reports) != 2 || merged.Reports[0].Subject.Canonical != "good.test" || merged.Reports[1].Subject.Canonical != "failed.test" || len(merged.Reports[1].Errors) != 0 {
		t.Fatalf("merged retry = %#v", merged)
	}
	if len(inputs) != 2 || inputs[0] != "good.test" || inputs[1] != "failed.test" {
		t.Fatalf("merged inputs = %#v", inputs)
	}
}

func TestServerRetryReturnsCompleteMergedBatch(t *testing.T) {
	var output bytes.Buffer
	server := NewServerWithEngine("test", fakeEngine{}, strings.NewReader(""), &output, &bytes.Buffer{})
	baseBatch := whodis.BatchReport{SchemaVersion: whodis.ReportSchemaVersion, Reports: []whodis.Report{
		{SchemaVersion: whodis.ReportSchemaVersion, Operation: whodis.OperationDNSQuery, Subject: whodis.Subject{Original: "good.test", Canonical: "good.test"}},
		{SchemaVersion: whodis.ReportSchemaVersion, Operation: whodis.OperationDNSQuery, Subject: whodis.Subject{Original: "failed.test", Canonical: "failed.test"}, Errors: []whodis.OperationError{{Message: "offline"}}},
	}}
	baseToken, err := server.storeReportResult(baseBatch, []string{"good.test", "failed.test"})
	if err != nil {
		t.Fatal(err)
	}
	params, err := json.Marshal(runParams{
		Targets: []string{"failed.test"}, Operation: whodis.OperationDNSQuery,
		BaseToken: baseToken, ReplaceIndices: []int{1},
	})
	if err != nil {
		t.Fatal(err)
	}
	server.handle(request{JSONRPC: "2.0", ID: json.RawMessage(`"retry-1"`), Method: "run", Params: params})
	server.group.Wait()
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("retry response lines = %d, want progress and result:\n%s", len(lines), output.String())
	}
	var response struct {
		Result runResult `json:"result"`
		Error  *rpcError `json:"error"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error != nil || response.Result.Token == "" || len(response.Result.Items) != 2 {
		t.Fatalf("retry response = %+v", response)
	}
	if response.Result.Items[0].Input != "good.test" || response.Result.Items[1].Input != "failed.test" || len(response.Result.Items[1].Report.Errors) != 0 {
		t.Fatalf("retry items = %#v", response.Result.Items)
	}
	stored, ok := server.loadResult(response.Result.Token)
	if !ok || stored.reportBatch == nil || len(stored.reportBatch.Reports) != 2 {
		t.Fatalf("merged export result was not retained: %#v", stored)
	}
}

func TestValidateRunParamsBoundsDesktopBatchesAndRetryIndexes(t *testing.T) {
	targets := make([]string, maximumGUIBatchItems+1)
	for index := range targets {
		targets[index] = "example.test"
	}
	if err := validateRunParams(runParams{Targets: targets, Operation: whodis.OperationRegistration}); err == nil {
		t.Fatal("oversized desktop batch was accepted")
	}
	if err := validateRunParams(runParams{Targets: []string{"example.test"}, Operation: whodis.OperationRegistration, BaseToken: "result-1"}); err == nil {
		t.Fatal("retry base without indexes was accepted")
	}
	if err := validateRunParams(runParams{Targets: []string{"one.test", "two.test"}, Operation: whodis.OperationRegistration, BaseToken: "result-1", ReplaceIndices: []int{1, 1}}); err == nil {
		t.Fatal("duplicate retry indexes were accepted")
	}
}

func TestStoredResultsExpireAndStayWithinCountLimit(t *testing.T) {
	server := NewServerWithEngine("test", fakeEngine{}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	batch := whodis.BatchReport{SchemaVersion: whodis.ReportSchemaVersion, Reports: []whodis.Report{{Operation: whodis.OperationRegistration}}}
	var first string
	for index := 0; index <= maximumStoredResults; index++ {
		token, err := server.storeReportResult(batch, []string{"example.test"})
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			first = token
		}
	}
	if len(server.resultIDs) != maximumStoredResults {
		t.Fatalf("stored result count = %d", len(server.resultIDs))
	}
	if _, ok := server.results[first]; ok {
		t.Fatal("oldest stored result was not evicted")
	}
	oldest := server.resultIDs[0]
	value := server.results[oldest]
	value.storedAt = time.Now().Add(-storedResultTTL - time.Second)
	server.results[oldest] = value
	if _, ok := server.loadResult(oldest); ok {
		t.Fatal("expired stored result remained available")
	}
}

func TestServerInputClosureCancelsActiveRuns(t *testing.T) {
	engine := cancelAwareEngine{started: make(chan struct{}), canceled: make(chan struct{})}
	input := strings.NewReader(`{"jsonrpc":"2.0","id":"run-1","method":"run","params":{"targets":["example.test"],"operation":"registration"}}` + "\n")
	server := NewServerWithEngine("test", engine, input, &bytes.Buffer{}, &bytes.Buffer{})
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	select {
	case <-engine.started:
	case <-time.After(time.Second):
		t.Fatal("run did not start")
	}
	select {
	case <-engine.canceled:
	case <-time.After(time.Second):
		t.Fatal("input closure did not cancel active run")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
