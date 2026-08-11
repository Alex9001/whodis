package guiapi

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Alex9001/whodis"
)

type fakeClient struct{}

func (fakeClient) LookupBatch(_ context.Context, targets []string, options whodis.BatchLookupOptions) (whodis.BatchResult, error) {
	batch := whodis.BatchResult{SchemaVersion: 1, Items: make([]whodis.BatchItem, len(targets))}
	for index, target := range targets {
		result := whodis.LookupResult{
			SchemaVersion: 2,
			Query:         whodis.Target{Original: target, Canonical: target, Kind: whodis.KindDomain},
			Route:         whodis.RouteDecision{Protocol: whodis.ProtocolRDAP},
			Object:        whodis.Object{Kind: whodis.KindDomain, Name: target, Registrar: "Example Registrar"},
			Sources:       []whodis.Source{{Protocol: whodis.ProtocolRDAP, Endpoint: "https://rdap.example", Raw: `{"ldhName":"example.com"}`}},
		}
		batch.Items[index] = whodis.BatchItem{Input: target, Result: &result}
		if options.OnProgress != nil {
			options.OnProgress(whodis.BatchProgress{Index: index, Completed: index + 1, Total: len(targets), Item: batch.Items[index]})
		}
	}
	return batch, nil
}

type fakeEngine struct{}

func (fakeEngine) RunBatch(_ context.Context, request whodis.BatchRequest) (whodis.BatchReport, error) {
	reports := make([]whodis.Report, len(request.Requests))
	for index, item := range request.Requests {
		reports[index] = whodis.Report{
			SchemaVersion: whodis.ReportSchemaVersion,
			Operation:     item.Operation,
			Query:         whodis.Target{Original: item.Target, Canonical: item.Target, Kind: whodis.KindDomain},
			DNS:           &whodis.DNSOperationResult{Mode: "query", Messages: []whodis.DNSMessage{{Name: item.Target, Type: "A", Rcode: "NOERROR"}}},
		}
		if request.OnProgress != nil {
			request.OnProgress(whodis.ProgressEvent{Operation: item.Operation, Target: item.Target, Stage: "completed", Completed: index + 1, Total: len(request.Requests)})
		}
	}
	return whodis.BatchReport{SchemaVersion: whodis.ReportSchemaVersion, Reports: reports}, nil
}

func TestServerHelloParseAndLookup(t *testing.T) {
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":"hello-1","method":"hello"}`,
		`{"jsonrpc":"2.0","id":"parse-1","method":"parse","params":{"input":"https://example.com/path"}}`,
		`{"jsonrpc":"2.0","id":"lookup-1","method":"lookup","params":{"targets":["https://example.com/path"]}}`,
	}, "\n") + "\n"
	var output bytes.Buffer
	server := NewServer("1.2.3", fakeClient{}, strings.NewReader(input), &output, &bytes.Buffer{})
	if err := server.Serve(); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("response lines = %d, want hello, parse, progress, lookup:\n%s", len(lines), output.String())
	}
	var lookup struct {
		Result lookupResult `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[3]), &lookup); err != nil {
		t.Fatal(err)
	}
	if lookup.Result.Token == "" || len(lookup.Result.Items) != 1 || len(lookup.Result.Items[0].RawSources) != 1 {
		t.Fatalf("lookup result = %+v", lookup.Result)
	}
}

func TestServerProtocolV2Run(t *testing.T) {
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":"hello-1","method":"hello"}`,
		`{"jsonrpc":"2.0","id":"run-1","method":"run","params":{"targets":["example.test"],"operation":"dns.query","dns":{"types":["A"]}}}`,
	}, "\n") + "\n"
	var output bytes.Buffer
	server := NewServerWithEngine("1.0.0", fakeClient{}, fakeEngine{}, strings.NewReader(input), &output, &bytes.Buffer{})
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
	if err := json.Unmarshal([]byte(lines[0]), &hello); err != nil || hello.Result.ProtocolVersion != 2 {
		t.Fatalf("hello = (%+v, %v)", hello, err)
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
