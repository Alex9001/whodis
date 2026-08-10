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
