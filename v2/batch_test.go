package whodis

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLookupBatchReportsSerializedProgress(t *testing.T) {
	client := NewClient(ClientOptions{Adapters: []ProtocolAdapter{batchTestAdapter{}}})
	var mutex sync.Mutex
	var progress []BatchProgress
	batch, err := client.LookupBatch(context.Background(), []string{"one.example", "two.example", "three.example"}, BatchLookupOptions{
		LookupOptions: LookupOptions{Protocol: ProtocolRWHOIS, Server: "fixture.example"},
		Workers:       3,
		OnProgress: func(update BatchProgress) {
			mutex.Lock()
			defer mutex.Unlock()
			progress = append(progress, update)
		},
	})
	if err != nil {
		t.Fatalf("LookupBatch() error = %v", err)
	}
	if len(batch.Items) != 3 || len(progress) != 3 {
		t.Fatalf("items/progress = %d/%d, want 3/3", len(batch.Items), len(progress))
	}
	seen := map[int]bool{}
	for index, update := range progress {
		if update.Completed != index+1 || update.Total != 3 || update.Index < 0 || update.Index >= 3 {
			t.Fatalf("progress[%d] = %+v", index, update)
		}
		if seen[update.Index] {
			t.Fatalf("duplicate progress index %d", update.Index)
		}
		seen[update.Index] = true
	}
}

func TestLookupBatchPreservesOrderAndContinues(t *testing.T) {
	client := NewClient(ClientOptions{Timeout: time.Second, CacheDirectory: t.TempDir(), Adapters: []ProtocolAdapter{batchTestAdapter{}}})
	batch, err := client.LookupBatch(context.Background(), []string{"192.0.2.1", "not a valid target", "192.0.2.2"}, BatchLookupOptions{
		LookupOptions: LookupOptions{Protocol: ProtocolRWHOIS, Server: "rwhois.example.test", Timeout: time.Second},
		Workers:       3,
	})
	if err != nil {
		t.Fatalf("LookupBatch() error = %v", err)
	}
	if len(batch.Items) != 3 || batch.Items[0].Result == nil || batch.Items[1].Error == nil || batch.Items[2].Result == nil {
		t.Fatalf("batch items = %#v, want success/error/success", batch.Items)
	}
	if got := []string{batch.Items[0].Input, batch.Items[1].Input, batch.Items[2].Input}; strings.Join(got, ",") != "192.0.2.1,not a valid target,192.0.2.2" {
		t.Fatalf("input order = %#v", got)
	}
	if !batch.HasErrors() || batch.Items[1].Error.Kind != ErrorInvalidInput {
		t.Fatalf("batch error = %#v, want invalid-input item", batch.Items[1].Error)
	}
}

type batchTestAdapter struct{}

func (batchTestAdapter) Protocol() Protocol { return ProtocolRWHOIS }

func (batchTestAdapter) Lookup(_ context.Context, target Target, route RouteDecision) (Object, []Source, error) {
	return Object{Kind: target.Kind, Name: target.Canonical}, []Source{{Protocol: ProtocolRWHOIS, Endpoint: route.Endpoint}}, nil
}

func TestRenderBatchProjectionTSV(t *testing.T) {
	result := LookupResult{
		Query:  Target{Canonical: "example.com", Kind: KindDomain},
		Route:  RouteDecision{Protocol: ProtocolRDAP},
		Object: Object{Events: []Event{{Action: "expiration", Date: "2028-09-14T00:00:00Z"}}},
	}
	batch := BatchResult{SchemaVersion: 1, Items: []BatchItem{
		{Input: "example.com", Result: &result},
		{Input: "missing.example", Error: &BatchError{Kind: ErrorNotFound, Message: "not found"}},
	}}
	var output bytes.Buffer
	err := RenderBatch(&output, batch, FormatPlain, BatchRenderOptions{Fields: []ProjectionField{FieldExpiration, FieldProtocol}})
	if err != nil {
		t.Fatalf("RenderBatch() error = %v", err)
	}
	want := "TARGET\tEXPIRATION\tPROTOCOL\tERROR\nexample.com\t2028-09-14T00:00:00Z\trdap\t\nmissing.example\t\t\tnot_found: not found\n"
	if output.String() != want {
		t.Fatalf("projection TSV = %q, want %q", output.String(), want)
	}
}

func TestParseProjectionFieldAliases(t *testing.T) {
	for _, value := range []string{"expiration", "expiry", "expires"} {
		field, err := ParseProjectionField(value)
		if err != nil || field != FieldExpiration {
			t.Fatalf("ParseProjectionField(%q) = %q, %v", value, field, err)
		}
	}
}
