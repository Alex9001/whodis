package guiapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Alex9001/whodis/v2"
)

type engineRunner interface {
	RunBatch(context.Context, whodis.BatchRequest) (whodis.BatchReport, error)
}

type storedResult struct {
	reportBatch *whodis.BatchReport
	inputs      []string
	storedAt    time.Time
	bytes       int64
}

const (
	maximumGUIBatchItems     = 1000
	maximumStoredResults     = 20
	maximumStoredResultBytes = 64 << 20
	storedResultTTL          = 30 * time.Minute
)

// Server exposes the Whodis engine to a desktop frontend over JSON-RPC.
type Server struct {
	version string
	engine  engineRunner
	input   io.Reader
	output  io.Writer
	logs    io.Writer

	writeMutex  sync.Mutex
	stateMutex  sync.Mutex
	cancels     map[string]context.CancelFunc
	results     map[string]storedResult
	resultIDs   []string
	resultBytes int64
	nextToken   atomic.Uint64
	group       sync.WaitGroup
}

// NewServerWithEngine constructs a protocol-v4 server with an explicitly
// injected operation engine. The caller owns the engine and all streams.
func NewServerWithEngine(version string, engine engineRunner, input io.Reader, output, logs io.Writer) *Server {
	return &Server{
		version: version,
		engine:  engine,
		input:   input,
		output:  output,
		logs:    logs,
		cancels: make(map[string]context.CancelFunc),
		results: make(map[string]storedResult),
	}
}

// Serve processes requests until input closes, then waits for active lookups.
func (server *Server) Serve() error {
	if server.engine == nil || server.input == nil || server.output == nil {
		return fmt.Errorf("GUI engine requires an operation engine, input, and output")
	}
	scanner := bufio.NewScanner(server.input)
	scanner.Buffer(make([]byte, 64<<10), 16<<20)
	for scanner.Scan() {
		var rpcRequest request
		if err := json.Unmarshal(scanner.Bytes(), &rpcRequest); err != nil {
			server.writeResponse(response{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "invalid JSON"}})
			continue
		}
		server.handle(rpcRequest)
	}
	server.cancelAll()
	server.group.Wait()
	return scanner.Err()
}

func (server *Server) handle(rpcRequest request) {
	if rpcRequest.JSONRPC != "2.0" || rpcRequest.Method == "" {
		server.writeError(rpcRequest.ID, -32600, "invalid JSON-RPC request", nil)
		return
	}
	switch rpcRequest.Method {
	case "hello":
		server.writeResult(rpcRequest.ID, helloResult{
			ProtocolVersion: ProtocolVersion,
			EngineVersion:   server.version,
			Capabilities:    []string{"registration", "inspect", "dns_query", "dns_inventory", "dns_compare", "dns_trace", "dns_transfer", "diagnose", "investigate", "stack", "related", "batch", "batch_retry", "progress", "cancel", "raw", "export", "schema_v5"},
		})
	case "parse":
		var params parseParams
		if err := decodeParams(rpcRequest.Params, &params); err != nil {
			server.writeError(rpcRequest.ID, -32602, err.Error(), nil)
			return
		}
		result, err := parseTarget(params.Input)
		if err != nil {
			server.writeError(rpcRequest.ID, -32602, err.Error(), nil)
			return
		}
		server.writeResult(rpcRequest.ID, result)
	case "run":
		var params runParams
		if err := decodeParams(rpcRequest.Params, &params); err != nil {
			server.writeError(rpcRequest.ID, -32602, err.Error(), nil)
			return
		}
		if server.engine == nil {
			server.writeError(rpcRequest.ID, -32601, "operation engine is unavailable", nil)
			return
		}
		if err := validateRunParams(params); err != nil {
			server.writeError(rpcRequest.ID, -32602, err.Error(), nil)
			return
		}
		server.startRun(rpcRequest.ID, params)
	case "cancel":
		var params cancelParams
		if err := decodeParams(rpcRequest.Params, &params); err != nil {
			server.writeError(rpcRequest.ID, -32602, err.Error(), nil)
			return
		}
		canceled := server.cancel(params.RequestID)
		server.writeResult(rpcRequest.ID, map[string]bool{"canceled": canceled})
	case "export":
		var params exportParams
		if err := decodeParams(rpcRequest.Params, &params); err != nil {
			server.writeError(rpcRequest.ID, -32602, err.Error(), nil)
			return
		}
		stored, ok := server.loadResult(params.Token)
		if !ok {
			server.writeError(rpcRequest.ID, -32602, "unknown or expired result token", nil)
			return
		}
		var rendered exportResult
		var err error
		if stored.reportBatch == nil {
			server.writeError(rpcRequest.ID, -32602, "result is unavailable", nil)
			return
		}
		rendered, err = renderReportExport(*stored.reportBatch, params)
		if err != nil {
			server.writeError(rpcRequest.ID, -32602, err.Error(), nil)
			return
		}
		server.writeResult(rpcRequest.ID, rendered)
	default:
		server.writeError(rpcRequest.ID, -32601, "method not found", nil)
	}
}

func decodeParams(payload json.RawMessage, destination any) error {
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	if err := json.Unmarshal(payload, destination); err != nil {
		return fmt.Errorf("invalid params: %w", err)
	}
	return nil
}

func validateRunParams(params runParams) error {
	if len(params.Targets) == 0 {
		return fmt.Errorf("at least one target is required")
	}
	if len(params.Targets) > maximumGUIBatchItems {
		return fmt.Errorf("desktop batches support at most %d targets; use the CLI streaming formats for larger jobs", maximumGUIBatchItems)
	}
	if (strings.TrimSpace(params.BaseToken) == "") != (len(params.ReplaceIndices) == 0) {
		return fmt.Errorf("base_token and replace_indices must be supplied together")
	}
	if len(params.ReplaceIndices) > 0 {
		if len(params.ReplaceIndices) != len(params.Targets) {
			return fmt.Errorf("replace_indices must match the number of retry targets")
		}
		seen := make(map[int]bool, len(params.ReplaceIndices))
		for _, index := range params.ReplaceIndices {
			if index < 0 || seen[index] {
				return fmt.Errorf("replace_indices must contain unique non-negative indexes")
			}
			seen[index] = true
		}
	}
	switch params.Operation {
	case whodis.OperationRegistration, whodis.OperationInspect, whodis.OperationDNSQuery, whodis.OperationDNSInventory,
		whodis.OperationDNSCompare, whodis.OperationDNSTrace, whodis.OperationDNSTransfer,
		whodis.OperationDiagnose, whodis.OperationInvestigate:
	default:
		return fmt.Errorf("unknown operation %q", params.Operation)
	}
	if params.Workers < 0 || params.Workers > 32 {
		return fmt.Errorf("workers must be between 1 and 32")
	}
	if params.TimeoutMS < 0 || params.TimeoutMS > int((10*time.Minute)/time.Millisecond) {
		return fmt.Errorf("timeout_ms must be between 1 and 600000")
	}
	if params.Protocol != "" {
		switch params.Protocol {
		case whodis.ProtocolAuto, whodis.ProtocolRDAP, whodis.ProtocolWHOIS, whodis.ProtocolRWHOIS:
		default:
			return fmt.Errorf("protocol must be auto, rdap, whois, or rwhois")
		}
	}
	if params.Fallback != "" {
		switch params.Fallback {
		case whodis.FallbackUnavailable, whodis.FallbackNone, whodis.FallbackAnyError:
		default:
			return fmt.Errorf("fallback must be unavailable, none, or any-error")
		}
	}
	protocol := params.Protocol
	if protocol == "" {
		protocol = whodis.ProtocolAuto
	}
	if protocol == whodis.ProtocolRWHOIS && strings.TrimSpace(params.Server) == "" {
		return fmt.Errorf("rwhois requires a server")
	}
	if strings.TrimSpace(params.Server) != "" && protocol == whodis.ProtocolAuto {
		return fmt.Errorf("a server requires an explicit protocol")
	}
	if err := whodis.ValidateDNSOptions(params.DNS); err != nil {
		return fmt.Errorf("invalid DNS options: %w", err)
	}
	if err := whodis.ValidateInvestigationOptions(params.Investigation); err != nil {
		return fmt.Errorf("invalid investigation options: %w", err)
	}
	if params.Operation != whodis.OperationInvestigate && (len(params.Investigation.Enrichments) > 0 || params.Investigation.RelatedLimit != 0 || strings.TrimSpace(params.Investigation.ExternalLinkTemplate) != "" || strings.TrimSpace(params.Investigation.OTXEndpoint) != "") {
		return fmt.Errorf("investigation options require the investigate operation")
	}
	for _, provider := range params.Investigation.Enrichments {
		if strings.ToLower(strings.TrimSpace(provider)) != "otx" {
			return fmt.Errorf("unknown enrichment provider %q", provider)
		}
	}
	return nil
}

func (server *Server) startRun(id json.RawMessage, params runParams) {
	requestID, ok := stringID(id)
	if !ok {
		server.writeError(id, -32600, "run id must be a string", nil)
		return
	}
	var retryBase *storedResult
	if params.BaseToken != "" {
		stored, found := server.loadResult(params.BaseToken)
		if !found || stored.reportBatch == nil {
			server.writeError(id, -32602, "unknown or expired base result token", nil)
			return
		}
		if len(stored.inputs) != len(stored.reportBatch.Reports) {
			server.writeError(id, -32602, "base result is incomplete", nil)
			return
		}
		for offset, index := range params.ReplaceIndices {
			if index >= len(stored.inputs) || stored.inputs[index] != params.Targets[offset] || stored.reportBatch.Reports[index].Operation != params.Operation {
				server.writeError(id, -32602, "retry targets do not match the base result", nil)
				return
			}
		}
		retryBase = &stored
	}

	server.stateMutex.Lock()
	if _, exists := server.cancels[requestID]; exists {
		server.stateMutex.Unlock()
		server.writeError(id, -32600, "run id is already active", nil)
		return
	}
	runContext, cancel := context.WithCancel(context.Background())
	server.cancels[requestID] = cancel
	server.stateMutex.Unlock()

	timeout := 15 * time.Second
	if params.Operation == whodis.OperationInvestigate {
		timeout = 30 * time.Second
	}
	if params.TimeoutMS > 0 {
		timeout = time.Duration(params.TimeoutMS) * time.Millisecond
	}
	protocol := params.Protocol
	if protocol == "" {
		protocol = whodis.ProtocolAuto
	}
	fallback := params.Fallback
	if fallback == "" {
		fallback = whodis.FallbackUnavailable
	}
	requests := make([]whodis.Request, len(params.Targets))
	for index, target := range params.Targets {
		diagnose := params.Diagnose
		diagnose.Timeout = timeout
		diagnose.DNS = params.DNS
		request := whodis.Request{
			ID: fmt.Sprintf("%s-%d", requestID, index), Operation: params.Operation,
			Target: target, Timeout: timeout, DNS: params.DNS, Diagnose: diagnose,
			Registration: whodis.LookupOptions{Protocol: protocol, Fallback: fallback, Server: strings.TrimSpace(params.Server), Timeout: timeout, RefreshBootstrap: params.RefreshBootstrap},
		}
		if params.Operation == whodis.OperationInvestigate {
			investigation := params.Investigation
			investigation.DNS = params.DNS
			investigation.OTXToken = os.Getenv("WHODIS_OTX_API_KEY")
			request.Investigation = investigation
		}
		requests[index] = request
	}
	server.group.Add(1)
	go func() {
		defer server.group.Done()
		defer server.removeCancel(requestID)
		batch, err := server.engine.RunBatch(runContext, whodis.BatchRequest{
			Requests: requests, Workers: params.Workers,
			OnProgress: func(event whodis.ProgressEvent) {
				server.writeNotification("progress", map[string]any{
					"request_id": requestID, "operation": event.Operation, "target": event.Target,
					"stage": event.Stage, "completed": event.Completed, "total": event.Total,
				})
			},
		})
		if err != nil {
			server.writeLookupError(id, err)
			return
		}
		batch, inputs := mergeRetryResult(batch, params, retryBase)
		token, storeErr := server.storeReportResult(batch, inputs)
		if storeErr != nil {
			server.writeLookupError(id, storeErr)
			return
		}
		items := reportItems(inputs, batch.Reports)
		server.writeResult(id, runResult{Token: token, Items: items, Canceled: runContext.Err() != nil})
	}()
}

func (server *Server) writeLookupError(id json.RawMessage, err error) {
	var lookupError *whodis.LookupError
	if errors.As(err, &lookupError) {
		server.writeError(id, -32000, lookupError.Error(), map[string]string{"kind": string(lookupError.Kind)})
		return
	}
	server.writeError(id, -32000, err.Error(), nil)
}

func stringID(raw json.RawMessage) (string, bool) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || value == "" {
		return "", false
	}
	return value, true
}

func (server *Server) cancel(requestID string) bool {
	server.stateMutex.Lock()
	cancel, ok := server.cancels[requestID]
	server.stateMutex.Unlock()
	if ok {
		cancel()
	}
	return ok
}

func (server *Server) cancelAll() {
	server.stateMutex.Lock()
	cancels := make([]context.CancelFunc, 0, len(server.cancels))
	for _, cancel := range server.cancels {
		cancels = append(cancels, cancel)
	}
	server.stateMutex.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}

func (server *Server) removeCancel(requestID string) {
	server.stateMutex.Lock()
	delete(server.cancels, requestID)
	server.stateMutex.Unlock()
}

func reportItems(inputs []string, reports []whodis.Report) []reportItem {
	items := make([]reportItem, len(reports))
	for index, report := range reports {
		input := report.Subject.Original
		if index < len(inputs) && inputs[index] != "" {
			input = inputs[index]
		}
		presentation := report
		items[index] = reportItem{Input: input, Report: presentation}
		if report.Registration == nil {
			continue
		}
		registration := *report.Registration
		registration.Sources = append([]whodis.Source(nil), report.Registration.Sources...)
		for sourceIndex := range registration.Sources {
			source := &registration.Sources[sourceIndex]
			if source.Raw != "" {
				items[index].RawSources = append(items[index].RawSources, rawSource{Protocol: source.Protocol, Endpoint: source.Endpoint, Authority: source.Authority, Content: source.Raw})
				source.Raw = ""
			}
		}
		presentation.Registration = &registration
		items[index].Report = presentation
	}
	return items
}

func mergeRetryResult(batch whodis.BatchReport, params runParams, base *storedResult) (whodis.BatchReport, []string) {
	if base == nil {
		return batch, append([]string(nil), params.Targets...)
	}
	merged := append([]whodis.Report(nil), base.reportBatch.Reports...)
	for offset, index := range params.ReplaceIndices {
		merged[index] = batch.Reports[offset]
	}
	return whodis.BatchReport{SchemaVersion: whodis.ReportSchemaVersion, Reports: merged}, append([]string(nil), base.inputs...)
}

func (server *Server) storeReportResult(batch whodis.BatchReport, inputs []string) (string, error) {
	encoded, err := json.Marshal(batch)
	if err != nil {
		return "", fmt.Errorf("could not retain desktop result: %w", err)
	}
	size := int64(len(encoded))
	if size > maximumStoredResultBytes {
		return "", fmt.Errorf("desktop result exceeds the 64 MiB retention limit; use CLI streaming output for this batch")
	}
	token := fmt.Sprintf("result-%d", server.nextToken.Add(1))
	server.stateMutex.Lock()
	defer server.stateMutex.Unlock()
	server.pruneResultsLocked(time.Now())
	for len(server.resultIDs) >= maximumStoredResults || (len(server.resultIDs) > 0 && server.resultBytes+size > maximumStoredResultBytes) {
		server.removeOldestResultLocked()
	}
	server.results[token] = storedResult{reportBatch: &batch, inputs: append([]string(nil), inputs...), storedAt: time.Now(), bytes: size}
	server.resultIDs = append(server.resultIDs, token)
	server.resultBytes += size
	return token, nil
}

func (server *Server) loadResult(token string) (storedResult, bool) {
	server.stateMutex.Lock()
	defer server.stateMutex.Unlock()
	server.pruneResultsLocked(time.Now())
	result, ok := server.results[token]
	return result, ok
}

func (server *Server) pruneResultsLocked(now time.Time) {
	for len(server.resultIDs) > 0 {
		oldest := server.results[server.resultIDs[0]]
		if now.Sub(oldest.storedAt) < storedResultTTL {
			break
		}
		server.removeOldestResultLocked()
	}
}

func (server *Server) removeOldestResultLocked() {
	if len(server.resultIDs) == 0 {
		return
	}
	oldestID := server.resultIDs[0]
	server.resultIDs = server.resultIDs[1:]
	server.resultBytes -= server.results[oldestID].bytes
	delete(server.results, oldestID)
}

func (server *Server) writeResult(id json.RawMessage, result any) {
	server.writeResponse(response{JSONRPC: "2.0", ID: id, Result: result})
}

func (server *Server) writeError(id json.RawMessage, code int, message string, data any) {
	server.writeResponse(response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: message, Data: data}})
}

func (server *Server) writeResponse(message response) {
	server.write(message)
}

func (server *Server) writeNotification(method string, params any) {
	server.write(notification{JSONRPC: "2.0", Method: method, Params: params})
}

func (server *Server) write(message any) {
	server.writeMutex.Lock()
	defer server.writeMutex.Unlock()
	if err := json.NewEncoder(server.output).Encode(message); err != nil && server.logs != nil {
		fmt.Fprintln(server.logs, "whodis-gui-engine:", err)
	}
}
