package guiapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Alex9001/whodis"
)

type batchClient interface {
	LookupBatch(context.Context, []string, whodis.BatchLookupOptions) (whodis.BatchResult, error)
}

type storedResult struct {
	batch whodis.BatchResult
}

// Server exposes the Whodis engine to a desktop frontend over JSON-RPC.
type Server struct {
	version string
	client  batchClient
	input   io.Reader
	output  io.Writer
	logs    io.Writer

	writeMutex sync.Mutex
	stateMutex sync.Mutex
	cancels    map[string]context.CancelFunc
	results    map[string]storedResult
	resultIDs  []string
	nextToken  atomic.Uint64
	group      sync.WaitGroup
}

// NewServer constructs a GUI engine server. The caller owns all streams.
func NewServer(version string, client batchClient, input io.Reader, output, logs io.Writer) *Server {
	return &Server{
		version: version,
		client:  client,
		input:   input,
		output:  output,
		logs:    logs,
		cancels: make(map[string]context.CancelFunc),
		results: make(map[string]storedResult),
	}
}

// Serve processes requests until input closes, then waits for active lookups.
func (server *Server) Serve() error {
	if server.client == nil || server.input == nil || server.output == nil {
		return fmt.Errorf("GUI engine requires a client, input, and output")
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
			Capabilities:    []string{"registration", "dns_scan", "axfr", "batch", "progress", "cancel", "raw", "export"},
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
	case "lookup":
		var params lookupParams
		if err := decodeParams(rpcRequest.Params, &params); err != nil {
			server.writeError(rpcRequest.ID, -32602, err.Error(), nil)
			return
		}
		if len(rpcRequest.ID) == 0 || string(rpcRequest.ID) == "null" {
			server.writeError(rpcRequest.ID, -32600, "lookup requires an id", nil)
			return
		}
		options, err := parseLookupOptions(params)
		if err != nil {
			server.writeError(rpcRequest.ID, -32602, err.Error(), nil)
			return
		}
		server.startLookup(rpcRequest.ID, params, options)
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
		rendered, err := renderExport(stored.batch, params)
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

func parseLookupOptions(params lookupParams) (whodis.BatchLookupOptions, error) {
	if len(params.Targets) == 0 {
		return whodis.BatchLookupOptions{}, fmt.Errorf("at least one target is required")
	}
	protocol := whodis.ProtocolAuto
	if params.Protocol != "" {
		protocol = whodis.Protocol(strings.ToLower(params.Protocol))
	}
	switch protocol {
	case whodis.ProtocolAuto, whodis.ProtocolRDAP, whodis.ProtocolWHOIS, whodis.ProtocolRWHOIS:
	default:
		return whodis.BatchLookupOptions{}, fmt.Errorf("protocol must be auto, rdap, whois, or rwhois")
	}
	fallback := whodis.FallbackUnavailable
	if params.Fallback != "" {
		fallback = whodis.FallbackMode(strings.ToLower(params.Fallback))
	}
	switch fallback {
	case whodis.FallbackUnavailable, whodis.FallbackNone, whodis.FallbackAnyError:
	default:
		return whodis.BatchLookupOptions{}, fmt.Errorf("fallback must be unavailable, none, or any-error")
	}
	mode := strings.ToLower(strings.TrimSpace(params.Mode))
	dnsMode := whodis.DNSOff
	switch mode {
	case "", "registration":
	case "scan":
		dnsMode = whodis.DNSScan
	case "axfr":
		dnsMode = whodis.DNSAXFR
	default:
		return whodis.BatchLookupOptions{}, fmt.Errorf("mode must be registration, scan, or axfr")
	}
	timeout := 15 * time.Second
	if params.TimeoutMS != 0 {
		if params.TimeoutMS < 1 || params.TimeoutMS > int((10*time.Minute)/time.Millisecond) {
			return whodis.BatchLookupOptions{}, fmt.Errorf("timeout_ms must be between 1 and 600000")
		}
		timeout = time.Duration(params.TimeoutMS) * time.Millisecond
	}
	if params.Workers < 0 || params.Workers > 32 {
		return whodis.BatchLookupOptions{}, fmt.Errorf("workers must be between 1 and 32")
	}
	if protocol == whodis.ProtocolRWHOIS && strings.TrimSpace(params.Server) == "" {
		return whodis.BatchLookupOptions{}, fmt.Errorf("rwhois requires a server")
	}
	if strings.TrimSpace(params.Server) != "" && protocol == whodis.ProtocolAuto {
		return whodis.BatchLookupOptions{}, fmt.Errorf("a server requires an explicit protocol")
	}
	return whodis.BatchLookupOptions{
		LookupOptions: whodis.LookupOptions{
			Protocol:         protocol,
			Fallback:         fallback,
			Server:           strings.TrimSpace(params.Server),
			Timeout:          timeout,
			RefreshBootstrap: params.RefreshBootstrap,
			DNSMode:          dnsMode,
			DNSResolver:      strings.TrimSpace(params.Resolver),
		},
		Workers: params.Workers,
	}, nil
}

func (server *Server) startLookup(id json.RawMessage, params lookupParams, options whodis.BatchLookupOptions) {
	requestID, ok := stringID(id)
	if !ok {
		server.writeError(id, -32600, "lookup id must be a string", nil)
		return
	}
	server.stateMutex.Lock()
	if _, exists := server.cancels[requestID]; exists {
		server.stateMutex.Unlock()
		server.writeError(id, -32600, "lookup id is already active", nil)
		return
	}
	contextForLookup, cancel := context.WithCancel(context.Background())
	server.cancels[requestID] = cancel
	server.stateMutex.Unlock()

	originals := append([]string(nil), params.Targets...)
	normalized := make([]string, len(originals))
	for index, input := range originals {
		value, err := normalizeTarget(input)
		if err != nil {
			normalized[index] = input
		} else {
			normalized[index] = value
		}
	}
	options.OnProgress = func(update whodis.BatchProgress) {
		server.writeNotification("progress", progressParams{
			RequestID: requestID,
			Index:     update.Index,
			Completed: update.Completed,
			Total:     update.Total,
			Item:      makeItem(originals[update.Index], update.Item),
		})
	}

	server.group.Add(1)
	go func() {
		defer server.group.Done()
		defer server.removeCancel(requestID)
		batch, err := server.client.LookupBatch(contextForLookup, normalized, options)
		if err != nil {
			server.writeLookupError(id, err)
			return
		}
		for index := range batch.Items {
			batch.Items[index].Input = originals[index]
		}
		token := server.storeResult(batch)
		items := make([]item, len(batch.Items))
		for index, batchItem := range batch.Items {
			items[index] = makeItem(originals[index], batchItem)
		}
		server.writeResult(id, lookupResult{Token: token, Items: items, Canceled: contextForLookup.Err() != nil})
	}()
}

func makeItem(input string, batchItem whodis.BatchItem) item {
	result := item{Input: input, Result: batchItem.Result, Error: batchItem.Error}
	if batchItem.Result != nil {
		for _, source := range batchItem.Result.Sources {
			result.RawSources = append(result.RawSources, rawSource{
				Protocol: source.Protocol, Endpoint: source.Endpoint, Authority: source.Authority, Content: source.Raw,
			})
		}
	}
	return result
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

func (server *Server) storeResult(batch whodis.BatchResult) string {
	token := fmt.Sprintf("result-%d", server.nextToken.Add(1))
	server.stateMutex.Lock()
	server.results[token] = storedResult{batch: batch}
	server.resultIDs = append(server.resultIDs, token)
	if len(server.resultIDs) > 20 {
		oldest := server.resultIDs[0]
		server.resultIDs = server.resultIDs[1:]
		delete(server.results, oldest)
	}
	server.stateMutex.Unlock()
	return token
}

func (server *Server) loadResult(token string) (storedResult, bool) {
	server.stateMutex.Lock()
	defer server.stateMutex.Unlock()
	result, ok := server.results[token]
	return result, ok
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
