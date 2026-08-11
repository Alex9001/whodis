package guiapi

import (
	"encoding/json"

	"github.com/Alex9001/whodis"
)

const ProtocolVersion = 2

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type notification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type helloResult struct {
	ProtocolVersion int      `json:"protocol_version"`
	EngineVersion   string   `json:"engine_version"`
	Capabilities    []string `json:"capabilities"`
}

type parseParams struct {
	Input string `json:"input"`
}

type parseResult struct {
	Input      string        `json:"input"`
	Normalized string        `json:"normalized"`
	Target     whodis.Target `json:"target"`
}

type lookupParams struct {
	Targets          []string `json:"targets"`
	Mode             string   `json:"mode,omitempty"`
	Protocol         string   `json:"protocol,omitempty"`
	Fallback         string   `json:"fallback,omitempty"`
	Server           string   `json:"server,omitempty"`
	Resolver         string   `json:"resolver,omitempty"`
	TimeoutMS        int      `json:"timeout_ms,omitempty"`
	Workers          int      `json:"workers,omitempty"`
	RefreshBootstrap bool     `json:"refresh_bootstrap,omitempty"`
}

type runParams struct {
	Targets          []string               `json:"targets"`
	Operation        whodis.Operation       `json:"operation"`
	Protocol         whodis.Protocol        `json:"protocol,omitempty"`
	Fallback         whodis.FallbackMode    `json:"fallback,omitempty"`
	Server           string                 `json:"server,omitempty"`
	TimeoutMS        int                    `json:"timeout_ms,omitempty"`
	Workers          int                    `json:"workers,omitempty"`
	RefreshBootstrap bool                   `json:"refresh_bootstrap,omitempty"`
	DNS              whodis.DNSOptions      `json:"dns,omitempty"`
	Diagnose         whodis.DiagnoseOptions `json:"diagnose,omitempty"`
}

type cancelParams struct {
	RequestID string `json:"request_id"`
}

type exportParams struct {
	Token  string   `json:"token"`
	Format string   `json:"format"`
	Fields []string `json:"fields,omitempty"`
}

type rawSource struct {
	Protocol  whodis.Protocol `json:"protocol"`
	Endpoint  string          `json:"endpoint"`
	Authority string          `json:"authority,omitempty"`
	Content   string          `json:"content"`
}

type item struct {
	Input      string               `json:"input"`
	Result     *whodis.LookupResult `json:"result,omitempty"`
	Error      *whodis.BatchError   `json:"error,omitempty"`
	RawSources []rawSource          `json:"raw_sources,omitempty"`
}

type progressParams struct {
	RequestID string `json:"request_id"`
	Index     int    `json:"index"`
	Completed int    `json:"completed"`
	Total     int    `json:"total"`
	Item      item   `json:"item"`
}

type lookupResult struct {
	Token    string `json:"token"`
	Items    []item `json:"items"`
	Canceled bool   `json:"canceled,omitempty"`
}

type reportItem struct {
	Input      string        `json:"input"`
	Report     whodis.Report `json:"report"`
	RawSources []rawSource   `json:"raw_sources,omitempty"`
}

type runResult struct {
	Token    string       `json:"token"`
	Items    []reportItem `json:"items"`
	Canceled bool         `json:"canceled,omitempty"`
}

type exportResult struct {
	Content   string `json:"content"`
	MIME      string `json:"mime"`
	Extension string `json:"extension"`
}
