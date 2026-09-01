package guiapi

import (
	"encoding/json"

	"github.com/Alex9001/whodis/v2"
)

const ProtocolVersion = 5

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
	ProtocolVersion            int                                `json:"protocol_version"`
	EngineVersion              string                             `json:"engine_version"`
	Capabilities               []string                           `json:"capabilities"`
	InvestigationLinkProviders []whodis.InvestigationLinkProvider `json:"investigation_link_providers"`
}

type parseParams struct {
	Input string `json:"input"`
}

type parseResult struct {
	Input      string         `json:"input"`
	Normalized string         `json:"normalized"`
	Subject    whodis.Subject `json:"subject"`
}

type runParams struct {
	Targets          []string                    `json:"targets"`
	Operation        whodis.Operation            `json:"operation"`
	Protocol         whodis.Protocol             `json:"protocol,omitempty"`
	Fallback         whodis.FallbackMode         `json:"fallback,omitempty"`
	Server           string                      `json:"server,omitempty"`
	TimeoutMS        int                         `json:"timeout_ms,omitempty"`
	Workers          int                         `json:"workers,omitempty"`
	RefreshBootstrap bool                        `json:"refresh_bootstrap,omitempty"`
	DNS              whodis.DNSOptions           `json:"dns,omitempty"`
	Diagnose         whodis.DiagnoseOptions      `json:"diagnose,omitempty"`
	Investigation    whodis.InvestigationOptions `json:"investigation,omitempty"`
	BaseToken        string                      `json:"base_token,omitempty"`
	ReplaceIndices   []int                       `json:"replace_indices,omitempty"`
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
