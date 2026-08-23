package whodis

import (
	"bytes"
	"encoding/json"
	"testing"

	mdns "github.com/miekg/dns"
)

func FuzzSubjectAndEndpointParsing(f *testing.F) {
	for _, seed := range []string{"example.com", "https://example.com/path", "8.8.8.8", "2001:4860:4860::8888", "AS15169", "xn--bcher-kva.example", "rwhois://example.net:4321"} {
		f.Add(seed, uint8(0))
	}
	operations := []Operation{OperationRegistration, OperationDNSQuery, OperationInspect, OperationDiagnose, OperationInvestigate}
	protocols := []Protocol{ProtocolRDAP, ProtocolWHOIS, ProtocolRWHOIS}
	f.Fuzz(func(t *testing.T, input string, selector uint8) {
		_, _ = ParseSubject(input, operations[int(selector)%len(operations)])
		_, _ = ParseDNSName(input)
		_, _ = canonicalEndpoint(protocols[int(selector)%len(protocols)], input)
	})
}

func FuzzRegistrationTextParsers(f *testing.F) {
	f.Add("Domain Name: EXAMPLE.COM\nRegistry Expiry Date: 2030-01-01T00:00:00Z\n")
	f.Add("%rwhois V-1.5:003fff:00 rwhois.example:4321\nnetwork:ID:NET-1\n%ok\n")
	f.Fuzz(func(t *testing.T, input string) {
		_ = parseWHOIS(input)
		_ = parseRWHOIS(input)
	})
}

func FuzzDNSWireNormalization(f *testing.F) {
	message := new(mdns.Msg)
	message.SetQuestion("example.com.", mdns.TypeA)
	wire, _ := message.Pack()
	f.Add(wire)
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded mdns.Msg
		if decoded.Unpack(input) != nil {
			return
		}
		_ = recordsFromRR(decoded.Answer)
		_ = recordsFromRR(decoded.Ns)
		_ = recordsFromRR(decoded.Extra)
		_ = extendedDNSErrors(&decoded)
		_ = dnsSecurityState(&decoded)
	})
}

func FuzzReportRendering(f *testing.F) {
	seed, _ := json.Marshal(Report{SchemaVersion: ReportSchemaVersion, Operation: OperationRegistration, Subject: Subject{Canonical: "example.com"}})
	f.Add(seed)
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		var report Report
		if json.Unmarshal(input, &report) != nil {
			return
		}
		for _, format := range []Format{FormatPlain, FormatPretty, FormatTree, FormatGeekBoys, FormatJSON, FormatYAML, FormatMarkdown} {
			var output bytes.Buffer
			_ = RenderReport(&output, report, format, RenderOptions{Width: 120})
		}
	})
}
