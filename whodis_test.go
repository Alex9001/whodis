package whodis

import (
	"context"
	"testing"
	"time"
)

func TestParseTarget(t *testing.T) {
	cases := []struct {
		input, canonical string
		kind             Kind
	}{
		{"Example.COM.", "example.com", KindDomain},
		{"bücher.example", "xn--bcher-kva.example", KindDomain},
		{"2001:4860:4860::8888", "2001:4860:4860::8888", KindIP},
		{"192.0.2.12/24", "192.0.2.0/24", KindIP},
		{"AS15169", "15169", KindASN},
		{"15169", "15169", KindASN},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			target, err := ParseTarget(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			if target.Canonical != tc.canonical || target.Kind != tc.kind {
				t.Fatalf("ParseTarget(%q) = %#v", tc.input, target)
			}
		})
	}
	if _, err := ParseTarget("ASbogus"); err == nil {
		t.Fatal("invalid ASN was accepted")
	}
}

func TestBootstrapPrefersLongestAuthoritativeMatch(t *testing.T) {
	registry := bootstrapRegistry{Version: "1.0", Services: [][][]string{
		{{"com"}, {"https://com.example/"}},
		{{"example.com"}, {"https://example.example/", "http://backup.example/"}},
	}}
	target, _ := ParseTarget("a.example.com")
	endpoints := registry.match(target)
	if len(endpoints) != 2 || endpoints[0] != "https://example.example/" || endpoints[1] != "http://backup.example/" {
		t.Fatalf("unexpected endpoint match: %#v", endpoints)
	}
	root := bootstrapRegistry{Version: "1.0", Services: [][][]string{{{""}, {"https://root.example/"}}}}
	if got := root.match(target); len(got) != 1 || got[0] != "https://root.example/" {
		t.Fatalf("root match = %#v", got)
	}
}

func TestRDAPAndWHOISNormalizers(t *testing.T) {
	rdapObject := normalizeRDAP(KindDomain, rdapRecord{
		ObjectClassName: "domain", LDHName: "example.test", Status: []string{"active"},
		Nameservers: []rdapNS{{LDHName: "ns1.example.test"}},
	})
	if rdapObject.Name != "example.test" || len(rdapObject.Nameservers) != 1 {
		t.Fatalf("unexpected RDAP object: %#v", rdapObject)
	}
	whoisObject := normalizeWHOIS(Target{Canonical: "example.test", Kind: KindDomain}, parseWHOIS("Domain Name: EXAMPLE.TEST\r\nRegistrar: Test Registrar\r\nName Server: NS1.EXAMPLE.TEST\r\n"))
	if whoisObject.Name != "EXAMPLE.TEST" || whoisObject.Registrar != "Test Registrar" {
		t.Fatalf("unexpected WHOIS object: %#v", whoisObject)
	}
}

func TestNewResultDeduplicatesEquivalentEventsAndRetainsDistinctDates(t *testing.T) {
	object := Object{Events: []Event{
		{Action: "registration", Date: "2026-02-21T05:13:38Z"},
		{Action: "Registration", Date: "2026-02-21T05:13:38+00:00"},
		{Action: "expiration", Date: "2027-02-21T05:13:38Z"},
		{Action: "registrar expiration", Date: "2027-02-21T05:13:38+00:00"},
		{Action: "registrar expiration", Date: "2028-02-21T05:13:38Z"},
		{Action: "last update of RDAP database", Date: "2026-08-11T03:19:33Z"},
		{Action: "last update of RDAP database", Date: "2026-02-21T05:13:38+00:00"},
	}}
	result := newResult(Target{}, RouteDecision{}, nil, object, nil)
	if len(result.Object.Events) != 5 {
		t.Fatalf("normalized events = %#v, want five unique facts", result.Object.Events)
	}
	if result.Object.Events[0].Action != "registration" || result.Object.Events[1].Action != "expiration" {
		t.Fatalf("equivalent event aliases were not normalized: %#v", result.Object.Events)
	}
	if result.Object.Events[2].Action != "registrar expiration" || result.Object.Events[2].Date != "2028-02-21T05:13:38Z" {
		t.Fatalf("distinct registrar expiration was lost: %#v", result.Object.Events)
	}
}

func TestClientUsesInjectedAdapter(t *testing.T) {
	adapter := staticAdapter{protocol: ProtocolRDAP, object: Object{Kind: KindDomain, Name: "example.test"}}
	client := NewClient(ClientOptions{Timeout: time.Second, Adapters: []ProtocolAdapter{adapter}})
	result, err := client.Lookup(context.Background(), "example.test", LookupOptions{Protocol: ProtocolRDAP, Server: "https://rdap.test/", Fallback: FallbackNone})
	if err != nil {
		t.Fatal(err)
	}
	if result.Object.Name != "example.test" || result.Route.Endpoint != "https://rdap.test/" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.DNS != nil {
		t.Fatalf("zero-value lookup options unexpectedly performed DNS discovery: %#v", result.DNS)
	}
}

func TestFallbackPolicy(t *testing.T) {
	if !shouldFallback(lookupError(ErrorUnavailable, "down", nil), FallbackUnavailable) {
		t.Fatal("unavailable should fall back")
	}
	if shouldFallback(lookupError(ErrorNotFound, "missing", nil), FallbackUnavailable) {
		t.Fatal("not found should not fall back")
	}
	if !shouldFallback(lookupError(ErrorNotFound, "missing", nil), FallbackAnyError) {
		t.Fatal("any-error should fall back")
	}
}

type staticAdapter struct {
	protocol Protocol
	object   Object
}

func (a staticAdapter) Protocol() Protocol { return a.protocol }

func (a staticAdapter) Lookup(_ context.Context, _ Target, route RouteDecision) (Object, []Source, error) {
	return a.object, []Source{{Protocol: a.protocol, Endpoint: route.Endpoint, Raw: "fixture"}}, nil
}
