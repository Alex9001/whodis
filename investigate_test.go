package whodis

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

type investigationDNSFixture struct {
	records []DNSRecord
	queries map[string][]DNSRecord
	query   func(string, DNSOptions) (*DNSOperationResult, error)
}

func (fixture investigationDNSFixture) Query(_ context.Context, name string, options DNSOptions) (*DNSOperationResult, error) {
	if fixture.query != nil {
		return fixture.query(name, options)
	}
	return &DNSOperationResult{Mode: "query", Messages: []DNSMessage{{Name: name, Answer: fixture.queries[normalizeDNSName(name)]}}}, nil
}
func (fixture investigationDNSFixture) Inventory(context.Context, string, DNSOptions) (*DNSOperationResult, error) {
	return &DNSOperationResult{Mode: "inventory", Inventory: &DNSResult{Records: fixture.records}}, nil
}
func (fixture investigationDNSFixture) Compare(context.Context, string, DNSOptions) (*DNSOperationResult, error) {
	return nil, nil
}
func (fixture investigationDNSFixture) Trace(context.Context, string, DNSOptions) (*DNSOperationResult, error) {
	return nil, nil
}
func (fixture investigationDNSFixture) Transfer(context.Context, string, DNSOptions) (*DNSOperationResult, error) {
	return nil, nil
}

type investigationRegistrationFixture struct{}

func (investigationRegistrationFixture) Lookup(_ context.Context, subject Subject, _ LookupOptions) (RegistrationResult, error) {
	return RegistrationResult{
		Route:  RouteDecision{Protocol: ProtocolRDAP, Endpoint: "https://rdap.example.test"},
		Object: Object{Kind: KindIP, Name: "EXAMPLE-NET", CIDR: []string{"93.184.216.0/24"}, Entities: []Entity{{Roles: []string{"registrant"}, Name: "Amazon Technologies Inc."}}},
	}, nil
}

func investigationHTTPFixture(headers http.Header, body string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     headers.Clone(),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    request,
		}, nil
	})}
}

func TestInvestigationSynthesizesLayeredStackWithoutOverclaimingMail(t *testing.T) {
	domain := "example.test"
	address := "93.184.216.34"
	records := []DNSRecord{
		{Name: domain, Type: "A", Value: address},
		{Name: domain, Type: "NS", Value: "ns001.inceptionwebsites.co."},
		{Name: domain, Type: "MX", Value: "0 example.test."},
		{Name: domain, Type: "TXT", Value: `"v=spf1 ip4:93.184.216.34 include:relay.mailchannels.net ~all"`},
		{Name: "cpanel." + domain, Type: "A", Value: address},
		{Name: "webmail." + domain, Type: "A", Value: address},
		{Name: "cpcontacts." + domain, Type: "A", Value: address},
		{Name: "cpcalendars." + domain, Type: "CNAME", Value: "server." + domain + "."},
		{Name: "server." + domain, Type: "A", Value: address},
	}
	reverse, _ := mdnsReverse(address)
	dns := investigationDNSFixture{records: records, queries: map[string][]DNSRecord{
		normalizeDNSName(reverse): {{Name: reverse, Type: "PTR", Value: "web006.inceptionseo.com."}},
	}}
	provider := newNativeInvestigationProvider(dns, investigationRegistrationFixture{}, NetworkPolicy{}, nil, nil)
	diagnosis := &DiagnosisReport{Domain: domain, DNS: &DNSOperationResult{Inventory: &DNSResult{Records: records}}}
	headers := http.Header{"Server": {"LiteSpeed"}, "X-Redirect-By": {"WordPress"}, "X-Two-Version": {"2.33.0"}}
	report, err := provider.Investigate(context.Background(), Subject{Canonical: domain, RegistrationDomain: domain, Kind: SubjectRegistrableDomain}, diagnosis, InvestigationOptions{
		HTTPClient: investigationHTTPFixture(headers, `<html><link href="/wp-content/plugins/elementor/app.css"></html>`),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"WordPress", "Elementor", "TenWeb", "LiteSpeed", "Amazon Web Services", "Inception Websites", "Same-host mail", "MailChannels", "cPanel-style service layout"} {
		if !hasComponent(report.Components, expected) {
			t.Errorf("missing %q in %#v", expected, report.Components)
		}
	}
	elementor := homepageComponent(report.Components, "Elementor")
	if elementor == nil || elementor.Parent != "WordPress" || elementor.Role != "Page builder" || !containsFold(elementor.Traits, "Page builders") || !containsFold(elementor.Basis, "asset_path") {
		t.Fatalf("granular Elementor component = %#v", elementor)
	}
	if report.Homepage == nil || !report.Homepage.MarkupAnalyzed || !hasFinding(report.Findings, "web.homepage.response") || !hasFinding(report.Findings, "web.security.headers") {
		t.Fatalf("homepage investigation = (%#v, %#v)", report.Homepage, report.Findings)
	}
	if hasComponent(report.Components, "Microsoft 365") {
		t.Fatalf("autodiscover-free local mail was mislabeled Microsoft 365: %#v", report.Components)
	}
	if len(report.Networks) != 1 || report.Networks[0].Provider != "Amazon Web Services" || len(report.Networks[0].PTR) != 1 {
		t.Fatalf("network observations = %#v", report.Networks)
	}
	if !strings.Contains(report.Summary, "Web: ") || !strings.Contains(report.Summary, "Network: Amazon Web Services") {
		t.Fatalf("summary = %q", report.Summary)
	}
}

func TestAutodiscoverAloneDoesNotClaimMicrosoft365OrCPanel(t *testing.T) {
	records := []DNSRecord{{Name: "autodiscover.example.test", Type: "A", Value: "93.184.216.34"}}
	components := newComponentAccumulator()
	components.addDNS("example.test", records)
	for _, name := range []string{"Microsoft 365", "cPanel-style service layout"} {
		if hasComponent(components.values(), name) {
			t.Fatalf("single autodiscover record claimed %s", name)
		}
	}
}

func TestComponentAccumulatorCapsEvidenceWithoutInflatingTheTotal(t *testing.T) {
	components := newComponentAccumulator()
	evidence := make([]InvestigationEvidence, 0, maximumComponentEvidence+2)
	for index := 0; index < maximumComponentEvidence+2; index++ {
		evidence = append(evidence, InvestigationEvidence{Source: "http", Field: "signal", Value: fmt.Sprintf("value-%d", index)})
	}
	component := StackComponent{Category: StackWebApplication, Name: "Example CMS", Confidence: ConfidenceMedium, Evidence: evidence}
	components.add(component)
	components.add(component)
	values := components.values()
	if len(values) != 1 || len(values[0].Evidence) != maximumComponentEvidence || values[0].EvidenceTotal != maximumComponentEvidence+2 {
		t.Fatalf("capped component = %#v", values)
	}
}

func TestExplicitTechnologyHeadersCaptureVersionsAndBasis(t *testing.T) {
	components := newComponentAccumulator()
	components.addWeb(nil, nil, webInvestigationObservation{
		URL: "https://example.test/",
		Headers: http.Header{
			"Server":       {"nginx/1.26.3"},
			"X-Powered-By": {"PHP/8.4.1"},
			"X-Pingback":   {"https://example.test/xmlrpc.php"},
		},
	})
	values := components.values()
	for _, expected := range []struct {
		name, version string
	}{
		{"nginx", "1.26.3"},
		{"PHP", "8.4.1"},
		{"WordPress", ""},
	} {
		component := homepageComponent(values, expected.name)
		if component == nil || component.Version != expected.version || component.Confidence != ConfidenceHigh || !containsFold(component.Basis, "header") {
			t.Errorf("%s component = %#v", expected.name, component)
		}
	}
}

func TestWappalyzerImplicationsCanBeMarkedAsIndirect(t *testing.T) {
	implications := wappalyzerImplicationMap()
	parents := implications["mysql"]
	if !containsFold(parents, "WordPress") || !detectedParent(parents, map[string]wappalyzer.AppInfo{"WordPress:6.8": {}}) {
		t.Fatalf("WordPress implication map = %#v", parents)
	}
}

func TestPublicHomepageEvidenceStripsURLSecretsAndControlCharacters(t *testing.T) {
	parsed, err := url.Parse("https://user:secret@example.test/path?token=private#fragment")
	if err != nil {
		t.Fatal(err)
	}
	if got := sanitizedObservationURL(parsed); got != "https://example.test/path" {
		t.Fatalf("sanitized URL = %q", got)
	}
	if got := cleanHeaderValue("nginx\x1b[31m\r\nspoofed\u202e"); strings.ContainsRune(got, '\x1b') || strings.ContainsRune(got, '\u202e') || strings.ContainsAny(got, "\r\n") {
		t.Fatalf("clean header retained terminal controls: %q", got)
	}
}

func TestDNSProviderSignaturesRequireAHostnameBoundary(t *testing.T) {
	if provider := providerByDNSHost("ns1.evilcloudflare.com", dnsProviderSignatures); provider.name != "" {
		t.Fatalf("lookalike hostname matched %q", provider.name)
	}
	if provider := providerByDNSHost("anna.ns.cloudflare.com", dnsProviderSignatures); provider.name != "Cloudflare DNS" {
		t.Fatalf("Cloudflare nameserver matched %q", provider.name)
	}
}

func TestCPanelPatternCanMatchTheWWWWebAddress(t *testing.T) {
	address := "93.184.216.34"
	components := newComponentAccumulator()
	components.addDNS("example.test", []DNSRecord{
		{Name: "www.example.test", Type: "A", Value: address},
		{Name: "cpanel.example.test", Type: "A", Value: address},
		{Name: "webmail.example.test", Type: "A", Value: address},
		{Name: "whm.example.test", Type: "A", Value: address},
	})
	if !hasComponent(components.values(), "cPanel-style service layout") {
		t.Fatal("co-hosted cPanel service pattern was not detected through www")
	}
}

func TestMailEvidenceCanSuggestGoDaddyManagedMicrosoft365(t *testing.T) {
	components := newComponentAccumulator()
	components.addDNS("example.test", []DNSRecord{
		{Name: "example.test", Type: "MX", Value: "0 example-test.mail.protection.outlook.com."},
		{Name: "example.test", Type: "TXT", Value: `"v=spf1 include:secureserver.net -all"`},
	})
	values := components.values()
	if !hasComponent(values, "Microsoft 365") || !hasComponent(values, "GoDaddy Email") || !hasComponent(values, "GoDaddy-managed Microsoft 365") {
		t.Fatalf("mail inference = %#v", values)
	}
	for _, component := range values {
		if component.Name == "GoDaddy-managed Microsoft 365" && component.Confidence != ConfidenceMedium {
			t.Fatalf("reseller inference confidence = %q", component.Confidence)
		}
	}
}

func TestOTXEnrichmentUsesOptionalKeyAndParsesPassiveDNS(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("X-OTX-API-KEY") != "test-key" {
			t.Errorf("OTX API key = %q", request.Header.Get("X-OTX-API-KEY"))
		}
		if !strings.Contains(request.URL.Path, "/indicators/IPv4/93.184.216.34/passive_dns") {
			t.Errorf("OTX path = %q", request.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{
			"count":2,"passive_dns":[
				{"hostname":"current.example","address":"93.184.216.34","record_type":"A","first":"2025-01-01T00:00:00","last":"2026-01-01T00:00:00","asn":"AS64500 Example"},
				{"hostname":"ignored.example","address":"93.184.216.34","record_type":"MX"}
			]}`)), Request: request}, nil
	})}
	provider := &otxEnrichmentProvider{networkPolicy: NetworkPolicy{AllowPrivate: true, AllowInsecureHTTP: true}, slots: make(chan struct{}, 2)}
	result, err := provider.Enrich(context.Background(), InvestigationSeed{Addresses: []string{"93.184.216.34"}}, EnrichmentOptions{
		Endpoint: "http://127.0.0.1:8080/api/v1", Token: "test-key", Limit: 25, HTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 2 || len(result.Related) != 1 || result.Related[0].Hostname != "current.example" || result.Related[0].FirstSeen.IsZero() {
		t.Fatalf("OTX result = %#v", result)
	}
}

func TestOTXEnrichmentPreservesRateLimitClassification(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusTooManyRequests, Status: "429 Too Many Requests", Header: make(http.Header), Body: http.NoBody, Request: request}, nil
	})}
	provider := &otxEnrichmentProvider{networkPolicy: NetworkPolicy{AllowPrivate: true, AllowInsecureHTTP: true}, slots: make(chan struct{}, 2)}
	_, err := provider.Enrich(context.Background(), InvestigationSeed{Addresses: []string{"93.184.216.34"}}, EnrichmentOptions{
		Endpoint: "http://127.0.0.1:8080/api/v1", HTTPClient: client,
	})
	var lookup *LookupError
	if !errors.As(err, &lookup) || lookup.Kind != ErrorRateLimited {
		t.Fatalf("OTX error = %v, want rate_limited", err)
	}
}

func TestRelatedValidationUsesOnlyTheObservedAddressFamily(t *testing.T) {
	var requested DNSOptions
	dns := investigationDNSFixture{query: func(name string, options DNSOptions) (*DNSOperationResult, error) {
		requested = options
		return &DNSOperationResult{Messages: []DNSMessage{{Name: name, Answer: []DNSRecord{{Name: name, Type: "A", Value: "93.184.216.34"}}}}}, nil
	}}
	provider := &nativeInvestigationProvider{dns: dns}
	observations := []RelatedObservation{{Hostname: "current.example", Address: "93.184.216.34", Current: RelatedUnknown}}
	provider.validateRelated(context.Background(), observations, DNSOptions{Globalping: true})
	if observations[0].Current != RelatedCurrent || strings.Join(requested.Types, ",") != "A" || requested.Globalping {
		t.Fatalf("related validation = (%#v, %#v)", observations[0], requested)
	}
}

func TestRelatedValidationDoesNotCallAnIncompleteLookupStale(t *testing.T) {
	dns := investigationDNSFixture{query: func(name string, _ DNSOptions) (*DNSOperationResult, error) {
		return &DNSOperationResult{Messages: []DNSMessage{{Name: name}}}, errors.New("resolver interrupted")
	}}
	provider := &nativeInvestigationProvider{dns: dns}
	observations := []RelatedObservation{{Hostname: "uncertain.example", Address: "2001:4860:4860::8888", Current: RelatedUnknown}}
	provider.validateRelated(context.Background(), observations, DNSOptions{})
	if observations[0].Current != RelatedUnknown {
		t.Fatalf("incomplete lookup state = %q, want unknown", observations[0].Current)
	}
}

func TestServerHeaderClassifiesKnownEdgeServices(t *testing.T) {
	components := newComponentAccumulator()
	components.addWeb(nil, nil, webInvestigationObservation{URL: "https://example.test/", Headers: http.Header{"Server": {"cloudflare"}}})
	values := components.values()
	if !hasComponent(values, "Cloudflare") || values[0].Category != StackEdge {
		t.Fatalf("edge header components = %#v", values)
	}
}

func TestInvestigationLinkRequiresSafeTemplate(t *testing.T) {
	link, err := resolveInvestigationLink("https://intel.example/{type}/{value}", "ip", "2001:db8::1")
	if err != nil || !strings.Contains(link.URL, "2001:db8::1") && !strings.Contains(link.URL, "2001:db8:%3A1") {
		t.Fatalf("link = %#v, %v", link, err)
	}
	if _, err := resolveInvestigationLink("file:///tmp/{value}", "ip", "192.0.2.1"); err == nil {
		t.Fatal("unsafe link template was accepted")
	}
}

func TestInvestigationLinkCatalogIsTypedSafeAndDeterministic(t *testing.T) {
	providers := AvailableInvestigationLinkProviders()
	if len(providers) != 14 || providers[0].ID != "otx" || providers[len(providers)-1].ID != "ipinfo" {
		t.Fatalf("provider catalog = %#v", providers)
	}
	seen := make(map[string]bool)
	for _, provider := range providers {
		if seen[provider.ID] || provider.ID == "" || provider.Label == "" || provider.Purpose == "" || len(provider.Targets) == 0 {
			t.Fatalf("invalid provider descriptor = %#v", provider)
		}
		seen[provider.ID] = true
	}
	providers[0].Targets[0] = "mutated"
	if AvailableInvestigationLinkProviders()[0].Targets[0] != "domain" {
		t.Fatal("provider catalog returned mutable target storage")
	}

	core, err := selectedInvestigationLinkDefinitions(nil)
	if err != nil || len(core) != 8 {
		t.Fatalf("core definitions = %d, %v", len(core), err)
	}
	domainLinks := buildInvestigationLinks(core, "domain", "example.com")
	ipv4Links := buildInvestigationLinks(core, "ip", "8.8.8.8")
	ipv6Links := buildInvestigationLinks(core, "ip", "2606:4700:4700::1111")
	if len(domainLinks) != 6 || len(ipv4Links) != 4 || len(ipv6Links) != 3 {
		t.Fatalf("core links = domain:%d ipv4:%d ipv6:%d", len(domainLinks), len(ipv4Links), len(ipv6Links))
	}
	for _, link := range append(append(domainLinks, ipv4Links...), ipv6Links...) {
		parsed, parseErr := url.Parse(link.URL)
		if parseErr != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
			t.Fatalf("unsafe generated link = %#v, %v", link, parseErr)
		}
	}
	if domainLinks[4].URL != "https://crt.sh/?q=%25.example.com" || ipv4Links[3].URL != "https://platform.censys.io/search?q=8.8.8.8" {
		t.Fatalf("typed URL builders = (%q, %q)", domainLinks[4].URL, ipv4Links[3].URL)
	}
}

func TestInvestigationLinkSelectionValidation(t *testing.T) {
	for _, selection := range [][]string{{"all", "otx"}, {"core", "virustotal"}, {"off", "otx"}, {"unknown"}} {
		if err := ValidateInvestigationOptions(InvestigationOptions{LinkProviders: selection}); err == nil {
			t.Fatalf("invalid selection accepted: %#v", selection)
		}
	}
	if err := ValidateInvestigationOptions(InvestigationOptions{LinkProviders: []string{"off"}, ExternalLinkTemplate: "off"}); err == nil {
		t.Fatal("conflicting off controls were accepted")
	}
	selected, err := selectedInvestigationLinkDefinitions([]string{"ipinfo,otx", "ipinfo"})
	if err != nil || len(selected) != 2 || selected[0].provider.ID != "otx" || selected[1].provider.ID != "ipinfo" {
		t.Fatalf("explicit selection = %#v, %v", selected, err)
	}
}

func hasComponent(components []StackComponent, name string) bool {
	for _, component := range components {
		if component.Name == name {
			return true
		}
	}
	return false
}

func mdnsReverse(address string) (string, error) {
	return mdns.ReverseAddr(address)
}
