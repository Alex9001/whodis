package whodis

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

const (
	defaultRelatedLimit             = 25
	maximumRelatedLimit             = 100
	maximumInvestigationBody        = 1 << 20
	maximumEnrichmentResponse       = 4 << 20
	defaultOTXEndpoint              = "https://otx.alienvault.com/api/v1"
	defaultInvestigationLink        = "https://otx.alienvault.com/indicator/{type}/{value}"
	maximumInvestigationRedirects   = 5
	maximumRelatedValidationWorkers = 8
)

// Confidence describes the strength of an explainable investigation claim.
// It is deliberately categorical: callers should inspect Evidence rather than
// treating confidence as an opaque score.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// StackCategory identifies the role a detected component plays.
type StackCategory string

const (
	StackWebApplication StackCategory = "web_application"
	StackFramework      StackCategory = "framework"
	StackWebServer      StackCategory = "web_server"
	StackEdge           StackCategory = "edge"
	StackHosting        StackCategory = "hosting"
	StackNetwork        StackCategory = "network"
	StackDNS            StackCategory = "dns"
	StackMail           StackCategory = "mail"
	StackAnalytics      StackCategory = "analytics"
	StackSecurity       StackCategory = "security"
	StackOther          StackCategory = "other"
)

// RelatedState says whether a passive observation still resolves to the
// address on which it was observed.
type RelatedState string

const (
	RelatedCurrent RelatedState = "current"
	RelatedStale   RelatedState = "stale"
	RelatedUnknown RelatedState = "unknown"
)

// InvestigationEvidence is one bounded public observation supporting a stack
// component. Values are short display-safe excerpts, never response bodies.
type InvestigationEvidence struct {
	Source  string `json:"source" yaml:"source"`
	Subject string `json:"subject,omitempty" yaml:"subject,omitempty"`
	Field   string `json:"field" yaml:"field"`
	Value   string `json:"value" yaml:"value"`
}

// StackComponent is one technology or provider and the evidence for its role.
type StackComponent struct {
	Category   StackCategory           `json:"category" yaml:"category"`
	Name       string                  `json:"name" yaml:"name"`
	Role       string                  `json:"role,omitempty" yaml:"role,omitempty"`
	Confidence Confidence              `json:"confidence" yaml:"confidence"`
	Summary    string                  `json:"summary,omitempty" yaml:"summary,omitempty"`
	Evidence   []InvestigationEvidence `json:"evidence,omitempty" yaml:"evidence,omitempty"`
}

// InvestigationLink is a resolved, user-opened pivot. Whodis never opens a
// link or contacts its destination without an explicit user action.
type InvestigationLink struct {
	Label string `json:"label" yaml:"label"`
	Type  string `json:"type" yaml:"type"`
	Value string `json:"value" yaml:"value"`
	URL   string `json:"url" yaml:"url"`
}

// NetworkObservation attributes one public web address without conflating the
// network operator with the site's customer-facing hosting provider.
type NetworkObservation struct {
	Address     string              `json:"address" yaml:"address"`
	PTR         []string            `json:"ptr,omitempty" yaml:"ptr,omitempty"`
	NetworkName string              `json:"network_name,omitempty" yaml:"network_name,omitempty"`
	Operator    string              `json:"operator,omitempty" yaml:"operator,omitempty"`
	Provider    string              `json:"provider,omitempty" yaml:"provider,omitempty"`
	CIDR        []string            `json:"cidr,omitempty" yaml:"cidr,omitempty"`
	Country     string              `json:"country,omitempty" yaml:"country,omitempty"`
	Source      string              `json:"source,omitempty" yaml:"source,omitempty"`
	Links       []InvestigationLink `json:"links,omitempty" yaml:"links,omitempty"`
}

// RelatedObservation is one historical provider observation, optionally
// checked against current DNS. It is not an ownership assertion.
type RelatedObservation struct {
	Provider      string       `json:"provider" yaml:"provider"`
	Hostname      string       `json:"hostname" yaml:"hostname"`
	Address       string       `json:"address" yaml:"address"`
	RecordType    string       `json:"record_type,omitempty" yaml:"record_type,omitempty"`
	ASN           string       `json:"asn,omitempty" yaml:"asn,omitempty"`
	FirstSeen     time.Time    `json:"first_seen,omitempty" yaml:"first_seen,omitempty"`
	LastSeen      time.Time    `json:"last_seen,omitempty" yaml:"last_seen,omitempty"`
	Current       RelatedState `json:"current" yaml:"current"`
	CurrentValues []string     `json:"current_values,omitempty" yaml:"current_values,omitempty"`
}

// InvestigationReport is the renderer-independent technology and
// infrastructure profile attached to an investigate report.
type InvestigationReport struct {
	Domain         string               `json:"domain" yaml:"domain"`
	Summary        string               `json:"summary" yaml:"summary"`
	Components     []StackComponent     `json:"components,omitempty" yaml:"components,omitempty"`
	Networks       []NetworkObservation `json:"networks,omitempty" yaml:"networks,omitempty"`
	Related        []RelatedObservation `json:"related,omitempty" yaml:"related,omitempty"`
	RelatedTotal   int                  `json:"related_total,omitempty" yaml:"related_total,omitempty"`
	Links          []InvestigationLink  `json:"links,omitempty" yaml:"links,omitempty"`
	Warnings       []string             `json:"warnings,omitempty" yaml:"warnings,omitempty"`
	ProviderErrors []OperationError     `json:"-" yaml:"-"`
}

// InvestigationOptions controls bounded local profiling and explicitly named
// third-party enrichments. Tokens and clients are never serialized.
type InvestigationOptions struct {
	DNS                  DNSOptions   `json:"dns,omitempty" yaml:"dns,omitempty"`
	Enrichments          []string     `json:"enrichments,omitempty" yaml:"enrichments,omitempty"`
	RelatedLimit         int          `json:"related_limit,omitempty" yaml:"related_limit,omitempty"`
	ExternalLinkTemplate string       `json:"external_link_template,omitempty" yaml:"external_link_template,omitempty"`
	OTXEndpoint          string       `json:"otx_endpoint,omitempty" yaml:"otx_endpoint,omitempty"`
	OTXToken             string       `json:"-" yaml:"-"`
	HTTPClient           *http.Client `json:"-" yaml:"-"`
}

// InvestigationSeed is the public, bounded input given to enrichment
// providers. Addresses are public representative A/AAAA results only.
type InvestigationSeed struct {
	Subject   Subject  `json:"subject" yaml:"subject"`
	Addresses []string `json:"addresses" yaml:"addresses"`
}

// EnrichmentOptions are shared controls passed to a named provider.
type EnrichmentOptions struct {
	Limit      int
	Endpoint   string
	Token      string
	HTTPClient *http.Client
}

// EnrichmentResult is a provider's bounded set of historical observations.
type EnrichmentResult struct {
	Related  []RelatedObservation
	Total    int
	Warnings []string
}

// EnrichmentProvider is the library extension point for passive intelligence
// sources. Providers are registered by Name through EngineOptions.
type EnrichmentProvider interface {
	Name() string
	Enrich(context.Context, InvestigationSeed, EnrichmentOptions) (EnrichmentResult, error)
}

// ValidateInvestigationOptions checks configuration that can be validated
// without contacting a provider. Engine execution additionally applies the
// configured network policy to custom endpoints.
func ValidateInvestigationOptions(options InvestigationOptions) error {
	if options.RelatedLimit < 0 || options.RelatedLimit > maximumRelatedLimit {
		return fmt.Errorf("related limit must be 0 (default) or between 1 and %d", maximumRelatedLimit)
	}
	if template := strings.TrimSpace(options.ExternalLinkTemplate); template != "" && !strings.EqualFold(template, "off") {
		if _, err := resolveInvestigationLink(template, "domain", "example.com"); err != nil {
			return fmt.Errorf("invalid investigation link template: %w", err)
		}
	}
	if endpoint := strings.TrimSpace(options.OTXEndpoint); endpoint != "" {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.Scheme != "https" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return fmt.Errorf("OTX endpoint must be an HTTPS URL without credentials, query, or fragment")
		}
	}
	return nil
}

type nativeInvestigationProvider struct {
	dns               DNSProvider
	registration      RegistrationProvider
	networkPolicy     NetworkPolicy
	fingerprinter     *wappalyzer.Wappalyze
	enrichments       map[string]EnrichmentProvider
	registrationSlots chan struct{}
}

func newNativeInvestigationProvider(dns DNSProvider, registration RegistrationProvider, policy NetworkPolicy, enrichments map[string]EnrichmentProvider, registrationSlots chan struct{}) InvestigationProvider {
	registered := make(map[string]EnrichmentProvider, len(enrichments)+1)
	for name, provider := range enrichments {
		if provider != nil {
			registered[strings.ToLower(strings.TrimSpace(name))] = provider
		}
	}
	if _, exists := registered["otx"]; !exists {
		registered["otx"] = &otxEnrichmentProvider{networkPolicy: policy, slots: make(chan struct{}, 2)}
	}
	fingerprinter, _ := wappalyzer.New()
	if registrationSlots == nil {
		registrationSlots = make(chan struct{}, 4)
	}
	return &nativeInvestigationProvider{dns: dns, registration: registration, networkPolicy: policy, fingerprinter: fingerprinter, enrichments: registered, registrationSlots: registrationSlots}
}

func (provider *nativeInvestigationProvider) Investigate(ctx context.Context, subject Subject, diagnosis *DiagnosisReport, options InvestigationOptions) (*InvestigationReport, error) {
	domain := normalizeDNSName(subject.Canonical)
	report := &InvestigationReport{Domain: domain}
	limit := options.RelatedLimit
	if limit == 0 {
		limit = defaultRelatedLimit
	}
	if limit < 1 || limit > maximumRelatedLimit {
		return nil, lookupError(ErrorInvalidInput, fmt.Sprintf("related limit must be between 1 and %d", maximumRelatedLimit), nil)
	}
	template := strings.TrimSpace(options.ExternalLinkTemplate)
	if template == "" {
		template = defaultInvestigationLink
	}
	if !strings.EqualFold(template, "off") {
		link, err := resolveInvestigationLink(template, "domain", domain)
		if err != nil {
			return nil, lookupError(ErrorInvalidInput, "invalid investigation link template", err)
		}
		report.Links = append(report.Links, link)
	}

	records := diagnosisRecords(diagnosis)
	addresses := representativeAddresses(records, domain, maximumProbeAddresses)
	addresses = publicInvestigationAddresses(addresses)

	var web webInvestigationObservation
	var webErr error
	var networks []NetworkObservation
	var networkWarnings []string
	var group sync.WaitGroup
	group.Add(2)
	go func() {
		defer group.Done()
		web, webErr = provider.fetchWeb(ctx, domain, options.HTTPClient)
	}()
	go func() {
		defer group.Done()
		networks, networkWarnings = provider.inspectNetworks(ctx, addresses, options.DNS, template)
	}()
	group.Wait()
	report.Networks = networks
	report.Warnings = append(report.Warnings, networkWarnings...)
	if webErr != nil {
		report.Warnings = append(report.Warnings, "web fingerprint: "+webErr.Error())
	}

	components := newComponentAccumulator()
	components.addWeb(provider.fingerprinter, web)
	components.addDNS(domain, records)
	components.addNetworks(networks)
	report.Components = components.values()
	report.Summary = investigationSummary(report.Components)

	seed := InvestigationSeed{Subject: subject, Addresses: addresses}
	for _, requested := range uniqueLowerStrings(options.Enrichments) {
		enrichment := provider.enrichments[requested]
		if enrichment == nil {
			return nil, lookupError(ErrorInvalidInput, fmt.Sprintf("unknown enrichment provider %q", requested), nil)
		}
		providerOptions := EnrichmentOptions{Limit: limit, HTTPClient: options.HTTPClient}
		if requested == "otx" {
			providerOptions.Endpoint, providerOptions.Token = options.OTXEndpoint, options.OTXToken
		}
		result, enrichErr := enrichment.Enrich(ctx, seed, providerOptions)
		for _, related := range result.Related {
			hostname := normalizeDNSName(related.Hostname)
			if hostname == domain || hostname == "www."+domain {
				continue
			}
			report.Related = append(report.Related, related)
		}
		if result.Total > 0 {
			report.RelatedTotal += result.Total
		}
		report.Warnings = append(report.Warnings, result.Warnings...)
		if enrichErr != nil {
			report.ProviderErrors = appendOperationError(report.ProviderErrors, OperationInvestigate, enrichment.Name(), enrichErr)
		}
	}
	if len(report.Related) > 0 {
		report.Related = deduplicateRelated(report.Related)
		sortRelated(report.Related)
		if len(report.Related) > limit {
			report.Related = report.Related[:limit]
		}
		provider.validateRelated(ctx, report.Related, options.DNS)
		sortRelated(report.Related)
	}
	if report.RelatedTotal < len(report.Related) {
		report.RelatedTotal = len(report.Related)
	}
	report.Warnings = uniqueStrings(report.Warnings)
	return report, nil
}

func diagnosisRecords(diagnosis *DiagnosisReport) []DNSRecord {
	if diagnosis == nil || diagnosis.DNS == nil || diagnosis.DNS.Inventory == nil {
		return nil
	}
	return append([]DNSRecord(nil), diagnosis.DNS.Inventory.Records...)
}

func publicInvestigationAddresses(addresses []string) []string {
	result := make([]string, 0, len(addresses))
	for _, value := range addresses {
		address, err := netip.ParseAddr(strings.TrimSpace(value))
		if err == nil && publicNetworkAddress(address) {
			result = append(result, address.Unmap().String())
		}
	}
	return uniqueStrings(result)
}

type webInvestigationObservation struct {
	URL     string
	Status  int
	Headers http.Header
	Body    []byte
}

func (provider *nativeInvestigationProvider) fetchWeb(ctx context.Context, domain string, supplied *http.Client) (webInvestigationObservation, error) {
	client := supplied
	if client == nil {
		client = provider.safeHTTPClient()
	} else {
		copy := *client
		if copy.Timeout == 0 || copy.Timeout > 8*time.Second {
			copy.Timeout = 8 * time.Second
		}
		client = &copy
	}
	var failures []string
	for _, endpoint := range []string{"https://" + domain + "/", "http://" + domain + "/"} {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		request.Header.Set("User-Agent", productUserAgent())
		request.Header.Set("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1")
		response, err := client.Do(request)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maximumInvestigationBody))
		_ = response.Body.Close()
		if readErr != nil {
			return webInvestigationObservation{}, readErr
		}
		finalURL := endpoint
		if response.Request != nil && response.Request.URL != nil {
			finalURL = response.Request.URL.String()
		}
		return webInvestigationObservation{URL: finalURL, Status: response.StatusCode, Headers: response.Header.Clone(), Body: body}, nil
	}
	return webInvestigationObservation{}, errors.New(strings.Join(uniqueStrings(failures), "; "))
}

func (provider *nativeInvestigationProvider) safeHTTPClient() *http.Client {
	return safeInvestigationHTTPClient(provider.networkPolicy)
}

func safeInvestigationHTTPClient(policy NetworkPolicy) *http.Client {
	transport := &http.Transport{
		TLSHandshakeTimeout:    4 * time.Second,
		ResponseHeaderTimeout:  5 * time.Second,
		MaxResponseHeaderBytes: 1 << 20,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			addresses, err := permittedAutomaticAddresses(ctx, host, policy)
			if err != nil {
				return nil, err
			}
			dialer := &net.Dialer{Timeout: 4 * time.Second}
			var lastErr error
			for _, candidate := range addresses {
				connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
				if dialErr == nil {
					return connection, nil
				}
				lastErr = dialErr
			}
			return nil, lastErr
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= maximumInvestigationRedirects {
			return errors.New("too many redirects")
		}
		return validateAutomaticHost(request.Context(), request.URL.Hostname(), policy)
	}
	return client
}

func readLimitedBody(body io.Reader, maximum int64) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(body, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > maximum {
		return nil, fmt.Errorf("response body exceeded %d bytes", maximum)
	}
	return payload, nil
}

func (provider *nativeInvestigationProvider) inspectNetworks(ctx context.Context, addresses []string, dnsOptions DNSOptions, template string) ([]NetworkObservation, []string) {
	type completed struct {
		observation NetworkObservation
		warnings    []string
	}
	results := make(chan completed, len(addresses))
	var group sync.WaitGroup
	for _, address := range addresses {
		address := address
		group.Add(1)
		go func() {
			defer group.Done()
			observation := NetworkObservation{Address: address}
			var warnings []string
			subject := Subject{Original: address, Canonical: address, Kind: SubjectIP}
			select {
			case provider.registrationSlots <- struct{}{}:
			case <-ctx.Done():
				results <- completed{observation: observation, warnings: []string{fmt.Sprintf("IP registration %s: %v", address, ctx.Err())}}
				return
			}
			registration, err := provider.registration.Lookup(ctx, subject, LookupOptions{})
			<-provider.registrationSlots
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("IP registration %s: %v", address, err))
			} else {
				observation.NetworkName = registration.Object.Name
				observation.Operator = registrationOperator(registration.Object)
				observation.Provider = canonicalNetworkProvider(observation.Operator, observation.NetworkName)
				observation.CIDR = append([]string(nil), registration.Object.CIDR...)
				observation.Country = registration.Object.Country
				observation.Source = string(registration.Route.Protocol)
			}
			reverse, reverseErr := mdns.ReverseAddr(address)
			if reverseErr == nil {
				queryOptions := dnsOptions
				queryOptions.Types = []string{"PTR"}
				// Remote probes are scoped to the requested site. Do not disclose
				// discovered infrastructure names to them as a side effect.
				queryOptions.Globalping = false
				answer, queryErr := provider.dns.Query(ctx, reverse, queryOptions)
				if queryErr != nil {
					warnings = append(warnings, fmt.Sprintf("PTR %s: %v", address, queryErr))
				} else {
					for _, record := range dnsOperationRecords(answer) {
						if record.Type == "PTR" {
							observation.PTR = append(observation.PTR, normalizeDNSName(record.Value))
						}
					}
					observation.PTR = uniqueStrings(observation.PTR)
				}
			}
			if !strings.EqualFold(strings.TrimSpace(template), "off") {
				if link, linkErr := resolveInvestigationLink(template, "ip", address); linkErr == nil {
					observation.Links = append(observation.Links, link)
				}
			}
			results <- completed{observation: observation, warnings: warnings}
		}()
	}
	group.Wait()
	close(results)
	var observations []NetworkObservation
	var warnings []string
	for result := range results {
		observations = append(observations, result.observation)
		warnings = append(warnings, result.warnings...)
	}
	sort.Slice(observations, func(i, j int) bool { return observations[i].Address < observations[j].Address })
	return observations, warnings
}

func registrationOperator(object Object) string {
	for _, role := range []string{"registrant", "administrative", "technical"} {
		for _, entity := range object.Entities {
			if !hasRole(entity.Roles, role) {
				continue
			}
			if strings.TrimSpace(entity.Organization) != "" {
				return strings.TrimSpace(entity.Organization)
			}
			if strings.TrimSpace(entity.Name) != "" {
				return strings.TrimSpace(entity.Name)
			}
		}
	}
	for _, entity := range object.Entities {
		if strings.TrimSpace(entity.Organization) != "" {
			return strings.TrimSpace(entity.Organization)
		}
		if strings.TrimSpace(entity.Name) != "" {
			return strings.TrimSpace(entity.Name)
		}
	}
	return strings.TrimSpace(object.Name)
}

func canonicalNetworkProvider(operator, network string) string {
	value := strings.ToLower(operator + " " + network)
	signatures := []struct{ match, name string }{
		{"amazon", "Amazon Web Services"}, {"cloudflare", "Cloudflare"}, {"google", "Google Cloud"},
		{"microsoft", "Microsoft Azure"}, {"akamai", "Akamai"}, {"fastly", "Fastly"},
		{"digitalocean", "DigitalOcean"}, {"hetzner", "Hetzner"}, {"ovh", "OVHcloud"},
		{"linode", "Akamai Connected Cloud"}, {"oracle", "Oracle Cloud"}, {"vultr", "Vultr"},
	}
	for _, signature := range signatures {
		if strings.Contains(value, signature.match) {
			return signature.name
		}
	}
	return strings.TrimSpace(operator)
}

func resolveInvestigationLink(template, targetType, value string) (InvestigationLink, error) {
	template = strings.TrimSpace(template)
	if !strings.Contains(template, "{type}") || !strings.Contains(template, "{value}") {
		return InvestigationLink{}, errors.New("template must contain {type} and {value}")
	}
	resolved := strings.ReplaceAll(template, "{type}", targetType)
	resolved = strings.ReplaceAll(resolved, "{value}", url.PathEscape(value))
	parsed, err := url.Parse(resolved)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
		return InvestigationLink{}, errors.New("template must resolve to an HTTPS URL without credentials")
	}
	label := "Open in investigation service"
	if strings.EqualFold(parsed.Hostname(), "otx.alienvault.com") {
		label = "Open in AlienVault OTX"
	}
	return InvestigationLink{Label: label, Type: targetType, Value: value, URL: parsed.String()}, nil
}

type componentAccumulator struct{ valuesByKey map[string]*StackComponent }

func newComponentAccumulator() *componentAccumulator {
	return &componentAccumulator{valuesByKey: make(map[string]*StackComponent)}
}

func (accumulator *componentAccumulator) add(component StackComponent) {
	component.Name = strings.TrimSpace(component.Name)
	if component.Name == "" {
		return
	}
	key := string(component.Category) + "\x00" + strings.ToLower(component.Name) + "\x00" + strings.ToLower(component.Role)
	if existing := accumulator.valuesByKey[key]; existing != nil {
		if confidenceRank(component.Confidence) > confidenceRank(existing.Confidence) {
			existing.Confidence = component.Confidence
		}
		if existing.Summary == "" {
			existing.Summary = component.Summary
		}
		for _, evidence := range component.Evidence {
			existing.Evidence = appendUniqueEvidence(existing.Evidence, evidence)
		}
		return
	}
	copy := component
	copy.Evidence = append([]InvestigationEvidence(nil), component.Evidence...)
	accumulator.valuesByKey[key] = &copy
}

func (accumulator *componentAccumulator) addWeb(fingerprinter *wappalyzer.Wappalyze, web webInvestigationObservation) {
	if web.URL == "" {
		return
	}
	if fingerprinter != nil {
		identified := fingerprinter.FingerprintWithInfo(web.Headers, web.Body)
		names := make([]string, 0, len(identified))
		for name := range identified {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			info := identified[name]
			displayName, version, _ := strings.Cut(name, ":")
			category, role := fingerprintCategory(info.Categories)
			summary := "Matched bounded HTTP headers or homepage markup."
			if version != "" {
				summary += " Fingerprint version: " + truncateEvidence(version) + "."
			}
			accumulator.add(StackComponent{Category: category, Name: displayName, Role: role, Confidence: ConfidenceMedium,
				Summary:  summary,
				Evidence: []InvestigationEvidence{{Source: "http", Subject: web.URL, Field: "technology fingerprint", Value: name}}})
		}
	}
	server := cleanHeaderValue(web.Headers.Get("Server"))
	if server != "" {
		name := strings.TrimSpace(strings.SplitN(server, "/", 2)[0])
		category, role := StackWebServer, "Web server"
		switch {
		case strings.Contains(strings.ToLower(server), "cloudflare"):
			category, name, role = StackEdge, "Cloudflare", "Edge/CDN"
		case strings.Contains(strings.ToLower(server), "cloudfront"):
			category, name, role = StackEdge, "Amazon CloudFront", "Edge/CDN"
		case strings.Contains(strings.ToLower(server), "akamai"):
			category, name, role = StackEdge, "Akamai", "Edge/CDN"
		}
		accumulator.add(StackComponent{Category: category, Name: name, Role: role, Confidence: ConfidenceHigh,
			Summary:  "The HTTP response explicitly identified this software or edge service.",
			Evidence: []InvestigationEvidence{{Source: "http", Subject: web.URL, Field: "Server", Value: server}}})
	}
	redirectBy := cleanHeaderValue(web.Headers.Get("X-Redirect-By"))
	if strings.Contains(strings.ToLower(redirectBy), "wordpress") {
		accumulator.add(StackComponent{Category: StackWebApplication, Name: "WordPress", Role: "CMS", Confidence: ConfidenceHigh,
			Evidence: []InvestigationEvidence{{Source: "http", Subject: web.URL, Field: "X-Redirect-By", Value: redirectBy}}})
	}
	for key, values := range web.Headers {
		lower := strings.ToLower(key)
		if !strings.HasPrefix(lower, "x-two-") {
			continue
		}
		accumulator.add(StackComponent{Category: StackWebApplication, Name: "TenWeb", Role: "WordPress optimization", Confidence: ConfidenceHigh,
			Summary:  "TenWeb-specific response headers were present.",
			Evidence: []InvestigationEvidence{{Source: "http", Subject: web.URL, Field: key, Value: cleanHeaderValue(strings.Join(values, ", "))}}})
	}
	body := strings.ToLower(string(web.Body))
	if strings.Contains(body, "/wp-content/") || strings.Contains(body, "/wp-includes/") {
		accumulator.add(StackComponent{Category: StackWebApplication, Name: "WordPress", Role: "CMS", Confidence: ConfidenceHigh,
			Evidence: []InvestigationEvidence{{Source: "http", Subject: web.URL, Field: "homepage markup", Value: "WordPress asset paths"}}})
	}
	if strings.Contains(body, "elementor") {
		accumulator.add(StackComponent{Category: StackWebApplication, Name: "Elementor", Role: "Page builder", Confidence: ConfidenceMedium,
			Evidence: []InvestigationEvidence{{Source: "http", Subject: web.URL, Field: "homepage markup", Value: "Elementor asset markers"}}})
	}
}

func fingerprintCategory(categories []string) (StackCategory, string) {
	joined := strings.ToLower(strings.Join(categories, " "))
	switch {
	case strings.Contains(joined, "web server"):
		return StackWebServer, "Web server"
	case strings.Contains(joined, "cdn") || strings.Contains(joined, "reverse prox"):
		return StackEdge, "Edge/CDN"
	case strings.Contains(joined, "cms"):
		return StackWebApplication, "CMS"
	case strings.Contains(joined, "page builder"):
		return StackWebApplication, "Page builder"
	case strings.Contains(joined, "javascript framework") || strings.Contains(joined, "web framework"):
		return StackFramework, "Framework"
	case strings.Contains(joined, "analytics") || strings.Contains(joined, "rum"):
		return StackAnalytics, "Analytics"
	case strings.Contains(joined, "security") || strings.Contains(joined, "waf"):
		return StackSecurity, "Security"
	case strings.Contains(joined, "hosting") || strings.Contains(joined, "paas"):
		return StackHosting, "Hosting platform"
	default:
		return StackOther, firstString(categories, "Web technology")
	}
}

func (accumulator *componentAccumulator) addDNS(domain string, records []DNSRecord) {
	webAddresses := append(addressesForDNSName(records, domain), addressesForDNSName(records, "www."+domain)...)
	webAddresses = uniqueStrings(webAddresses)
	serviceLabels := make(map[string]bool)
	var microsoftMailEvidence, godaddyMailEvidence []InvestigationEvidence
	for _, record := range records {
		name := normalizeDNSName(record.Name)
		value := strings.Trim(strings.TrimSpace(record.Value), "\"")
		switch strings.ToUpper(record.Type) {
		case "NS":
			target := dnsRecordValueTarget(record)
			if provider := providerByDNSHost(target, dnsProviderSignatures); provider.name != "" {
				accumulator.add(provider.component("Authoritative DNS", "dns", name, record.Type, target))
			}
		case "MX":
			target := dnsRecordValueTarget(record)
			if provider := providerByDNSHost(target, mailProviderSignatures); provider.name != "" {
				accumulator.add(provider.component("Inbound mail", "dns", name, record.Type, target))
				evidence := InvestigationEvidence{Source: "dns", Subject: name, Field: record.Type, Value: truncateEvidence(target)}
				if provider.name == "Microsoft 365" {
					microsoftMailEvidence = append(microsoftMailEvidence, evidence)
				}
				if provider.name == "GoDaddy Email" {
					godaddyMailEvidence = append(godaddyMailEvidence, evidence)
				}
			}
			if target == domain || intersectsStrings(webAddresses, addressesForDNSName(records, target)) {
				accumulator.add(StackComponent{Category: StackMail, Name: "Same-host mail", Role: "Inbound mail", Confidence: ConfidenceHigh,
					Summary:  "The MX target resolves with the website rather than to a separate mail platform.",
					Evidence: []InvestigationEvidence{{Source: "dns", Subject: name, Field: "MX", Value: record.Value}}})
			}
		case "CNAME":
			target := dnsRecordValueTarget(record)
			if provider := providerByDNSHost(target, cnameProviderSignatures); provider.name != "" {
				accumulator.add(provider.component(provider.role, "dns", name, record.Type, target))
			}
		case "TXT":
			lower := strings.ToLower(value)
			for _, signature := range txtProviderSignatures {
				if strings.Contains(lower, signature.match) {
					accumulator.add(signature.component(signature.role, "dns", name, record.Type, truncateEvidence(value)))
					evidence := InvestigationEvidence{Source: "dns", Subject: name, Field: record.Type, Value: truncateEvidence(value)}
					if signature.name == "Microsoft 365" {
						microsoftMailEvidence = append(microsoftMailEvidence, evidence)
					}
					if signature.name == "GoDaddy Email" {
						godaddyMailEvidence = append(godaddyMailEvidence, evidence)
					}
				}
			}
		}
		if inDNSZone(name, domain) {
			label := strings.TrimSuffix(name, "."+domain)
			switch label {
			case "cpanel", "webmail", "whm", "cpcontacts", "cpcalendars":
				if intersectsStrings(webAddresses, addressesForDNSName(records, name)) {
					serviceLabels[label] = true
				}
			}
		}
	}
	if len(microsoftMailEvidence) > 0 && len(godaddyMailEvidence) > 0 {
		accumulator.add(StackComponent{Category: StackMail, Name: "GoDaddy-managed Microsoft 365", Role: "Mail reseller", Confidence: ConfidenceMedium,
			Summary:  "DNS publishes both Microsoft 365 delivery/authorization and GoDaddy mail authorization; this suggests, but does not prove, a GoDaddy-managed Microsoft 365 setup.",
			Evidence: append(microsoftMailEvidence, godaddyMailEvidence...)})
	}
	if len(serviceLabels) >= 3 {
		labels := make([]string, 0, len(serviceLabels))
		for label := range serviceLabels {
			labels = append(labels, label)
		}
		sort.Strings(labels)
		accumulator.add(StackComponent{Category: StackHosting, Name: "cPanel-style service layout", Role: "Control panel", Confidence: ConfidenceMedium,
			Summary:  "Multiple conventional cPanel service names resolve with the website; this is a strong pattern, not direct product confirmation.",
			Evidence: []InvestigationEvidence{{Source: "dns", Subject: domain, Field: "service names", Value: strings.Join(labels, ", ")}}})
	}
}

func (accumulator *componentAccumulator) addNetworks(networks []NetworkObservation) {
	for _, network := range networks {
		if network.Provider != "" {
			value := network.Operator
			if value == "" {
				value = network.NetworkName
			}
			accumulator.add(StackComponent{Category: StackNetwork, Name: network.Provider, Role: "Network owner", Confidence: ConfidenceHigh,
				Summary:  "IP registration identifies the network operator; this does not prove a direct customer relationship.",
				Evidence: []InvestigationEvidence{{Source: "rdap", Subject: network.Address, Field: "network registrant", Value: truncateEvidence(value)}}})
		}
		for _, ptr := range network.PTR {
			if provider := providerByDNSHost(ptr, ptrProviderSignatures); provider.name != "" {
				accumulator.add(provider.component(provider.role, "ptr", network.Address, "PTR", ptr))
			}
		}
	}
}

func (accumulator *componentAccumulator) values() []StackComponent {
	result := make([]StackComponent, 0, len(accumulator.valuesByKey))
	for _, component := range accumulator.valuesByKey {
		component.Evidence = uniqueEvidence(component.Evidence)
		result = append(result, *component)
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := stackCategoryOrder(result[i].Category), stackCategoryOrder(result[j].Category)
		if left != right {
			return left < right
		}
		if confidenceRank(result[i].Confidence) != confidenceRank(result[j].Confidence) {
			return confidenceRank(result[i].Confidence) > confidenceRank(result[j].Confidence)
		}
		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})
	return result
}

type providerSignature struct {
	match      string
	name       string
	category   StackCategory
	role       string
	confidence Confidence
}

func (signature providerSignature) component(role, source, subject, field, value string) StackComponent {
	if role == "" {
		role = signature.role
	}
	return StackComponent{Category: signature.category, Name: signature.name, Role: role, Confidence: signature.confidence,
		Evidence: []InvestigationEvidence{{Source: source, Subject: subject, Field: field, Value: truncateEvidence(value)}}}
}

var dnsProviderSignatures = []providerSignature{
	{"inceptionwebsites.co", "Inception Websites", StackDNS, "Authoritative DNS", ConfidenceHigh},
	{"cloudflare.com", "Cloudflare DNS", StackDNS, "Authoritative DNS", ConfidenceHigh},
	{"awsdns-", "Amazon Route 53", StackDNS, "Authoritative DNS", ConfidenceHigh},
	{"domaincontrol.com", "GoDaddy DNS", StackDNS, "Authoritative DNS", ConfidenceHigh},
	{"googledomains.com", "Google Cloud DNS", StackDNS, "Authoritative DNS", ConfidenceHigh},
	{"azure-dns.", "Azure DNS", StackDNS, "Authoritative DNS", ConfidenceHigh},
	{"dnsimple.com", "DNSimple", StackDNS, "Authoritative DNS", ConfidenceHigh},
	{"nsone.net", "NS1", StackDNS, "Authoritative DNS", ConfidenceHigh},
	{"digitalocean.com", "DigitalOcean DNS", StackDNS, "Authoritative DNS", ConfidenceHigh},
	{"registrar-servers.com", "Namecheap DNS", StackDNS, "Authoritative DNS", ConfidenceHigh},
}

var mailProviderSignatures = []providerSignature{
	{"mail.protection.outlook.com", "Microsoft 365", StackMail, "Inbound mail", ConfidenceHigh},
	{"aspmx.l.google.com", "Google Workspace", StackMail, "Inbound mail", ConfidenceHigh},
	{"googlemail.com", "Google Workspace", StackMail, "Inbound mail", ConfidenceHigh},
	{"secureserver.net", "GoDaddy Email", StackMail, "Inbound mail", ConfidenceHigh},
	{"zoho.com", "Zoho Mail", StackMail, "Inbound mail", ConfidenceHigh},
	{"zoho.eu", "Zoho Mail", StackMail, "Inbound mail", ConfidenceHigh},
	{"protonmail.ch", "Proton Mail", StackMail, "Inbound mail", ConfidenceHigh},
	{"messagingengine.com", "Fastmail", StackMail, "Inbound mail", ConfidenceHigh},
	{"mimecast.com", "Mimecast", StackMail, "Mail security", ConfidenceHigh},
	{"pphosted.com", "Proofpoint", StackMail, "Mail security", ConfidenceHigh},
}

var cnameProviderSignatures = []providerSignature{
	{"cloudfront.net", "Amazon CloudFront", StackEdge, "Edge/CDN", ConfidenceHigh},
	{"cdn.cloudflare.net", "Cloudflare", StackEdge, "Edge/CDN", ConfidenceHigh},
	{"fastly.net", "Fastly", StackEdge, "Edge/CDN", ConfidenceHigh},
	{"akamaiedge.net", "Akamai", StackEdge, "Edge/CDN", ConfidenceHigh},
	{"myshopify.com", "Shopify", StackWebApplication, "Commerce platform", ConfidenceHigh},
	{"vercel-dns.com", "Vercel", StackHosting, "Hosting platform", ConfidenceHigh},
	{"netlify.app", "Netlify", StackHosting, "Hosting platform", ConfidenceHigh},
	{"proxy-ssl.webflow.com", "Webflow", StackWebApplication, "Site builder", ConfidenceHigh},
	{"wixdns.net", "Wix", StackWebApplication, "Site builder", ConfidenceHigh},
	{"squarespace.com", "Squarespace", StackWebApplication, "Site builder", ConfidenceHigh},
}

var txtProviderSignatures = []providerSignature{
	{"include:spf.protection.outlook.com", "Microsoft 365", StackMail, "Outbound mail authorization", ConfidenceHigh},
	{"include:_spf.google.com", "Google Workspace", StackMail, "Outbound mail authorization", ConfidenceHigh},
	{"secureserver.net", "GoDaddy Email", StackMail, "Outbound mail authorization", ConfidenceMedium},
	{"relay.mailchannels.net", "MailChannels", StackMail, "Outbound mail relay", ConfidenceHigh},
	{"sendgrid.net", "SendGrid", StackMail, "Outbound mail relay", ConfidenceHigh},
	{"mailgun.org", "Mailgun", StackMail, "Outbound mail relay", ConfidenceHigh},
	{"amazonses.com", "Amazon SES", StackMail, "Outbound mail relay", ConfidenceHigh},
}

var ptrProviderSignatures = []providerSignature{
	{"inceptionseo.com", "Inception Websites", StackHosting, "Managed hosting", ConfidenceMedium},
	{"amazonaws.com", "Amazon Web Services", StackHosting, "Cloud hostname", ConfidenceMedium},
	{"googleusercontent.com", "Google Cloud", StackHosting, "Cloud hostname", ConfidenceMedium},
	{"cloudapp.azure.com", "Microsoft Azure", StackHosting, "Cloud hostname", ConfidenceMedium},
}

func providerByDNSHost(host string, signatures []providerSignature) providerSignature {
	host = strings.ToLower(normalizeDNSName(host))
	for _, signature := range signatures {
		match := strings.ToLower(normalizeDNSName(signature.match))
		fragment := strings.HasSuffix(signature.match, "-") || strings.HasSuffix(signature.match, ".")
		if fragment && strings.Contains(host, match) || !fragment && (host == match || strings.HasSuffix(host, "."+match)) {
			return signature
		}
	}
	return providerSignature{}
}

func addressesForDNSName(records []DNSRecord, name string) []string {
	frontier := []string{normalizeDNSName(name)}
	seen := make(map[string]bool)
	var result []string
	for depth := 0; depth < 8 && len(frontier) > 0; depth++ {
		current := frontier[0]
		frontier = frontier[1:]
		if seen[current] {
			continue
		}
		seen[current] = true
		for _, record := range records {
			if normalizeDNSName(record.Name) != current {
				continue
			}
			switch strings.ToUpper(record.Type) {
			case "A", "AAAA":
				if address, err := netip.ParseAddr(strings.TrimSpace(record.Value)); err == nil {
					result = append(result, address.Unmap().String())
				}
			case "CNAME":
				target := dnsRecordValueTarget(record)
				if target != "" && !seen[target] {
					frontier = append(frontier, target)
				}
			}
		}
	}
	return uniqueStrings(result)
}

func intersectsStrings(left, right []string) bool {
	seen := make(map[string]bool, len(left))
	for _, value := range left {
		seen[value] = true
	}
	for _, value := range right {
		if seen[value] {
			return true
		}
	}
	return false
}

func investigationSummary(components []StackComponent) string {
	groups := []struct {
		label      string
		categories map[StackCategory]bool
	}{
		{"Web", map[StackCategory]bool{StackWebApplication: true, StackFramework: true}},
		{"Server", map[StackCategory]bool{StackWebServer: true, StackEdge: true}},
		{"Hosting", map[StackCategory]bool{StackHosting: true}},
		{"Network", map[StackCategory]bool{StackNetwork: true}},
		{"DNS", map[StackCategory]bool{StackDNS: true}},
		{"Mail", map[StackCategory]bool{StackMail: true}},
	}
	var parts []string
	for _, group := range groups {
		var names []string
		for _, component := range components {
			if group.categories[component.Category] && component.Confidence != ConfidenceLow {
				names = append(names, component.Name)
			}
		}
		names = uniqueStrings(names)
		if len(names) > 3 {
			names = append(names[:3], fmt.Sprintf("+%d more", len(names)-3))
		}
		if len(names) > 0 {
			parts = append(parts, group.label+": "+strings.Join(names, ", "))
		}
	}
	if len(parts) == 0 {
		return "No technologies could be identified from the bounded public evidence."
	}
	return strings.Join(parts, " · ")
}

func confidenceRank(value Confidence) int {
	switch value {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	default:
		return 1
	}
}

func stackCategoryOrder(value StackCategory) int {
	order := map[StackCategory]int{
		StackWebApplication: 0, StackFramework: 1, StackWebServer: 2, StackEdge: 3,
		StackHosting: 4, StackNetwork: 5, StackDNS: 6, StackMail: 7,
		StackAnalytics: 8, StackSecurity: 9, StackOther: 10,
	}
	if result, exists := order[value]; exists {
		return result
	}
	return 99
}

func appendUniqueEvidence(values []InvestigationEvidence, candidate InvestigationEvidence) []InvestigationEvidence {
	candidate.Value = truncateEvidence(candidate.Value)
	key := candidate.Source + "\x00" + candidate.Subject + "\x00" + candidate.Field + "\x00" + candidate.Value
	for _, existing := range values {
		if existing.Source+"\x00"+existing.Subject+"\x00"+existing.Field+"\x00"+existing.Value == key {
			return values
		}
	}
	return append(values, candidate)
}

func uniqueEvidence(values []InvestigationEvidence) []InvestigationEvidence {
	result := make([]InvestigationEvidence, 0, len(values))
	for _, value := range values {
		result = appendUniqueEvidence(result, value)
	}
	return result
}

func truncateEvidence(value string) string {
	value = cleanHeaderValue(value)
	if len(value) > 512 {
		return value[:509] + "..."
	}
	return value
}

func cleanHeaderValue(value string) string {
	value = strings.Map(func(character rune) rune {
		if character == '\r' || character == '\n' || character == 0 {
			return ' '
		}
		return character
	}, value)
	return strings.Join(strings.Fields(value), " ")
}

func firstString(values []string, fallback string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return fallback
}

func uniqueLowerStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			result = append(result, value)
		}
	}
	return uniqueStrings(result)
}

func dnsOperationRecords(result *DNSOperationResult) []DNSRecord {
	if result == nil {
		return nil
	}
	var records []DNSRecord
	if result.Inventory != nil {
		records = append(records, result.Inventory.Records...)
	}
	for _, message := range result.Messages {
		records = append(records, message.Answer...)
		records = append(records, message.Additional...)
	}
	return uniqueDNSRecords(records)
}

func (provider *nativeInvestigationProvider) validateRelated(ctx context.Context, observations []RelatedObservation, options DNSOptions) {
	workers := min(maximumRelatedValidationWorkers, len(observations))
	if workers == 0 {
		return
	}
	jobs := make(chan int)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range jobs {
				observation := &observations[index]
				name, err := ParseDNSName(observation.Hostname)
				observed, observedErr := netip.ParseAddr(observation.Address)
				if err != nil || observedErr != nil {
					observation.Current = RelatedUnknown
					continue
				}
				queryOptions := options
				queryOptions.Types = []string{"A"}
				if observed.Is6() {
					queryOptions.Types = []string{"AAAA"}
				}
				// The enrichment opt-in covers OTX only. Never fan historical
				// hostnames out to an unrelated remote-probe provider.
				queryOptions.Globalping = false
				answer, queryErr := provider.dns.Query(ctx, name, queryOptions)
				if queryErr != nil && answer == nil {
					observation.Current = RelatedUnknown
					continue
				}
				var current []string
				for _, record := range dnsOperationRecords(answer) {
					if record.Type != "A" && record.Type != "AAAA" {
						continue
					}
					if address, parseErr := netip.ParseAddr(strings.TrimSpace(record.Value)); parseErr == nil {
						current = append(current, address.Unmap().String())
					}
				}
				observation.CurrentValues = uniqueStrings(current)
				observation.Current = RelatedStale
				for _, value := range observation.CurrentValues {
					candidate, candidateErr := netip.ParseAddr(value)
					if candidateErr == nil && candidate.Unmap() == observed.Unmap() {
						observation.Current = RelatedCurrent
						break
					}
				}
				if observation.Current != RelatedCurrent && queryErr != nil {
					observation.Current = RelatedUnknown
				}
			}
		}()
	}
	for index := range observations {
		select {
		case jobs <- index:
		case <-ctx.Done():
			close(jobs)
			group.Wait()
			return
		}
	}
	close(jobs)
	group.Wait()
}

type otxEnrichmentProvider struct {
	networkPolicy NetworkPolicy
	slots         chan struct{}
}

func (provider *otxEnrichmentProvider) Name() string { return "otx" }

func (provider *otxEnrichmentProvider) Enrich(ctx context.Context, seed InvestigationSeed, options EnrichmentOptions) (EnrichmentResult, error) {
	if len(seed.Addresses) == 0 {
		return EnrichmentResult{}, nil
	}
	endpoint := strings.TrimRight(strings.TrimSpace(options.Endpoint), "/")
	if endpoint == "" {
		endpoint = defaultOTXEndpoint
	}
	if err := validateEnrichmentEndpoint(ctx, endpoint, provider.networkPolicy); err != nil {
		return EnrichmentResult{}, err
	}
	client := options.HTTPClient
	if client == nil {
		client = safeInvestigationHTTPClient(provider.networkPolicy)
	}
	limit := options.Limit
	if limit <= 0 || limit > maximumRelatedLimit {
		limit = defaultRelatedLimit
	}
	var result EnrichmentResult
	var failures []string
	failureKind := ErrorKind("")
	for _, address := range seed.Addresses {
		parsed, err := netip.ParseAddr(address)
		if err != nil || !publicNetworkAddress(parsed) {
			continue
		}
		select {
		case provider.slots <- struct{}{}:
		case <-ctx.Done():
			return result, ctx.Err()
		}
		value, requestErr := provider.query(ctx, client, endpoint, address, limit, options.Token)
		<-provider.slots
		if requestErr != nil {
			if ctx.Err() != nil {
				return result, contextLookupError("AlienVault OTX", ctx.Err())
			}
			var typed *LookupError
			if errors.As(requestErr, &typed) {
				if typed.Kind == ErrorRateLimited {
					return result, requestErr
				}
				if failureKind == "" {
					failureKind = typed.Kind
				} else if failureKind != typed.Kind {
					failureKind = ErrorUnavailable
				}
			} else if failureKind == "" {
				failureKind = ErrorUnavailable
			}
			failures = append(failures, address+": "+requestErr.Error())
			continue
		}
		result.Related = append(result.Related, value.Related...)
		result.Total += value.Total
		result.Warnings = append(result.Warnings, value.Warnings...)
	}
	if len(failures) > 0 {
		if failureKind == "" {
			failureKind = ErrorUnavailable
		}
		return result, lookupError(failureKind, "AlienVault OTX: "+strings.Join(failures, "; "), nil)
	}
	return result, nil
}

func (provider *otxEnrichmentProvider) query(ctx context.Context, client *http.Client, endpoint, address string, limit int, token string) (EnrichmentResult, error) {
	indicatorType := "IPv4"
	if parsed, _ := netip.ParseAddr(address); parsed.Is6() {
		indicatorType = "IPv6"
	}
	requestURL := endpoint + "/indicators/" + indicatorType + "/" + url.PathEscape(address) + "/passive_dns?limit=" + strconv.Itoa(limit) + "&page=1"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return EnrichmentResult{}, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", productUserAgent())
	if strings.TrimSpace(token) != "" {
		request.Header.Set("X-OTX-API-KEY", strings.TrimSpace(token))
	}
	response, err := client.Do(request)
	if err != nil {
		return EnrichmentResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusTooManyRequests {
		return EnrichmentResult{}, lookupError(ErrorRateLimited, "rate limited", nil)
	}
	if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusUnauthorized {
		return EnrichmentResult{}, lookupError(ErrorUnavailable, "API access was denied; set WHODIS_OTX_API_KEY if the endpoint requires a key", nil)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return EnrichmentResult{}, fmt.Errorf("HTTP %s", response.Status)
	}
	payload, err := readLimitedBody(response.Body, maximumEnrichmentResponse)
	if err != nil {
		return EnrichmentResult{}, err
	}
	var document struct {
		PassiveDNS []struct {
			Address    string `json:"address"`
			Hostname   string `json:"hostname"`
			RecordType string `json:"record_type"`
			First      string `json:"first"`
			Last       string `json:"last"`
			ASN        string `json:"asn"`
		} `json:"passive_dns"`
		Count    int `json:"count"`
		FullSize int `json:"full_size"`
	}
	if err := json.Unmarshal(payload, &document); err != nil {
		return EnrichmentResult{}, fmt.Errorf("invalid JSON: %w", err)
	}
	result := EnrichmentResult{Total: max(document.Count, document.FullSize)}
	for _, item := range document.PassiveDNS {
		if len(result.Related) >= limit {
			break
		}
		hostname, nameErr := ParseDNSName(item.Hostname)
		parsedAddress, addressErr := netip.ParseAddr(strings.TrimSpace(item.Address))
		recordType := strings.ToUpper(strings.TrimSpace(item.RecordType))
		if nameErr != nil || addressErr != nil ||
			(recordType != "A" && recordType != "AAAA") ||
			(recordType == "A" && !parsedAddress.Is4()) || (recordType == "AAAA" && !parsedAddress.Is6()) {
			continue
		}
		result.Related = append(result.Related, RelatedObservation{
			Provider: "otx", Hostname: hostname, Address: parsedAddress.Unmap().String(), RecordType: recordType,
			ASN: truncateEvidence(item.ASN), FirstSeen: parseProviderTime(item.First), LastSeen: parseProviderTime(item.Last), Current: RelatedUnknown,
		})
	}
	if result.Total == 0 {
		result.Total = len(result.Related)
	}
	return result, nil
}

func validateEnrichmentEndpoint(ctx context.Context, endpoint string, policy NetworkPolicy) error {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return lookupError(ErrorInvalidInput, "enrichment endpoint must be a URL without credentials", err)
	}
	if parsed.Scheme != "https" && !policy.AllowInsecureHTTP {
		return lookupError(ErrorInvalidInput, "enrichment endpoint must use HTTPS", nil)
	}
	return validateAutomaticHost(ctx, parsed.Hostname(), policy)
}

func parseProviderTime(value string) time.Time {
	value = strings.TrimSpace(value)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

func deduplicateRelated(values []RelatedObservation) []RelatedObservation {
	seen := make(map[string]int, len(values))
	result := make([]RelatedObservation, 0, len(values))
	for _, value := range values {
		key := strings.ToLower(value.Provider) + "\x00" + normalizeDNSName(value.Hostname) + "\x00" + value.Address + "\x00" + value.RecordType
		if index, exists := seen[key]; exists {
			if !value.FirstSeen.IsZero() && (result[index].FirstSeen.IsZero() || value.FirstSeen.Before(result[index].FirstSeen)) {
				result[index].FirstSeen = value.FirstSeen
			}
			if value.LastSeen.After(result[index].LastSeen) {
				result[index].LastSeen = value.LastSeen
			}
			continue
		}
		seen[key] = len(result)
		result = append(result, value)
	}
	return result
}

func sortRelated(values []RelatedObservation) {
	stateOrder := func(state RelatedState) int {
		switch state {
		case RelatedCurrent:
			return 0
		case RelatedUnknown:
			return 1
		default:
			return 2
		}
	}
	sort.SliceStable(values, func(i, j int) bool {
		if stateOrder(values[i].Current) != stateOrder(values[j].Current) {
			return stateOrder(values[i].Current) < stateOrder(values[j].Current)
		}
		if !values[i].LastSeen.Equal(values[j].LastSeen) {
			return values[i].LastSeen.After(values[j].LastSeen)
		}
		return values[i].Hostname < values[j].Hostname
	})
}
