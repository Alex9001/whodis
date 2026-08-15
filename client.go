package whodis

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

const defaultTimeout = 15 * time.Second

// Client is safe to reuse for multiple sequential or concurrent registration
// lookups.
//
// Deprecated: use Engine for new integrations. Client remains available for
// source compatibility with registration-focused v1 callers.
type Client struct {
	timeout       time.Duration
	cache         *bootstrapCache
	adapters      map[Protocol]ProtocolAdapter
	networkPolicy NetworkPolicy
	transport     *http.Transport
	autoTransport *http.Transport
}

// NewClient creates a protocol-aware lookup client. It makes no network
// requests until Route or Lookup is called.
//
// Deprecated: use NewEngine for new integrations.
func NewClient(options ClientOptions) *Client {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxConnsPerHost = 4
	transport.MaxIdleConnsPerHost = 4
	autoTransport := transport.Clone()
	// Automatic registry discovery must connect directly so an environment
	// proxy cannot resolve a referral again after Whodis validates it.
	autoTransport.Proxy = nil
	autoTransport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialAutomaticContext(ctx, network, address, timeout, options.NetworkPolicy)
	}
	c := &Client{
		timeout: timeout, cache: newBootstrapCache(options.CacheDirectory), adapters: make(map[Protocol]ProtocolAdapter),
		networkPolicy: options.NetworkPolicy, transport: transport, autoTransport: autoTransport,
	}
	c.adapters[ProtocolRDAP] = rdapAdapter{client: c}
	c.adapters[ProtocolWHOIS] = whoisAdapter{client: c}
	c.adapters[ProtocolRWHOIS] = rwhoisAdapter{client: c}
	for _, adapter := range options.Adapters {
		if adapter != nil {
			c.adapters[adapter.Protocol()] = adapter
		}
	}
	return c
}

// Close releases pooled network transports. It is safe to call repeatedly.
func (c *Client) Close() error {
	if c != nil && c.transport != nil {
		c.transport.CloseIdleConnections()
	}
	if c != nil && c.autoTransport != nil {
		c.autoTransport.CloseIdleConnections()
	}
	return nil
}

// ParseTarget classifies and canonicalizes one user supplied lookup target.
func ParseTarget(input string) (Target, error) {
	original := strings.TrimSpace(input)
	if original == "" {
		return Target{}, lookupError(ErrorInvalidInput, "a domain, IP address, CIDR, or ASN is required", nil)
	}

	upper := strings.ToUpper(original)
	if strings.HasPrefix(upper, "AS") {
		rawASN := upper[2:]
		if rawASN == "" {
			return Target{}, lookupError(ErrorInvalidInput, "ASN must contain a number", nil)
		}
		n, err := strconv.ParseUint(rawASN, 10, 32)
		if err != nil {
			return Target{}, lookupError(ErrorInvalidInput, "invalid ASN", nil)
		}
		return Target{Original: original, Canonical: fmt.Sprintf("%d", n), Kind: KindASN}, nil
	}
	if n, err := strconv.ParseUint(original, 10, 32); err == nil {
		return Target{Original: original, Canonical: fmt.Sprintf("%d", n), Kind: KindASN}, nil
	}

	if addr, err := netip.ParseAddr(original); err == nil {
		return Target{Original: original, Canonical: addr.String(), Kind: KindIP}, nil
	}
	if prefix, err := netip.ParsePrefix(original); err == nil {
		return Target{Original: original, Canonical: prefix.Masked().String(), Kind: KindIP}, nil
	}

	domain := strings.TrimSuffix(strings.ToLower(original), ".")
	if domain == "" || strings.ContainsAny(domain, " /@:") {
		return Target{}, lookupError(ErrorInvalidInput, "invalid domain name", nil)
	}
	canonical, err := idna.Lookup.ToASCII(domain)
	if err != nil || canonical == "" || len(canonical) > 253 {
		return Target{}, lookupError(ErrorInvalidInput, "invalid internationalized domain name", err)
	}
	return Target{Original: original, Canonical: strings.ToLower(canonical), Kind: KindDomain}, nil
}

// Route decides which known authority should receive a lookup without making a
// registration-data query. WHOIS route discovery may query IANA's referral
// service when the selected protocol is WHOIS.
func (c *Client) Route(ctx context.Context, input string, options LookupOptions) (RouteDecision, error) {
	target, err := ParseTarget(input)
	if err != nil {
		return RouteDecision{}, err
	}
	return c.route(ctx, target, normalizedOptions(options))
}

// Lookup resolves one target and returns a stable, renderer-independent model.
func (c *Client) Lookup(ctx context.Context, input string, options LookupOptions) (LookupResult, error) {
	target, err := ParseTarget(input)
	if err != nil {
		return LookupResult{}, err
	}
	opts := normalizedOptions(options)
	if err := validateDNSOptions(target, opts); err != nil {
		return LookupResult{}, err
	}

	var dnsResults chan *DNSResult
	var cancelDNS context.CancelFunc
	if shouldScanDNS(target, opts) {
		dnsContext := ctx
		if opts.DNSMode != DNSAXFR {
			dnsContext, cancelDNS = context.WithTimeout(ctx, dnsScanTimeout(opts.Timeout))
		} else {
			dnsContext, cancelDNS = context.WithCancel(ctx)
		}
		defer cancelDNS()
		dnsResults = make(chan *DNSResult, 1)
		go func() {
			dnsResults <- c.lookupDNS(dnsContext, target, opts)
		}()
	}

	primary, err := c.route(ctx, target, opts)
	if err != nil {
		return LookupResult{}, err
	}

	object, sources, err := c.lookupWithRoute(ctx, target, primary)
	if err == nil {
		effectiveRoute := routedSources(primary, sources)
		if opts.Protocol == ProtocolAuto && primary.Protocol == ProtocolRDAP && (target.Kind == KindIP || target.Kind == KindASN) {
			object, sources, effectiveRoute = c.enrichRDAPWithRWHOIS(ctx, target, object, sources, effectiveRoute)
		}
		result := newResult(target, effectiveRoute, nil, object, sources)
		if dnsResults != nil {
			result.DNS = <-dnsResults
		}
		return result, nil
	}
	if !shouldFallback(err, opts.Fallback) || opts.Server != "" {
		return LookupResult{}, err
	}

	fallback, fallbackErr := c.alternateRoute(ctx, target, opts, primary.Protocol)
	if fallbackErr != nil {
		return LookupResult{}, err
	}
	object, sources, fallbackErr = c.lookupWithRoute(ctx, target, fallback)
	if fallbackErr != nil {
		return LookupResult{}, fallbackErr
	}
	result := newResult(target, routedSources(fallback, sources), &primary, object, sources)
	if dnsResults != nil {
		result.DNS = <-dnsResults
	}
	return result, nil
}

func newResult(target Target, route RouteDecision, fallback *RouteDecision, object Object, sources []Source) LookupResult {
	object.Events = uniqueEvents(object.Events)
	return LookupResult{
		SchemaVersion: 2,
		Query:         target,
		Route:         route,
		FallbackFrom:  fallback,
		RetrievedAt:   time.Now().UTC(),
		Object:        object,
		Sources:       sources,
	}
}

// uniqueEvents removes duplicate lifecycle facts contributed by overlapping
// registry and registrar RDAP responses. RFC 3339 permits multiple spellings
// of the same instant (for example Z and +00:00), and authorities sometimes
// use a more specific alias such as "registrar expiration" for the same fact.
// Different instants are always retained.
func uniqueEvents(events []Event) []Event {
	result := make([]Event, 0, len(events))
	indexes := make(map[string]int, len(events))
	for _, event := range events {
		event.Action = strings.TrimSpace(event.Action)
		event.Date = strings.TrimSpace(event.Date)
		if event.Action == "" && event.Date == "" {
			continue
		}
		actionClass := eventActionClass(event.Action)
		key := actionClass + "\x00" + eventDateKey(event.Date)
		if index, exists := indexes[key]; exists {
			// Prefer Whodis's common lifecycle wording only when two source
			// events have already proved equivalent by action class and instant.
			if canonical := canonicalEventAction(actionClass); canonical != "" {
				result[index].Action = canonical
			}
			continue
		}
		indexes[key] = len(result)
		result = append(result, event)
	}
	return result
}

func eventActionClass(action string) string {
	key := strings.ToLower(strings.TrimSpace(action))
	key = strings.NewReplacer(" ", "", "-", "", "_", "", ".", "").Replace(key)
	switch key {
	case "registration", "registered", "creation", "created", "registrarregistration":
		return "registration"
	case "expiration", "expiry", "expires", "registryexpiration", "registryexpiry", "registrarexpiration":
		return "expiration"
	case "lastchanged", "lastupdate", "updated", "changed":
		return "lastchanged"
	default:
		return key
	}
}

func canonicalEventAction(actionClass string) string {
	switch actionClass {
	case "registration":
		return "registration"
	case "expiration":
		return "expiration"
	case "lastchanged":
		return "last changed"
	default:
		return ""
	}
}

func eventDateKey(date string) string {
	if parsed, err := time.Parse(time.RFC3339Nano, date); err == nil {
		return parsed.UTC().Format(time.RFC3339Nano)
	}
	return strings.ToLower(strings.TrimSpace(date))
}

func normalizedOptions(options LookupOptions) LookupOptions {
	if options.Protocol == "" {
		options.Protocol = ProtocolAuto
	}
	if options.Fallback == "" {
		options.Fallback = FallbackUnavailable
	}
	if options.Timeout <= 0 {
		options.Timeout = defaultTimeout
	}
	if options.DNSMode == "" {
		options.DNSMode = DNSOff
	}
	return options
}

func validateDNSOptions(target Target, options LookupOptions) error {
	switch options.DNSMode {
	case DNSAuto, DNSOff, DNSScan, DNSAXFR:
	default:
		return lookupError(ErrorInvalidInput, "dns mode must be auto, off, scan, or axfr", nil)
	}
	if options.DNSResolver != "" {
		if options.DNSMode == DNSOff {
			return lookupError(ErrorInvalidInput, "dns resolver cannot be used with dns mode off", nil)
		}
		if _, err := normalizeDNSResolver(options.DNSResolver); err != nil {
			return lookupError(ErrorInvalidInput, err.Error(), err)
		}
	}
	if target.Kind != KindDomain && options.DNSMode != DNSAuto && options.DNSMode != DNSOff {
		return lookupError(ErrorInvalidInput, "dns scans and AXFR require a domain target", nil)
	}
	if target.Kind != KindDomain && options.DNSResolver != "" {
		return lookupError(ErrorInvalidInput, "dns resolver requires a domain target", nil)
	}
	return nil
}

func shouldScanDNS(target Target, options LookupOptions) bool {
	return target.Kind == KindDomain && options.DNSMode != DNSOff
}

func (c *Client) route(ctx context.Context, target Target, options LookupOptions) (RouteDecision, error) {
	if options.Server != "" {
		if options.Protocol != ProtocolRDAP && options.Protocol != ProtocolWHOIS && options.Protocol != ProtocolRWHOIS {
			return RouteDecision{}, lookupError(ErrorInvalidInput, "--server requires --protocol rdap, whois, or rwhois", nil)
		}
		endpoint, err := canonicalEndpoint(options.Protocol, options.Server)
		if err != nil {
			return RouteDecision{}, err
		}
		return RouteDecision{Protocol: options.Protocol, Endpoint: endpoint, DiscoverySource: "command line", Reason: "server explicitly selected"}, nil
	}

	switch options.Protocol {
	case ProtocolRDAP:
		return c.discoverRDAP(ctx, target, options.RefreshBootstrap)
	case ProtocolWHOIS:
		return c.discoverWHOIS(ctx, target)
	case ProtocolRWHOIS:
		return RouteDecision{}, lookupError(ErrorInvalidInput, "--protocol rwhois requires --server because RWhois has no global bootstrap", nil)
	case ProtocolAuto:
		rdapRoute, err := c.discoverRDAP(ctx, target, options.RefreshBootstrap)
		if err == nil {
			return rdapRoute, nil
		}
		if typed, ok := err.(*LookupError); !ok || typed.Kind != ErrorDiscovery {
			return RouteDecision{}, err
		}
		return c.discoverWHOIS(ctx, target)
	default:
		return RouteDecision{}, lookupError(ErrorInvalidInput, "protocol must be auto, rdap, whois, or rwhois", nil)
	}
}

func (c *Client) alternateRoute(ctx context.Context, target Target, options LookupOptions, current Protocol) (RouteDecision, error) {
	if current == ProtocolRDAP {
		return c.discoverWHOIS(ctx, target)
	}
	return c.discoverRDAP(ctx, target, options.RefreshBootstrap)
}

func (c *Client) lookupWithRoute(ctx context.Context, target Target, route RouteDecision) (Object, []Source, error) {
	adapter, ok := c.adapters[route.Protocol]
	if !ok {
		return Object{}, nil, lookupError(ErrorProtocol, "no adapter is registered for "+string(route.Protocol), nil)
	}
	return adapter.Lookup(ctx, target, route)
}

func routedSources(initial RouteDecision, sources []Source) RouteDecision {
	if len(sources) == 0 {
		return initial
	}
	last := sources[len(sources)-1]
	if last.Protocol != ProtocolRWHOIS {
		return initial
	}
	if initial.Protocol == ProtocolRWHOIS && strings.EqualFold(initial.Endpoint, last.Endpoint) {
		return initial
	}
	if initial.Protocol == ProtocolRWHOIS {
		return RouteDecision{
			Protocol:        ProtocolRWHOIS,
			Endpoint:        last.Endpoint,
			DiscoverySource: "RWhois referral",
			Reason:          "RWhois authority delegated the registration object",
		}
	}
	return RouteDecision{
		Protocol:        ProtocolRWHOIS,
		Endpoint:        last.Endpoint,
		DiscoverySource: "WHOIS RWhois referral",
		Reason:          "authoritative WHOIS service delegated the registration object",
	}
}

// enrichRDAPWithRWHOIS makes RWhois discovery invisible for the common
// network-delegation path: RDAP advertises port43, WHOIS advertises RWhois,
// and RWhois returns the more-specific assignment. Every probe failure keeps
// the successful RDAP result intact.
func (c *Client) enrichRDAPWithRWHOIS(ctx context.Context, target Target, rdapObject Object, rdapSources []Source, current RouteDecision) (Object, []Source, RouteDecision) {
	port43 := rdapPort43(rdapSources)
	if port43 == "" {
		return rdapObject, rdapSources, current
	}
	whoisObject, whoisSources, referral, found := (whoisAdapter{client: c}).probeRWHOISReferral(ctx, target, port43)
	if !found {
		return rdapObject, rdapSources, current
	}
	route := RouteDecision{Protocol: ProtocolRWHOIS, Endpoint: referral, DiscoverySource: "RDAP port43 WHOIS referral", Reason: "RDAP authority delegated a more-specific registration object"}
	rwhoisObject, rwhoisSources, err := c.lookupWithRoute(ctx, target, route)
	if err != nil {
		return rdapObject, rdapSources, current
	}
	return mergeObjects(rwhoisObject, mergeObjects(whoisObject, rdapObject)), append(append(rdapSources, whoisSources...), rwhoisSources...), routedSources(route, rwhoisSources)
}

func shouldFallback(err error, mode FallbackMode) bool {
	if mode == FallbackNone {
		return false
	}
	if mode == FallbackAnyError {
		return true
	}
	typed, ok := err.(*LookupError)
	return ok && (typed.Kind == ErrorUnavailable || typed.Kind == ErrorProtocol || typed.Kind == ErrorDiscovery)
}

func canonicalEndpoint(protocol Protocol, input string) (string, error) {
	endpoint := strings.TrimSpace(input)
	if endpoint == "" {
		return "", lookupError(ErrorInvalidInput, "server endpoint cannot be empty", nil)
	}
	if protocol == ProtocolWHOIS {
		endpoint = strings.TrimPrefix(endpoint, "whois://")
		endpoint = strings.TrimSuffix(endpoint, "/")
		if strings.Contains(endpoint, "/") {
			return "", lookupError(ErrorInvalidInput, "WHOIS server must be a host or host:port", nil)
		}
		return endpoint, nil
	}
	if protocol == ProtocolRWHOIS {
		return canonicalRWHOISEndpoint(endpoint)
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", lookupError(ErrorInvalidInput, "RDAP server must be an http or https URL", err)
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	return u.String(), nil
}
