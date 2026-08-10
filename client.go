package whodis

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

const defaultTimeout = 15 * time.Second

// Client is safe to reuse for multiple sequential or concurrent lookups.
type Client struct {
	timeout  time.Duration
	cache    *bootstrapCache
	adapters map[Protocol]ProtocolAdapter
}

// NewClient creates a protocol-aware lookup client. It makes no network
// requests until Route or Lookup is called.
func NewClient(options ClientOptions) *Client {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	c := &Client{
		timeout:  timeout,
		cache:    newBootstrapCache(options.CacheDirectory),
		adapters: make(map[Protocol]ProtocolAdapter),
	}
	c.adapters[ProtocolRDAP] = rdapAdapter{client: c}
	c.adapters[ProtocolWHOIS] = whoisAdapter{client: c}
	for _, adapter := range options.Adapters {
		if adapter != nil {
			c.adapters[adapter.Protocol()] = adapter
		}
	}
	return c
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
		result := newResult(target, primary, nil, object, sources)
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
	result := newResult(target, fallback, &primary, object, sources)
	if dnsResults != nil {
		result.DNS = <-dnsResults
	}
	return result, nil
}

func newResult(target Target, route RouteDecision, fallback *RouteDecision, object Object, sources []Source) LookupResult {
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
		options.DNSMode = DNSAuto
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
		if options.Protocol != ProtocolRDAP && options.Protocol != ProtocolWHOIS {
			return RouteDecision{}, lookupError(ErrorInvalidInput, "--server requires --protocol rdap or --protocol whois", nil)
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
		return RouteDecision{}, lookupError(ErrorInvalidInput, "protocol must be auto, rdap, or whois", nil)
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
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", lookupError(ErrorInvalidInput, "RDAP server must be an http or https URL", err)
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	return u.String(), nil
}
