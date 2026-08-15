package whodis

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ameshkov/dnscrypt/v2"
	mdns "github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// ResolverStrategy controls how multiple configured resolvers are used.
type ResolverStrategy string

const (
	ResolverFirst     ResolverStrategy = "first"
	ResolverAll       ResolverStrategy = "all"
	ResolverFastest   ResolverStrategy = "fastest"
	ResolverRandom    ResolverStrategy = "random"
	ResolverConsensus ResolverStrategy = "consensus"
)

// EDNSOptions configures the OPT pseudo-record used for DNS queries.
type EDNSOptions struct {
	BufferSize uint16 `json:"buffer_size,omitempty" yaml:"buffer_size,omitempty"`
	DNSSEC     bool   `json:"dnssec,omitempty" yaml:"dnssec,omitempty"`
	NSID       bool   `json:"nsid,omitempty" yaml:"nsid,omitempty"`
	ECS        string `json:"ecs,omitempty" yaml:"ecs,omitempty"`
	Cookie     string `json:"cookie,omitempty" yaml:"cookie,omitempty"`
	Padding    uint16 `json:"padding,omitempty" yaml:"padding,omitempty"`
}

// TransferOptions configures an explicit AXFR or IXFR request.
type TransferOptions struct {
	Type       string `json:"type,omitempty" yaml:"type,omitempty"`
	Serial     uint32 `json:"serial,omitempty" yaml:"serial,omitempty"`
	TSIGName   string `json:"tsig_name,omitempty" yaml:"tsig_name,omitempty"`
	TSIGSecret string `json:"-" yaml:"-"`
	TSIGAlgo   string `json:"tsig_algorithm,omitempty" yaml:"tsig_algorithm,omitempty"`
	TLS        bool   `json:"tls,omitempty" yaml:"tls,omitempty"`
}

// DNSOptions controls query, inventory, comparison, trace, and transfer.
type DNSOptions struct {
	Types                []string         `json:"types,omitempty" yaml:"types,omitempty"`
	Class                string           `json:"class,omitempty" yaml:"class,omitempty"`
	Resolvers            []string         `json:"resolvers,omitempty" yaml:"resolvers,omitempty"`
	Strategy             ResolverStrategy `json:"strategy,omitempty" yaml:"strategy,omitempty"`
	Recursive            *bool            `json:"recursive,omitempty" yaml:"recursive,omitempty"`
	CheckingDisabled     bool             `json:"checking_disabled,omitempty" yaml:"checking_disabled,omitempty"`
	AuthoritativeOnly    bool             `json:"authoritative_only,omitempty" yaml:"authoritative_only,omitempty"`
	EDNS                 EDNSOptions      `json:"edns,omitempty" yaml:"edns,omitempty"`
	Transfer             TransferOptions  `json:"transfer,omitempty" yaml:"transfer,omitempty"`
	Globalping           bool             `json:"globalping,omitempty" yaml:"globalping,omitempty"`
	GlobalpingLocations  []string         `json:"globalping_locations,omitempty" yaml:"globalping_locations,omitempty"`
	GlobalpingLimit      int              `json:"globalping_limit,omitempty" yaml:"globalping_limit,omitempty"`
	GlobalpingToken      string           `json:"-" yaml:"-"`
	GlobalpingEndpoint   string           `json:"-" yaml:"-"`
	GlobalpingHTTPClient *http.Client     `json:"-" yaml:"-"`
}

// DNSFlags is the stable subset of a DNS message header useful to callers.
type DNSFlags struct {
	Response           bool `json:"response" yaml:"response"`
	Authoritative      bool `json:"authoritative" yaml:"authoritative"`
	Truncated          bool `json:"truncated" yaml:"truncated"`
	RecursionDesired   bool `json:"recursion_desired" yaml:"recursion_desired"`
	RecursionAvailable bool `json:"recursion_available" yaml:"recursion_available"`
	AuthenticatedData  bool `json:"authenticated_data" yaml:"authenticated_data"`
	CheckingDisabled   bool `json:"checking_disabled" yaml:"checking_disabled"`
}

// DNSMessage captures one complete DNS exchange, including every response
// section and transport metadata.
type DNSMessage struct {
	Name           string        `json:"name" yaml:"name"`
	Type           string        `json:"type" yaml:"type"`
	Class          string        `json:"class" yaml:"class"`
	Resolver       string        `json:"resolver" yaml:"resolver"`
	Transport      string        `json:"transport" yaml:"transport"`
	Server         string        `json:"server" yaml:"server"`
	Duration       time.Duration `json:"duration_ns" yaml:"duration_ns"`
	ID             uint16        `json:"id" yaml:"id"`
	Opcode         string        `json:"opcode" yaml:"opcode"`
	Rcode          string        `json:"rcode" yaml:"rcode"`
	Flags          DNSFlags      `json:"flags" yaml:"flags"`
	Answer         []DNSRecord   `json:"answer,omitempty" yaml:"answer,omitempty"`
	Authority      []DNSRecord   `json:"authority,omitempty" yaml:"authority,omitempty"`
	Additional     []DNSRecord   `json:"additional,omitempty" yaml:"additional,omitempty"`
	ExtendedErrors []string      `json:"extended_errors,omitempty" yaml:"extended_errors,omitempty"`
	DNSSEC         string        `json:"dnssec" yaml:"dnssec"`
	Raw            []byte        `json:"raw,omitempty" yaml:"raw,omitempty"`
	Error          string        `json:"error,omitempty" yaml:"error,omitempty"`
}

// DNSDifference is one normalized disagreement between resolvers.
type DNSDifference struct {
	Resolver string   `json:"resolver" yaml:"resolver"`
	Name     string   `json:"name,omitempty" yaml:"name,omitempty"`
	Type     string   `json:"type,omitempty" yaml:"type,omitempty"`
	Class    string   `json:"class,omitempty" yaml:"class,omitempty"`
	Missing  []string `json:"missing,omitempty" yaml:"missing,omitempty"`
	Extra    []string `json:"extra,omitempty" yaml:"extra,omitempty"`
}

// DNSTraceHop is one iterative delegation step.
type DNSTraceHop struct {
	Zone        string        `json:"zone" yaml:"zone"`
	Server      string        `json:"server" yaml:"server"`
	Duration    time.Duration `json:"duration_ns" yaml:"duration_ns"`
	Rcode       string        `json:"rcode" yaml:"rcode"`
	Nameservers []string      `json:"nameservers,omitempty" yaml:"nameservers,omitempty"`
	Addresses   []string      `json:"addresses,omitempty" yaml:"addresses,omitempty"`
	DNSSEC      string        `json:"dnssec" yaml:"dnssec"`
	Glue        string        `json:"glue,omitempty" yaml:"glue,omitempty"`
	Lame        bool          `json:"lame,omitempty" yaml:"lame,omitempty"`
	Error       string        `json:"error,omitempty" yaml:"error,omitempty"`
}

// DNSOperationResult is the common result for every DNS engine operation.
type DNSOperationResult struct {
	Mode        string                 `json:"mode" yaml:"mode"`
	Messages    []DNSMessage           `json:"messages,omitempty" yaml:"messages,omitempty"`
	Inventory   *DNSResult             `json:"inventory,omitempty" yaml:"inventory,omitempty"`
	Differences []DNSDifference        `json:"differences,omitempty" yaml:"differences,omitempty"`
	Trace       []DNSTraceHop          `json:"trace,omitempty" yaml:"trace,omitempty"`
	Transfer    *DNSResult             `json:"transfer,omitempty" yaml:"transfer,omitempty"`
	Warnings    []string               `json:"warnings,omitempty" yaml:"warnings,omitempty"`
	Remote      []RemoteDNSMeasurement `json:"remote,omitempty" yaml:"remote,omitempty"`
}

type nativeDNSProvider struct {
	httpClient     *http.Client
	exchangeFunc   func(context.Context, *mdns.Msg, resolverSpec) (*mdns.Msg, []byte, error)
	exchangeSlots  chan struct{}
	transportMu    sync.Mutex
	h3Transports   map[string]*http3.Transport
	doqConnections map[string]*quic.Conn
	dnscryptInfo   map[string]*dnscrypt.ResolverInfo
}

func newNativeDNSProvider() DNSProvider {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxConnsPerHost = 16
	transport.MaxIdleConnsPerHost = 8
	return &nativeDNSProvider{
		httpClient: &http.Client{Timeout: dnsQueryTimeout, Transport: transport}, exchangeSlots: make(chan struct{}, 16),
		h3Transports: make(map[string]*http3.Transport), doqConnections: make(map[string]*quic.Conn), dnscryptInfo: make(map[string]*dnscrypt.ResolverInfo),
	}
}

func (provider *nativeDNSProvider) Close() error {
	provider.transportMu.Lock()
	defer provider.transportMu.Unlock()
	for key, transport := range provider.h3Transports {
		_ = transport.Close()
		delete(provider.h3Transports, key)
	}
	for key, connection := range provider.doqConnections {
		_ = connection.CloseWithError(0, "engine closed")
		delete(provider.doqConnections, key)
	}
	clear(provider.dnscryptInfo)
	if provider.httpClient != nil {
		if transport, ok := provider.httpClient.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}
	return nil
}

type resolverSpec struct {
	original   string
	transport  string
	address    string
	url        string
	serverName string
}

func (provider *nativeDNSProvider) Query(ctx context.Context, name string, options DNSOptions) (*DNSOperationResult, error) {
	types, class, resolvers, strategy, err := normalizeDNSOperation(options)
	if err != nil {
		return nil, lookupError(ErrorInvalidInput, err.Error(), nil)
	}
	result := &DNSOperationResult{Mode: "query"}
	for _, typeID := range types {
		messages := provider.queryResolvers(ctx, name, typeID, class, resolvers, strategy, options)
		result.Messages = append(result.Messages, messages...)
	}
	if strategy == ResolverConsensus {
		result.Differences = compareDNSMessages(result.Messages)
	}
	if len(result.Messages) == 0 {
		return nil, lookupError(ErrorUnavailable, "no DNS query completed", nil)
	}
	if options.AuthoritativeOnly {
		filtered := result.Messages[:0]
		for _, message := range result.Messages {
			if message.Flags.Authoritative || message.Error != "" {
				filtered = append(filtered, message)
			}
		}
		result.Messages = filtered
	}
	succeeded := 0
	for _, message := range result.Messages {
		if message.Error == "" {
			succeeded++
		}
	}
	if options.Globalping {
		remote, remoteErr := queryGlobalping(ctx, name, types, options)
		result.Remote = append(result.Remote, remote...)
		if remoteErr != nil {
			if succeeded == 0 {
				return result, remoteErr
			}
			return result, remoteErr
		}
	}
	if succeeded == 0 && len(result.Remote) == 0 {
		return result, lookupError(ErrorUnavailable, "all DNS resolvers failed", nil)
	}
	return result, nil
}

func (provider *nativeDNSProvider) Inventory(ctx context.Context, zone string, options DNSOptions) (*DNSOperationResult, error) {
	result := &DNSOperationResult{Mode: "inventory", Inventory: &DNSResult{Method: "inventory"}}
	remoteOptions := options
	options.Globalping = false

	wildcardQueries := make([]dnsQuery, 0, 5)
	wildcardName := randomDNSLabel() + "." + zone
	for _, typeID := range []uint16{mdns.TypeA, mdns.TypeAAAA, mdns.TypeTXT, mdns.TypeSRV, mdns.TypeHTTPS} {
		wildcardQueries = append(wildcardQueries, dnsQuery{name: wildcardName, typeID: typeID, guessed: true})
	}
	wildcards := make(map[string]struct{})
	for _, response := range provider.runInventoryQueries(ctx, wildcardQueries, options) {
		if response.err != nil || response.answer == nil {
			continue
		}
		for _, message := range response.answer.Messages {
			for _, record := range message.Answer {
				wildcards[dnsRecordSignature(record)] = struct{}{}
			}
		}
	}
	if len(wildcards) > 0 {
		result.Warnings = appendDNSWarning(result.Warnings, "wildcard DNS answers detected during discovery")
	}

	patternResponses := provider.runInventoryQueries(ctx, dnsPatternQueries(zone), options)
	targets, suppressed, failedQueries := provider.collectInventoryResponses(result, zone, patternResponses, wildcards)
	totalQueries := len(patternResponses)
	if suppressed {
		result.Warnings = appendDNSWarning(result.Warnings, "wildcard DNS answers were detected; matching guessed records were omitted")
	}
	follow := make([]dnsQuery, 0, len(targets)*2)
	for _, target := range limitedDNSNames(targets, maximumDynamicDNSNames) {
		follow = append(follow, dnsQuery{name: target, typeID: mdns.TypeA}, dnsQuery{name: target, typeID: mdns.TypeAAAA})
	}
	followResponses := provider.runInventoryQueries(ctx, follow, options)
	_, _, followFailures := provider.collectInventoryResponses(result, zone, followResponses, nil)
	failedQueries += followFailures
	totalQueries += len(followResponses)

	result.Inventory.Records = uniqueDNSRecords(result.Inventory.Records)
	result.Inventory.Nameservers = uniqueDNSNames(result.Inventory.Nameservers)
	result.Inventory.Warnings = append(result.Inventory.Warnings, result.Warnings...)
	if remoteOptions.Globalping {
		remote, remoteErr := queryGlobalping(ctx, zone, []uint16{mdns.TypeA}, remoteOptions)
		result.Remote = append(result.Remote, remote...)
		if remoteErr != nil {
			return result, remoteErr
		}
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if failedQueries > 0 {
		return result, lookupError(ErrorUnavailable, fmt.Sprintf("%d of %d DNS inventory queries failed", failedQueries, totalQueries), nil)
	}
	return result, nil
}

type inventoryResponse struct {
	query  dnsQuery
	answer *DNSOperationResult
	err    error
}

func (provider *nativeDNSProvider) runInventoryQueries(ctx context.Context, queries []dnsQuery, options DNSOptions) []inventoryResponse {
	responses := make([]inventoryResponse, len(queries))
	if len(queries) == 0 {
		return responses
	}
	jobs := make(chan int)
	workers := min(maximumDNSWorkers, len(queries))
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range jobs {
				query := queries[index]
				queryOptions := options
				queryOptions.Types = []string{mdns.TypeToString[query.typeID]}
				answer, err := provider.Query(ctx, query.name, queryOptions)
				responses[index] = inventoryResponse{query: query, answer: answer, err: err}
			}
		}()
	}
	for index := range queries {
		select {
		case jobs <- index:
		case <-ctx.Done():
			close(jobs)
			group.Wait()
			return responses
		}
	}
	close(jobs)
	group.Wait()
	return responses
}

func (provider *nativeDNSProvider) collectInventoryResponses(result *DNSOperationResult, zone string, responses []inventoryResponse, wildcards map[string]struct{}) ([]string, bool, int) {
	var targets []string
	suppressed := false
	failed := 0
	for _, response := range responses {
		if response.err != nil {
			failed++
			if !errors.Is(response.err, context.Canceled) && !errors.Is(response.err, context.DeadlineExceeded) {
				result.Warnings = appendDNSWarning(result.Warnings, response.err.Error())
			}
			continue
		}
		if response.answer == nil {
			failed++
			continue
		}
		result.Messages = append(result.Messages, response.answer.Messages...)
		for _, message := range response.answer.Messages {
			if message.Error != "" {
				continue
			}
			for _, record := range message.Answer {
				if !inDNSZone(record.Name, zone) {
					continue
				}
				if response.query.guessed && wildcards != nil {
					if _, matched := wildcards[dnsRecordSignature(record)]; matched {
						suppressed = true
						continue
					}
				}
				result.Inventory.Records = append(result.Inventory.Records, record)
				if record.Type == "NS" && normalizeDNSName(record.Name) == normalizeDNSName(zone) {
					result.Inventory.Nameservers = append(result.Inventory.Nameservers, normalizeDNSName(record.Value))
				}
				if target := dnsRecordValueTarget(record); target != "" && inDNSZone(target, zone) {
					targets = append(targets, target)
				}
			}
		}
	}
	targets = uniqueDNSNames(targets)
	sort.Strings(targets)
	return targets, suppressed, failed
}

func dnsRecordValueTarget(record DNSRecord) string {
	fields := strings.Fields(record.Value)
	if len(fields) == 0 {
		return ""
	}
	switch strings.ToUpper(record.Type) {
	case "CNAME", "NS", "PTR":
		return normalizeDNSName(fields[0])
	case "MX", "SRV":
		return normalizeDNSName(fields[len(fields)-1])
	case "SVCB", "HTTPS":
		if len(fields) > 1 {
			return normalizeDNSName(fields[1])
		}
	}
	return ""
}

func (provider *nativeDNSProvider) Compare(ctx context.Context, name string, options DNSOptions) (*DNSOperationResult, error) {
	if len(options.Resolvers) == 0 {
		options.Resolvers = append([]string{"system"}, authoritativeResolverMarker)
	} else if len(options.Resolvers) == 1 && !strings.EqualFold(strings.TrimSpace(options.Resolvers[0]), authoritativeResolverMarker) {
		options.Resolvers = append(options.Resolvers, authoritativeResolverMarker)
	}
	var authoritative []resolverSpec
	ordinary := make([]string, 0, len(options.Resolvers))
	for _, value := range options.Resolvers {
		if strings.EqualFold(strings.TrimSpace(value), authoritativeResolverMarker) {
			resolved, err := provider.authoritativeResolvers(ctx, name, options)
			if err != nil {
				return nil, err
			}
			authoritative = append(authoritative, resolved...)
		} else {
			ordinary = append(ordinary, value)
		}
	}
	var resolvers []resolverSpec
	if len(ordinary) > 0 {
		var err error
		resolvers, err = parseResolverSpecs(ordinary)
		if err != nil {
			return nil, lookupError(ErrorInvalidInput, err.Error(), nil)
		}
	}
	resolvers = append(resolvers, authoritative...)
	if len(resolvers) == 0 {
		return nil, lookupError(ErrorUnavailable, "no comparison resolver is available", nil)
	}
	options.Strategy = ResolverAll
	types, class, _, _, err := normalizeDNSOperation(options)
	if err != nil {
		return nil, err
	}
	result := &DNSOperationResult{Mode: "compare"}
	for _, typeID := range types {
		result.Messages = append(result.Messages, provider.queryResolvers(ctx, name, typeID, class, resolvers, ResolverAll, options)...)
	}
	var remoteErr error
	if options.Globalping {
		var remote []RemoteDNSMeasurement
		remote, remoteErr = queryGlobalping(ctx, name, types, options)
		result.Remote = append(result.Remote, remote...)
		if remoteErr != nil {
			result.Warnings = appendDNSWarning(result.Warnings, remoteErr.Error())
		}
	}
	result.Differences = compareDNSMessages(result.Messages)
	succeeded := 0
	for _, message := range result.Messages {
		if message.Error == "" {
			succeeded++
		}
	}
	if succeeded == 0 && len(result.Remote) == 0 {
		if remoteErr != nil {
			return result, remoteErr
		}
		return result, lookupError(ErrorUnavailable, "all DNS resolvers failed", nil)
	}
	if remoteErr != nil {
		return result, remoteErr
	}
	return result, nil
}

const authoritativeResolverMarker = "authoritative"

func (provider *nativeDNSProvider) Trace(ctx context.Context, name string, options DNSOptions) (*DNSOperationResult, error) {
	types, class, _, _, err := normalizeDNSOperation(options)
	if err != nil {
		return nil, err
	}
	typeID := types[0]
	servers := append([]string(nil), rootServerAddresses...)
	zone := "."
	result := &DNSOperationResult{Mode: "trace"}
	seen := make(map[string]bool)
	for depth := 0; depth < 32 && len(servers) > 0; depth++ {
		server := servers[0]
		servers = servers[1:]
		key := zone + "|" + server
		if seen[key] {
			continue
		}
		seen[key] = true
		spec := resolverSpec{original: "udp://" + server, transport: "udp", address: server}
		traceOptions := options
		recursive := false
		traceOptions.Recursive = &recursive
		traceOptions.EDNS.DNSSEC = true
		message := provider.exchange(ctx, name, typeID, class, spec, traceOptions)
		hop := DNSTraceHop{Zone: zone, Server: server, Duration: message.Duration, Rcode: message.Rcode, DNSSEC: traceDNSSECState(message), Error: message.Error}
		result.Messages = append(result.Messages, message)
		if message.Error != "" {
			result.Trace = append(result.Trace, hop)
			continue
		}
		if len(message.Answer) > 0 || message.Rcode == "NXDOMAIN" {
			result.Trace = append(result.Trace, hop)
			return result, nil
		}
		referralZone := ""
		for _, record := range message.Authority {
			if record.Type == "NS" {
				referralZone = record.Name
				hop.Nameservers = append(hop.Nameservers, normalizeDNSName(record.Value))
			}
		}
		for _, record := range message.Additional {
			if record.Type == "A" || record.Type == "AAAA" {
				for _, nameserver := range hop.Nameservers {
					if normalizeDNSName(record.Name) == nameserver {
						hop.Addresses = append(hop.Addresses, record.Value)
					}
				}
			}
		}
		hop.Nameservers = uniqueDNSNames(hop.Nameservers)
		hop.Addresses = uniqueStrings(hop.Addresses)
		inBailiwick, missingGlue := 0, 0
		for _, nameserver := range hop.Nameservers {
			if inDNSZone(nameserver, referralZone) {
				inBailiwick++
				found := false
				for _, record := range message.Additional {
					if (record.Type == "A" || record.Type == "AAAA") && normalizeDNSName(record.Name) == nameserver {
						found = true
						break
					}
				}
				if !found {
					missingGlue++
				}
			}
		}
		if inBailiwick > 0 {
			hop.Glue = "present"
			if missingGlue > 0 {
				hop.Glue = fmt.Sprintf("missing for %d of %d in-bailiwick nameservers", missingGlue, inBailiwick)
				result.Warnings = appendDNSWarning(result.Warnings, referralZone+": "+hop.Glue)
			}
		} else if len(hop.Nameservers) > 0 {
			hop.Glue = "not required (out-of-bailiwick)"
		}
		if referralZone == "" {
			hop.Lame = true
			result.Trace = append(result.Trace, hop)
			return result, lookupError(ErrorProtocol, "iterative trace stopped without an answer or referral", nil)
		}
		result.Trace = append(result.Trace, hop)
		zone = referralZone
		servers = nil
		for _, address := range hop.Addresses {
			servers = append(servers, net.JoinHostPort(address, "53"))
		}
		if len(servers) == 0 {
			resolved, resolveErr := provider.resolveNameserverAddresses(ctx, hop.Nameservers, options)
			if resolveErr != nil {
				return result, resolveErr
			}
			servers = resolved
		}
	}
	return result, lookupError(ErrorUnavailable, "iterative trace exceeded its delegation limit", nil)
}

func traceDNSSECState(message DNSMessage) string {
	for _, record := range message.Authority {
		if record.Type == "DS" {
			return "secure"
		}
	}
	if len(message.Answer) > 0 {
		return message.DNSSEC
	}
	return "insecure"
}

func (provider *nativeDNSProvider) Transfer(ctx context.Context, zone string, options DNSOptions) (*DNSOperationResult, error) {
	resolvers, err := provider.authoritativeResolvers(ctx, zone, options)
	if err != nil {
		return nil, err
	}
	transferType := strings.ToUpper(strings.TrimSpace(options.Transfer.Type))
	if transferType == "" {
		transferType = "AXFR"
	}
	if transferType != "AXFR" && transferType != "IXFR" {
		return nil, lookupError(ErrorInvalidInput, "transfer type must be AXFR or IXFR", nil)
	}
	result := &DNSOperationResult{Mode: "transfer"}
	var failures []string
	for _, resolver := range resolvers {
		records, transferErr := transferDNSZone(ctx, zone, resolver, options.Transfer)
		if transferErr == nil {
			result.Transfer = &DNSResult{Method: strings.ToLower(transferType), Complete: true, Nameservers: []string{resolver.address}, Records: records}
			return result, nil
		}
		failures = append(failures, resolver.address+": "+transferErr.Error())
	}
	return result, lookupError(ErrorUnavailable, "zone transfer failed: "+strings.Join(failures, "; "), nil)
}

func normalizeDNSOperation(options DNSOptions) ([]uint16, uint16, []resolverSpec, ResolverStrategy, error) {
	if options.EDNS.BufferSize != 0 && options.EDNS.BufferSize < 512 {
		return nil, 0, nil, "", fmt.Errorf("EDNS buffer size must be at least 512 bytes")
	}
	if options.EDNS.ECS != "" {
		if _, err := netip.ParsePrefix(options.EDNS.ECS); err != nil {
			return nil, 0, nil, "", fmt.Errorf("invalid EDNS client subnet %q: %w", options.EDNS.ECS, err)
		}
	}
	if options.EDNS.Cookie != "" {
		cookie, err := hex.DecodeString(strings.TrimSpace(options.EDNS.Cookie))
		if err != nil || len(cookie) < 8 || len(cookie) > 40 {
			return nil, 0, nil, "", fmt.Errorf("EDNS cookie must be 8 to 40 bytes of hexadecimal data")
		}
	}
	if options.GlobalpingLimit < 0 || options.GlobalpingLimit > 10 {
		return nil, 0, nil, "", fmt.Errorf("globalping limit must be between 1 and 10")
	}
	if (options.Transfer.TSIGName == "") != (options.Transfer.TSIGSecret == "") {
		return nil, 0, nil, "", fmt.Errorf("TSIG name and secret must be supplied together")
	}
	typeNames := options.Types
	if len(typeNames) == 0 {
		typeNames = []string{"A", "AAAA"}
	}
	if len(typeNames) > 32 {
		return nil, 0, nil, "", fmt.Errorf("at most 32 DNS record types may be requested")
	}
	types := make([]uint16, 0, len(typeNames))
	for _, name := range typeNames {
		value, err := parseDNSMnemonic(name, mdns.StringToType, "type")
		if err != nil {
			return nil, 0, nil, "", err
		}
		types = append(types, value)
	}
	class := uint16(mdns.ClassINET)
	if strings.TrimSpace(options.Class) != "" {
		value, err := parseDNSMnemonic(options.Class, mdns.StringToClass, "class")
		if err != nil {
			return nil, 0, nil, "", err
		}
		class = value
	}
	resolvers, err := parseResolverSpecs(options.Resolvers)
	if err != nil {
		return nil, 0, nil, "", err
	}
	if len(resolvers) > 16 {
		return nil, 0, nil, "", fmt.Errorf("at most 16 DNS resolvers may be used")
	}
	strategy := options.Strategy
	if strategy == "" {
		strategy = ResolverFirst
	}
	switch strategy {
	case ResolverFirst, ResolverAll, ResolverFastest, ResolverRandom, ResolverConsensus:
	default:
		return nil, 0, nil, "", fmt.Errorf("resolver strategy must be first, all, fastest, random, or consensus")
	}
	return types, class, resolvers, strategy, nil
}

// ValidateDNSOptions validates public DNS settings without performing network
// activity. It is useful to configuration UIs and SDK callers.
func ValidateDNSOptions(options DNSOptions) error {
	_, _, _, _, err := normalizeDNSOperation(options)
	return err
}

func parseDNSMnemonic(value string, known map[string]uint16, kind string) (uint16, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	if numeric := strings.TrimPrefix(value, map[bool]string{true: "TYPE", false: "CLASS"}[kind == "type"]); numeric != value {
		value = numeric
	}
	if number, err := strconv.ParseUint(value, 10, 16); err == nil {
		return uint16(number), nil
	}
	if number, ok := known[value]; ok {
		return number, nil
	}
	return 0, fmt.Errorf("unknown DNS %s %q", kind, value)
}

func parseResolverSpecs(values []string) ([]resolverSpec, error) {
	if len(values) == 0 {
		values = []string{"system"}
	}
	var specs []resolverSpec
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || strings.EqualFold(value, "system") || strings.EqualFold(value, "system://") {
			for _, address := range uniqueStrings(systemDNSResolvers()) {
				specs = append(specs, resolverSpec{original: "system", transport: "udp", address: address})
			}
			continue
		}
		if !strings.Contains(value, "://") {
			address, err := normalizeDNSResolver(value)
			if err != nil {
				return nil, err
			}
			specs = append(specs, resolverSpec{original: value, transport: "udp", address: address})
			continue
		}
		if strings.HasPrefix(strings.ToLower(value), "sdns://") {
			specs = append(specs, resolverSpec{original: value, transport: "dnscrypt", url: value})
			continue
		}
		parsed, err := url.Parse(value)
		if err != nil {
			return nil, fmt.Errorf("invalid resolver URI %q: %w", value, err)
		}
		scheme := strings.ToLower(parsed.Scheme)
		switch scheme {
		case "udp", "tcp", "tls", "dot":
			defaultPort := "53"
			transport := scheme
			if scheme == "tls" || scheme == "dot" {
				defaultPort, transport = "853", "tls"
			}
			host := parsed.Hostname()
			if host == "" {
				return nil, fmt.Errorf("resolver URI %q is missing a host", value)
			}
			port := parsed.Port()
			if port == "" {
				port = defaultPort
			}
			specs = append(specs, resolverSpec{original: value, transport: transport, address: net.JoinHostPort(host, port), serverName: host})
		case "https", "http", "doh", "h3":
			if scheme == "doh" {
				parsed.Scheme = "https"
			}
			if scheme == "h3" {
				parsed.Scheme = "https"
			}
			if parsed.Hostname() == "" {
				return nil, fmt.Errorf("resolver URI %q is missing a host", value)
			}
			specs = append(specs, resolverSpec{original: value, transport: scheme, url: parsed.String(), address: parsed.Host, serverName: parsed.Hostname()})
		case "doq":
			host := parsed.Hostname()
			if host == "" {
				return nil, fmt.Errorf("resolver URI %q is missing a host", value)
			}
			port := parsed.Port()
			if port == "" {
				port = "853"
			}
			specs = append(specs, resolverSpec{original: value, transport: "doq", address: net.JoinHostPort(host, port), serverName: host})
		case "dnscrypt":
			stamp := strings.TrimPrefix(value, "dnscrypt://")
			stamp = "sdns://" + strings.TrimPrefix(stamp, "sdns://")
			specs = append(specs, resolverSpec{original: value, transport: "dnscrypt", url: stamp})
		default:
			return nil, fmt.Errorf("unsupported resolver scheme %q", scheme)
		}
	}
	if len(specs) == 0 {
		return nil, errors.New("no DNS resolver is available")
	}
	return specs, nil
}

func (provider *nativeDNSProvider) queryResolvers(ctx context.Context, name string, typeID, class uint16, resolvers []resolverSpec, strategy ResolverStrategy, options DNSOptions) []DNSMessage {
	if strategy == ResolverRandom {
		resolvers = append([]resolverSpec(nil), resolvers...)
		for index := len(resolvers) - 1; index > 0; index-- {
			n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(index+1)))
			if err == nil {
				resolvers[index], resolvers[n.Int64()] = resolvers[n.Int64()], resolvers[index]
			}
		}
		strategy = ResolverFirst
	}
	if strategy == ResolverFirst {
		var messages []DNSMessage
		for _, resolver := range resolvers {
			message := provider.exchange(ctx, name, typeID, class, resolver, options)
			messages = append(messages, message)
			if message.Error == "" {
				break
			}
		}
		return messages
	}
	type indexed struct {
		index   int
		message DNSMessage
	}
	channel := make(chan indexed, len(resolvers))
	queryContext := ctx
	cancel := func() {}
	if strategy == ResolverFastest {
		queryContext, cancel = context.WithCancel(ctx)
	}
	defer cancel()
	for index, resolver := range resolvers {
		go func(index int, resolver resolverSpec) {
			channel <- indexed{index: index, message: provider.exchange(queryContext, name, typeID, class, resolver, options)}
		}(index, resolver)
	}
	if strategy == ResolverFastest {
		var failures []DNSMessage
		for range resolvers {
			value := <-channel
			if value.message.Error == "" {
				cancel()
				return []DNSMessage{value.message}
			}
			failures = append(failures, value.message)
		}
		return failures
	}
	messages := make([]DNSMessage, len(resolvers))
	for range resolvers {
		value := <-channel
		messages[value.index] = value.message
	}
	return messages
}

func (provider *nativeDNSProvider) exchange(ctx context.Context, name string, typeID, class uint16, resolver resolverSpec, options DNSOptions) DNSMessage {
	query := new(mdns.Msg)
	query.SetQuestion(mdns.Fqdn(name), typeID)
	query.Question[0].Qclass = class
	query.RecursionDesired = options.Recursive == nil || *options.Recursive
	query.CheckingDisabled = options.CheckingDisabled
	applyEDNS(query, options.EDNS)
	started := time.Now()
	if provider.exchangeSlots != nil {
		select {
		case provider.exchangeSlots <- struct{}{}:
			defer func() { <-provider.exchangeSlots }()
		case <-ctx.Done():
			return DNSMessage{Name: normalizeDNSName(name), Type: dnsTypeName(typeID), Class: dnsClassName(class), Resolver: resolver.original, Transport: resolver.transport, Server: resolver.address, DNSSEC: "indeterminate", Error: ctx.Err().Error()}
		}
	}
	response, raw, err := provider.exchangeMessage(ctx, query, resolver)
	duration := time.Since(started)
	message := DNSMessage{Name: normalizeDNSName(name), Type: dnsTypeName(typeID), Class: dnsClassName(class), Resolver: resolver.original, Transport: resolver.transport, Server: resolver.address, Duration: duration}
	if err != nil {
		message.Error = err.Error()
		message.DNSSEC = "indeterminate"
		return message
	}
	message.ID = response.Id
	message.Opcode = mdns.OpcodeToString[response.Opcode]
	message.Rcode = mdns.RcodeToString[response.Rcode]
	message.Flags = DNSFlags{Response: response.Response, Authoritative: response.Authoritative, Truncated: response.Truncated, RecursionDesired: response.RecursionDesired, RecursionAvailable: response.RecursionAvailable, AuthenticatedData: response.AuthenticatedData, CheckingDisabled: response.CheckingDisabled}
	message.Answer = recordsFromRR(response.Answer)
	message.Authority = recordsFromRR(response.Ns)
	message.Additional = recordsFromRR(response.Extra)
	message.ExtendedErrors = extendedDNSErrors(response)
	message.DNSSEC = dnsSecurityState(response)
	if options.EDNS.DNSSEC && query.RecursionDesired && class == mdns.ClassINET {
		state, detail := provider.validateDNSSEC(ctx, response, resolver, options)
		message.DNSSEC = state
		if state == "bogus" || state == "indeterminate" {
			message.ExtendedErrors = append(message.ExtendedErrors, detail)
		}
	}
	message.Raw = raw
	return message
}

func (provider *nativeDNSProvider) exchangeMessage(ctx context.Context, query *mdns.Msg, resolver resolverSpec) (*mdns.Msg, []byte, error) {
	if provider.exchangeFunc != nil {
		return provider.exchangeFunc(ctx, query, resolver)
	}
	switch resolver.transport {
	case "udp", "tcp", "tls":
		network := resolver.transport
		client := &mdns.Client{Net: network, Timeout: dnsExchangeTimeout(ctx)}
		if network == "tls" {
			client.Net = "tcp-tls"
			client.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: resolver.serverName}
		}
		response, _, err := client.ExchangeContext(ctx, query, resolver.address)
		if err == nil && response != nil && response.Truncated && network == "udp" {
			client.Net = "tcp"
			response, _, err = client.ExchangeContext(ctx, query, resolver.address)
		}
		if err != nil {
			return nil, nil, err
		}
		raw, _ := response.Pack()
		return response, raw, nil
	case "https", "http", "doh":
		return exchangeDoH(ctx, query, resolver.url, provider.httpClient)
	case "h3":
		transport := provider.h3Transport(resolver)
		client := &http.Client{Transport: transport, Timeout: dnsExchangeTimeout(ctx)}
		return exchangeDoH(ctx, query, resolver.url, client)
	case "doq":
		return provider.exchangeDoQ(ctx, query, resolver)
	case "dnscrypt":
		return provider.exchangeDNSCrypt(ctx, query, resolver)
	default:
		return nil, nil, fmt.Errorf("unsupported transport %s", resolver.transport)
	}
}

func (provider *nativeDNSProvider) h3Transport(resolver resolverSpec) *http3.Transport {
	key := resolver.serverName + "|" + resolver.url
	provider.transportMu.Lock()
	defer provider.transportMu.Unlock()
	if transport := provider.h3Transports[key]; transport != nil {
		return transport
	}
	transport := &http3.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: resolver.serverName}}
	provider.h3Transports[key] = transport
	return transport
}

func exchangeDoH(ctx context.Context, query *mdns.Msg, endpoint string, client *http.Client) (*mdns.Msg, []byte, error) {
	packed, err := query.Pack()
	if err != nil {
		return nil, nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(packed))
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("Accept", "application/dns-message")
	request.Header.Set("Content-Type", "application/dns-message")
	response, err := client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("DoH server returned HTTP %s", response.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, nil, err
	}
	message := new(mdns.Msg)
	if err := message.Unpack(raw); err != nil {
		return nil, nil, err
	}
	return message, raw, nil
}

func (provider *nativeDNSProvider) exchangeDoQ(ctx context.Context, query *mdns.Msg, resolver resolverSpec) (*mdns.Msg, []byte, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		connection, err := provider.doqConnection(ctx, resolver)
		if err != nil {
			return nil, nil, err
		}
		response, raw, err := exchangeDoQStream(ctx, query, connection)
		if err == nil {
			return response, raw, nil
		}
		lastErr = err
		provider.discardDoQConnection(resolver, connection)
	}
	return nil, nil, lastErr
}

func (provider *nativeDNSProvider) doqConnection(ctx context.Context, resolver resolverSpec) (*quic.Conn, error) {
	key := resolver.address + "|" + resolver.serverName
	provider.transportMu.Lock()
	connection := provider.doqConnections[key]
	if connection != nil && connection.Context().Err() != nil {
		delete(provider.doqConnections, key)
		connection = nil
	}
	provider.transportMu.Unlock()
	if connection != nil {
		return connection, nil
	}
	timeout := dnsExchangeTimeout(ctx)
	created, err := quic.DialAddr(ctx, resolver.address, &tls.Config{MinVersion: tls.VersionTLS13, ServerName: resolver.serverName, NextProtos: []string{"doq"}}, &quic.Config{HandshakeIdleTimeout: timeout, MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 15 * time.Second})
	if err != nil {
		return nil, err
	}
	provider.transportMu.Lock()
	if existing := provider.doqConnections[key]; existing != nil && existing.Context().Err() == nil {
		provider.transportMu.Unlock()
		_ = created.CloseWithError(0, "duplicate pooled connection")
		return existing, nil
	}
	provider.doqConnections[key] = created
	provider.transportMu.Unlock()
	return created, nil
}

func (provider *nativeDNSProvider) discardDoQConnection(resolver resolverSpec, connection *quic.Conn) {
	key := resolver.address + "|" + resolver.serverName
	provider.transportMu.Lock()
	if provider.doqConnections[key] == connection {
		delete(provider.doqConnections, key)
	}
	provider.transportMu.Unlock()
	_ = connection.CloseWithError(0, "connection unusable")
}

func exchangeDoQStream(ctx context.Context, query *mdns.Msg, connection *quic.Conn) (*mdns.Msg, []byte, error) {
	stream, err := connection.OpenStreamSync(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer stream.CancelRead(0)
	packed, err := query.Pack()
	if err != nil {
		return nil, nil, err
	}
	if len(packed) > int(^uint16(0)) {
		return nil, nil, fmt.Errorf("DNS query is too large for DoQ framing")
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}
	frameLength := uint16(len(packed)) // #nosec G115 -- the immediately preceding bound proves the conversion fits.
	if err := binary.Write(stream, binary.BigEndian, frameLength); err != nil {
		return nil, nil, err
	}
	if _, err := stream.Write(packed); err != nil {
		return nil, nil, err
	}
	if err := stream.Close(); err != nil {
		return nil, nil, err
	}
	var length uint16
	if err := binary.Read(stream, binary.BigEndian, &length); err != nil {
		return nil, nil, err
	}
	raw := make([]byte, int(length))
	if _, err := io.ReadFull(stream, raw); err != nil {
		return nil, nil, err
	}
	response := new(mdns.Msg)
	if err := response.Unpack(raw); err != nil {
		return nil, nil, err
	}
	return response, raw, nil
}

func (provider *nativeDNSProvider) exchangeDNSCrypt(ctx context.Context, query *mdns.Msg, resolver resolverSpec) (*mdns.Msg, []byte, error) {
	timeout := dnsExchangeTimeout(ctx)
	if timeout <= 0 {
		return nil, nil, context.DeadlineExceeded
	}
	client := &dnscrypt.Client{Net: "udp", Timeout: timeout, UDPSize: int(query.IsEdns0().UDPSize())}
	type result struct {
		response *mdns.Msg
		err      error
	}
	completed := make(chan result, 1)
	go func() {
		info, err := provider.dnscryptResolverInfo(client, resolver.url)
		if err != nil {
			completed <- result{err: err}
			return
		}
		response, err := client.Exchange(query, info)
		completed <- result{response: response, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case value := <-completed:
		if value.err != nil {
			return nil, nil, value.err
		}
		raw, err := value.response.Pack()
		return value.response, raw, err
	}
}

func (provider *nativeDNSProvider) dnscryptResolverInfo(client *dnscrypt.Client, stamp string) (*dnscrypt.ResolverInfo, error) {
	provider.transportMu.Lock()
	info := provider.dnscryptInfo[stamp]
	provider.transportMu.Unlock()
	if info != nil {
		return info, nil
	}
	created, err := client.Dial(stamp)
	if err != nil {
		return nil, err
	}
	provider.transportMu.Lock()
	if existing := provider.dnscryptInfo[stamp]; existing != nil {
		provider.transportMu.Unlock()
		return existing, nil
	}
	provider.dnscryptInfo[stamp] = created
	provider.transportMu.Unlock()
	return created, nil
}

func applyEDNS(message *mdns.Msg, options EDNSOptions) {
	bufferSize := options.BufferSize
	if bufferSize == 0 {
		bufferSize = 1232
	}
	message.SetEdns0(bufferSize, options.DNSSEC)
	opt := message.IsEdns0()
	if options.NSID {
		opt.Option = append(opt.Option, &mdns.EDNS0_NSID{Code: mdns.EDNS0NSID})
	}
	if options.ECS != "" {
		if prefix, err := netip.ParsePrefix(options.ECS); err == nil {
			family := uint16(1)
			if prefix.Addr().Is6() {
				family = 2
			}
			mask := uint8(prefix.Bits()) // #nosec G115 -- netip prefixes are limited to 32 or 128 bits.
			opt.Option = append(opt.Option, &mdns.EDNS0_SUBNET{Code: mdns.EDNS0SUBNET, Family: family, SourceNetmask: mask, Address: net.IP(prefix.Addr().AsSlice())})
		}
	}
	if options.Cookie != "" {
		opt.Option = append(opt.Option, &mdns.EDNS0_COOKIE{Code: mdns.EDNS0COOKIE, Cookie: strings.ToLower(strings.TrimSpace(options.Cookie))})
	}
	if options.Padding > 0 {
		opt.Option = append(opt.Option, &mdns.EDNS0_PADDING{Padding: make([]byte, options.Padding)})
	}
}

func recordsFromRR(records []mdns.RR) []DNSRecord {
	result := make([]DNSRecord, 0, len(records))
	for _, record := range records {
		if record == nil || record.Header() == nil || record.Header().Rrtype == mdns.TypeOPT {
			continue
		}
		result = append(result, DNSRecord{Name: normalizeDNSName(record.Header().Name), Type: dnsTypeName(record.Header().Rrtype), TTL: record.Header().Ttl, Value: dnsRData(record)})
	}
	return result
}

func dnsTypeName(value uint16) string {
	if name := mdns.TypeToString[value]; name != "" {
		return name
	}
	return fmt.Sprintf("TYPE%d", value)
}

func dnsClassName(value uint16) string {
	if name := mdns.ClassToString[value]; name != "" {
		return name
	}
	return fmt.Sprintf("CLASS%d", value)
}

func extendedDNSErrors(message *mdns.Msg) []string {
	var result []string
	for _, record := range message.Extra {
		opt, ok := record.(*mdns.OPT)
		if !ok {
			continue
		}
		for _, option := range opt.Option {
			if ede, ok := option.(*mdns.EDNS0_EDE); ok {
				result = append(result, fmt.Sprintf("%d %s", ede.InfoCode, strings.TrimSpace(ede.ExtraText)))
			}
		}
	}
	return result
}

func dnsSecurityState(message *mdns.Msg) string {
	if message.AuthenticatedData {
		return "secure"
	}
	hasSignatures := false
	for _, section := range [][]mdns.RR{message.Answer, message.Ns} {
		for _, record := range section {
			if record.Header().Rrtype == mdns.TypeRRSIG {
				hasSignatures = true
			}
		}
	}
	if hasSignatures {
		return "indeterminate"
	}
	return "insecure"
}

func compareDNSMessages(messages []DNSMessage) []DNSDifference {
	type comparisonGroup struct {
		messages []DNSMessage
	}
	groups := make(map[string]*comparisonGroup)
	var order []string
	for _, message := range messages {
		key := strings.ToLower(strings.TrimSuffix(message.Name, ".")) + "\x00" + strings.ToUpper(message.Type) + "\x00" + strings.ToUpper(message.Class)
		group := groups[key]
		if group == nil {
			group = &comparisonGroup{}
			groups[key] = group
			order = append(order, key)
		}
		group.messages = append(group.messages, message)
	}
	var differences []DNSDifference
	for _, key := range order {
		group := groups[key]
		var baseline []string
		for _, message := range group.messages {
			if message.Error == "" {
				baseline = normalizedAnswerSet(message)
				break
			}
		}
		for _, message := range group.messages {
			difference := DNSDifference{Resolver: message.Resolver, Name: message.Name, Type: message.Type, Class: message.Class}
			if message.Error != "" {
				difference.Missing = append([]string(nil), baseline...)
				difference.Extra = []string{"ERROR: " + message.Error}
				differences = append(differences, difference)
				continue
			}
			current := normalizedAnswerSet(message)
			difference.Missing = stringSetDifference(baseline, current)
			difference.Extra = stringSetDifference(current, baseline)
			if len(difference.Missing) > 0 || len(difference.Extra) > 0 {
				differences = append(differences, difference)
			}
		}
	}
	return differences
}

func normalizedAnswerSet(message DNSMessage) []string {
	values := make([]string, 0, len(message.Answer)+1)
	values = append(values, "RCODE="+message.Rcode)
	for _, record := range message.Answer {
		values = append(values, record.Name+" "+record.Type+" "+record.Value)
	}
	return uniqueStrings(values)
}

func stringSetDifference(left, right []string) []string {
	seen := make(map[string]bool, len(right))
	for _, value := range right {
		seen[value] = true
	}
	var result []string
	for _, value := range left {
		if !seen[value] {
			result = append(result, value)
		}
	}
	return result
}

func (provider *nativeDNSProvider) authoritativeResolvers(ctx context.Context, zone string, options DNSOptions) ([]resolverSpec, error) {
	queryOptions := options
	queryOptions.Globalping = false
	queryOptions.Types = []string{"NS"}
	queryOptions.Resolvers = nil
	queryOptions.Strategy = ResolverFirst
	query, err := provider.Query(ctx, zone, queryOptions)
	if err != nil {
		return nil, err
	}
	var nameservers []string
	for _, message := range query.Messages {
		for _, record := range message.Answer {
			if record.Type == "NS" {
				nameservers = append(nameservers, normalizeDNSName(record.Value))
			}
		}
	}
	addresses, err := provider.resolveNameserverAddresses(ctx, uniqueDNSNames(nameservers), options)
	if err != nil {
		return nil, err
	}
	result := make([]resolverSpec, 0, len(addresses))
	for _, address := range addresses {
		result = append(result, resolverSpec{original: "authoritative://" + address, transport: "udp", address: address})
	}
	return result, nil
}

func (provider *nativeDNSProvider) resolveNameserverAddresses(ctx context.Context, nameservers []string, options DNSOptions) ([]string, error) {
	var addresses []string
	for _, nameserver := range nameservers {
		queryOptions := options
		queryOptions.Globalping = false
		queryOptions.Types = []string{"A", "AAAA"}
		queryOptions.Resolvers = nil
		queryOptions.Strategy = ResolverFirst
		result, _ := provider.Query(ctx, nameserver, queryOptions)
		if result == nil {
			continue
		}
		for _, message := range result.Messages {
			for _, record := range message.Answer {
				if record.Type == "A" || record.Type == "AAAA" {
					addresses = append(addresses, net.JoinHostPort(record.Value, "53"))
				}
			}
		}
	}
	addresses = uniqueStrings(addresses)
	if len(addresses) == 0 {
		return nil, lookupError(ErrorDiscovery, "authoritative nameservers had no reachable addresses", nil)
	}
	return addresses, nil
}

func transferDNSZone(ctx context.Context, zone string, resolver resolverSpec, options TransferOptions) ([]DNSRecord, error) {
	timeout := dnsExchangeTimeout(ctx)
	message := new(mdns.Msg)
	transferType := strings.ToUpper(strings.TrimSpace(options.Type))
	if transferType == "IXFR" {
		message.SetIxfr(mdns.Fqdn(zone), options.Serial, ".", ".")
	} else {
		message.SetAxfr(mdns.Fqdn(zone))
	}
	transfer := &mdns.Transfer{DialTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout}
	address := resolver.address
	if options.TLS {
		transfer.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: resolver.serverName}
		if host, _, err := net.SplitHostPort(address); err == nil {
			address = net.JoinHostPort(host, "853")
		}
	}
	if options.TSIGName != "" && options.TSIGSecret != "" {
		algorithm := options.TSIGAlgo
		if algorithm == "" {
			algorithm = mdns.HmacSHA256
		}
		message.SetTsig(mdns.Fqdn(options.TSIGName), algorithm, 300, time.Now().Unix())
		transfer.TsigSecret = map[string]string{mdns.Fqdn(options.TSIGName): options.TSIGSecret}
	}
	envelopes, err := transfer.In(message, address)
	if err != nil {
		return nil, err
	}
	var records []DNSRecord
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case envelope, ok := <-envelopes:
			if !ok {
				if len(records) == 0 {
					return nil, errors.New("transfer returned no records")
				}
				return uniqueDNSRecords(records), nil
			}
			if envelope.Error != nil {
				return nil, envelope.Error
			}
			records = append(records, recordsFromRR(envelope.RR)...)
			if len(records) > maximumAXFRRecords {
				return nil, fmt.Errorf("transfer exceeded the %d-record safety limit", maximumAXFRRecords)
			}
		}
	}
}

var rootServerAddresses = []string{
	"198.41.0.4:53", "170.247.170.2:53", "192.33.4.12:53", "199.7.91.13:53",
	"192.203.230.10:53", "192.5.5.241:53", "192.112.36.4:53", "198.97.190.53:53",
	"192.36.148.17:53", "192.58.128.30:53", "193.0.14.129:53", "199.7.83.42:53", "202.12.27.33:53",
}
