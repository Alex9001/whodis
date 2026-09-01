package whodis

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
)

const (
	maximumDNSScanDuration = 5 * time.Second
	dnsQueryTimeout        = 2 * time.Second
	maximumDNSWorkers      = 8
	maximumDynamicDNSNames = 32
	maximumAXFRRecords     = 100000
)

type dnsScanner struct {
	resolvers    []string
	queryFunc    func(context.Context, string, uint16) ([]mdns.RR, error)
	transferFunc func(context.Context, string, []string) ([]DNSRecord, error)
}

type dnsQuery struct {
	name    string
	typeID  uint16
	guessed bool
}

type dnsRecordCandidate struct {
	record DNSRecord
	target string
}

type dnsQueryResult struct {
	query   dnsQuery
	records []dnsRecordCandidate
	err     error
}

// dnsScanTimeout makes automatic enrichment predictably bounded without
// shortening a caller's explicitly requested overall lookup deadline.
func dnsScanTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 || timeout > maximumDNSScanDuration {
		return maximumDNSScanDuration
	}
	return timeout
}

func (c *Client) lookupDNS(ctx context.Context, target Target, options LookupOptions) *DNSResult {
	resolvers, err := dnsResolvers(options.DNSResolver)
	if err != nil {
		return &DNSResult{Method: "scan", Warnings: []string{err.Error()}}
	}
	scanner := dnsScanner{resolvers: resolvers}
	return scanDNSWithScanner(ctx, target.Canonical, options.DNSMode, scanner)
}

func scanDNSWithScanner(ctx context.Context, zone string, mode DNSMode, scanner dnsScanner) *DNSResult {
	if mode == DNSAXFR {
		nameservers, err := scanner.authoritativeNameservers(ctx, zone)
		if err == nil {
			transfer, transferErr := scanner.transferZone(ctx, zone, nameservers)
			if transferErr == nil {
				return transfer
			}
			fallback := scanner.patternScan(ctx, zone)
			fallback.Nameservers = uniqueDNSNames(append(fallback.Nameservers, nameservers...))
			fallback.Warnings = appendDNSWarning(fallback.Warnings, "AXFR was refused or unavailable; showing discovered records instead")
			return fallback
		}
		fallback := scanner.patternScan(ctx, zone)
		fallback.Warnings = appendDNSWarning(fallback.Warnings, "AXFR could not discover authoritative nameservers; showing discovered records instead")
		return fallback
	}

	return scanner.patternScan(ctx, zone)
}

func dnsResolvers(override string) ([]string, error) {
	if strings.TrimSpace(override) != "" {
		resolver, err := normalizeDNSResolver(override)
		if err != nil {
			return nil, err
		}
		return []string{resolver}, nil
	}
	resolvers := uniqueStrings(systemDNSResolvers())
	if len(resolvers) == 0 {
		return nil, errors.New("could not determine a system DNS resolver; use --resolver host[:port]")
	}
	return resolvers, nil
}

func normalizeDNSResolver(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("dns resolver cannot be empty")
	}
	if address := net.ParseIP(value); address != nil {
		return net.JoinHostPort(address.String(), "53"), nil
	}
	host, port, err := net.SplitHostPort(value)
	if err == nil {
		if strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
			return "", errors.New("dns resolver must be a host or IP address with an optional port")
		}
		if _, err := net.LookupPort("udp", port); err != nil {
			return "", fmt.Errorf("invalid dns resolver port %q", port)
		}
		return net.JoinHostPort(host, port), nil
	}
	if strings.Contains(value, ":") {
		return "", errors.New("IPv6 DNS resolvers with a port must be written as [address]:port")
	}
	return net.JoinHostPort(value, "53"), nil
}

func (s dnsScanner) patternScan(ctx context.Context, zone string) *DNSResult {
	result := &DNSResult{Method: "scan"}
	wildcards, wildcardWarning := s.wildcardRecords(ctx, zone)
	if wildcardWarning != "" {
		result.Warnings = appendDNSWarning(result.Warnings, wildcardWarning)
	}

	initial := s.runQueries(ctx, zone, dnsPatternQueries(zone))
	targets, wildcardSuppressed := collectDNSQueryResults(result, initial, zone, wildcards)
	if wildcardSuppressed {
		result.Warnings = appendDNSWarning(result.Warnings, "wildcard DNS answers were detected; matching guessed records were omitted")
	}

	follow := make([]dnsQuery, 0, len(targets)*2)
	for _, name := range limitedDNSNames(targets, maximumDynamicDNSNames) {
		follow = append(follow,
			dnsQuery{name: name, typeID: mdns.TypeA},
			dnsQuery{name: name, typeID: mdns.TypeAAAA},
		)
	}
	_, _ = collectDNSQueryResults(result, s.runQueries(ctx, zone, follow), zone, nil)
	result.Records = uniqueDNSRecords(result.Records)
	result.Nameservers = uniqueDNSNames(result.Nameservers)
	return result
}

func dnsPatternQueries(zone string) []dnsQuery {
	queries := make([]dnsQuery, 0, 72)
	for _, typeID := range []uint16{mdns.TypeA, mdns.TypeAAAA, mdns.TypeMX, mdns.TypeTXT, mdns.TypeNS, mdns.TypeSOA, mdns.TypeCAA, mdns.TypeHTTPS, mdns.TypeSVCB} {
		queries = append(queries, dnsQuery{name: zone, typeID: typeID})
	}
	for _, label := range []string{"www", "api", "cdn", "mail", "webmail", "smtp", "imap", "pop", "ftp", "autodiscover", "autoconfig", "cpanel", "whm", "cpcontacts", "cpcalendars"} {
		name := label + "." + zone
		queries = append(queries, dnsQuery{name: name, typeID: mdns.TypeA, guessed: true}, dnsQuery{name: name, typeID: mdns.TypeAAAA, guessed: true})
	}
	for _, label := range []string{"www", "api", "cdn"} {
		queries = append(queries, dnsQuery{name: label + "." + zone, typeID: mdns.TypeHTTPS, guessed: true})
	}
	for _, label := range []string{"_dmarc", "_mta-sts", "_smtp._tls"} {
		queries = append(queries, dnsQuery{name: label + "." + zone, typeID: mdns.TypeTXT, guessed: true})
	}
	for _, label := range []string{"default._domainkey", "google._domainkey", "selector1._domainkey", "selector2._domainkey"} {
		queries = append(queries, dnsQuery{name: label + "." + zone, typeID: mdns.TypeTXT, guessed: true})
	}
	for _, label := range []string{"_autodiscover._tcp", "_submission._tcp", "_imaps._tcp", "_pop3s._tcp", "_sip._tcp", "_sips._tcp", "_sip._udp"} {
		queries = append(queries, dnsQuery{name: label + "." + zone, typeID: mdns.TypeSRV, guessed: true})
	}
	return queries
}

func (s dnsScanner) wildcardRecords(ctx context.Context, zone string) (map[string]struct{}, string) {
	label := randomDNSLabel()
	queries := make([]dnsQuery, 0, 5)
	for _, typeID := range []uint16{mdns.TypeA, mdns.TypeAAAA, mdns.TypeTXT, mdns.TypeSRV, mdns.TypeHTTPS} {
		queries = append(queries, dnsQuery{name: label + "." + zone, typeID: typeID, guessed: true})
	}
	results := s.runQueries(ctx, zone, queries)
	values := make(map[string]struct{})
	for _, result := range results {
		for _, candidate := range result.records {
			values[dnsRecordSignature(candidate.record)] = struct{}{}
		}
	}
	if len(values) == 0 {
		return values, ""
	}
	return values, "wildcard DNS answers detected during discovery"
}

func randomDNSLabel() string {
	buffer := make([]byte, 8)
	if _, err := cryptorand.Read(buffer); err == nil {
		return "whodis-" + hex.EncodeToString(buffer)
	}
	return fmt.Sprintf("whodis-%d", time.Now().UnixNano())
}

func (s dnsScanner) runQueries(ctx context.Context, zone string, queries []dnsQuery) []dnsQueryResult {
	if len(queries) == 0 {
		return nil
	}
	results := make([]dnsQueryResult, len(queries))
	workers := make(chan struct{}, min(maximumDNSWorkers, len(queries)))
	var group sync.WaitGroup
	for index, query := range queries {
		group.Add(1)
		go func(index int, query dnsQuery) {
			defer group.Done()
			select {
			case workers <- struct{}{}:
				defer func() { <-workers }()
			case <-ctx.Done():
				results[index] = dnsQueryResult{query: query, err: ctx.Err()}
				return
			}
			answers, err := s.query(ctx, query.name, query.typeID)
			result := dnsQueryResult{query: query, err: err}
			for _, answer := range answers {
				if candidate, ok := dnsCandidateFromRR(answer, zone); ok {
					result.records = append(result.records, candidate)
				}
			}
			results[index] = result
		}(index, query)
	}
	group.Wait()
	return results
}

func (s dnsScanner) query(ctx context.Context, name string, typeID uint16) ([]mdns.RR, error) {
	if s.queryFunc != nil {
		return s.queryFunc(ctx, mdns.Fqdn(name), typeID)
	}
	message := new(mdns.Msg)
	message.SetQuestion(mdns.Fqdn(name), typeID)
	message.RecursionDesired = true
	message.SetEdns0(1232, false)
	var failures []string
	for _, resolver := range s.resolvers {
		response, err := dnsExchange(ctx, message, resolver, "udp")
		if err == nil && response != nil && response.Truncated {
			response, err = dnsExchange(ctx, message, resolver, "tcp")
		}
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		switch response.Rcode {
		case mdns.RcodeSuccess, mdns.RcodeNameError:
			return response.Answer, nil
		default:
			failures = append(failures, mdns.RcodeToString[response.Rcode])
		}
	}
	if len(failures) == 0 {
		return nil, errors.New("no DNS resolver was available")
	}
	return nil, fmt.Errorf("DNS query %s %s failed: %s", name, mdns.TypeToString[typeID], strings.Join(uniqueStrings(failures), "; "))
}

func dnsExchange(ctx context.Context, message *mdns.Msg, resolver, network string) (*mdns.Msg, error) {
	timeout := dnsExchangeTimeout(ctx)
	if timeout <= 0 {
		return nil, context.DeadlineExceeded
	}
	client := &mdns.Client{Net: network, Timeout: timeout}
	response, _, err := client.ExchangeContext(ctx, message, resolver)
	return response, err
}

func dnsExchangeTimeout(ctx context.Context) time.Duration {
	timeout := dnsQueryTimeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0
		}
		if remaining < timeout {
			timeout = remaining
		}
	}
	return timeout
}

func collectDNSQueryResults(result *DNSResult, queryResults []dnsQueryResult, zone string, wildcard map[string]struct{}) ([]string, bool) {
	targets := make([]string, 0)
	wildcardSuppressed := false
	for _, queryResult := range queryResults {
		if queryResult.err != nil {
			if !errors.Is(queryResult.err, context.Canceled) && !errors.Is(queryResult.err, context.DeadlineExceeded) {
				result.Warnings = appendDNSWarning(result.Warnings, queryResult.err.Error())
			}
			continue
		}
		for _, candidate := range queryResult.records {
			if queryResult.query.guessed && wildcard != nil {
				if _, matched := wildcard[dnsRecordSignature(candidate.record)]; matched {
					wildcardSuppressed = true
					continue
				}
			}
			result.Records = append(result.Records, candidate.record)
			if candidate.record.Type == "NS" && normalizeDNSName(candidate.record.Name) == normalizeDNSName(zone) {
				result.Nameservers = append(result.Nameservers, normalizeDNSName(candidate.record.Value))
			}
			if candidate.target != "" && inDNSZone(candidate.target, zone) {
				targets = append(targets, candidate.target)
			}
		}
	}
	return uniqueDNSNames(targets), wildcardSuppressed
}

func dnsCandidateFromRR(answer mdns.RR, zone string) (dnsRecordCandidate, bool) {
	if answer == nil || answer.Header() == nil || answer.Header().Class != mdns.ClassINET {
		return dnsRecordCandidate{}, false
	}
	record := DNSRecord{
		Name:  normalizeDNSName(answer.Header().Name),
		Type:  mdns.TypeToString[answer.Header().Rrtype],
		TTL:   answer.Header().Ttl,
		Value: dnsRData(answer),
	}
	if record.Name == "" || record.Type == "" || record.Value == "" || !inDNSZone(record.Name, zone) {
		return dnsRecordCandidate{}, false
	}
	return dnsRecordCandidate{record: record, target: dnsRecordTarget(answer)}, true
}

func dnsRData(record mdns.RR) string {
	switch value := record.(type) {
	case *mdns.A:
		return value.A.String()
	case *mdns.AAAA:
		return value.AAAA.String()
	case *mdns.CNAME:
		return value.Target
	case *mdns.NS:
		return value.Ns
	case *mdns.MX:
		return fmt.Sprintf("%d %s", value.Preference, value.Mx)
	case *mdns.PTR:
		return value.Ptr
	case *mdns.SRV:
		return fmt.Sprintf("%d %d %d %s", value.Priority, value.Weight, value.Port, value.Target)
	case *mdns.SOA:
		return fmt.Sprintf("%s %s %d %d %d %d %d", value.Ns, value.Mbox, value.Serial, value.Refresh, value.Retry, value.Expire, value.Minttl)
	case *mdns.TXT:
		parts := make([]string, 0, len(value.Txt))
		for _, text := range value.Txt {
			parts = append(parts, strconv.Quote(text))
		}
		return strings.Join(parts, " ")
	case *mdns.CAA:
		return fmt.Sprintf("%d %s %s", value.Flag, value.Tag, strconv.Quote(value.Value))
	}
	full := strings.TrimSpace(record.String())
	header := strings.TrimSpace(record.Header().String())
	if data := strings.TrimSpace(strings.TrimPrefix(full, header)); data != "" && data != full {
		return data
	}
	return full
}

func dnsRecordTarget(record mdns.RR) string {
	switch value := record.(type) {
	case *mdns.CNAME:
		return normalizeDNSName(value.Target)
	case *mdns.NS:
		return normalizeDNSName(value.Ns)
	case *mdns.MX:
		return normalizeDNSName(value.Mx)
	case *mdns.SRV:
		return normalizeDNSName(value.Target)
	case *mdns.SVCB:
		return normalizeDNSName(value.Target)
	case *mdns.HTTPS:
		return normalizeDNSName(value.Target)
	default:
		return ""
	}
}

func (s dnsScanner) authoritativeNameservers(ctx context.Context, zone string) ([]string, error) {
	answers, err := s.query(ctx, zone, mdns.TypeNS)
	if err != nil {
		return nil, err
	}
	nameservers := make([]string, 0)
	for _, answer := range answers {
		if value, ok := answer.(*mdns.NS); ok && normalizeDNSName(answer.Header().Name) == normalizeDNSName(zone) {
			nameservers = append(nameservers, normalizeDNSName(value.Ns))
		}
	}
	nameservers = uniqueDNSNames(nameservers)
	if len(nameservers) == 0 {
		return nil, errors.New("no authoritative nameservers were returned")
	}
	return nameservers, nil
}

func (s dnsScanner) transferZone(ctx context.Context, zone string, nameservers []string) (*DNSResult, error) {
	if s.transferFunc != nil {
		records, err := s.transferFunc(ctx, zone, nameservers)
		if err != nil {
			return nil, err
		}
		return &DNSResult{Method: "axfr", Complete: true, Nameservers: nameservers, Records: uniqueDNSRecords(records)}, nil
	}
	var failures []string
	for _, nameserver := range nameservers {
		addresses, err := s.nameserverAddresses(ctx, nameserver)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		for _, address := range addresses {
			records, err := transferFromNameserver(ctx, zone, address)
			if err == nil {
				return &DNSResult{Method: "axfr", Complete: true, Nameservers: nameservers, Records: records}, nil
			}
			failures = append(failures, err.Error())
		}
	}
	if len(failures) == 0 {
		return nil, errors.New("AXFR did not find a reachable authoritative nameserver")
	}
	return nil, errors.New(strings.Join(uniqueStrings(failures), "; "))
}

func (s dnsScanner) nameserverAddresses(ctx context.Context, nameserver string) ([]string, error) {
	addresses := make([]string, 0)
	for _, typeID := range []uint16{mdns.TypeA, mdns.TypeAAAA} {
		answers, err := s.query(ctx, nameserver, typeID)
		if err != nil {
			continue
		}
		for _, answer := range answers {
			switch value := answer.(type) {
			case *mdns.A:
				addresses = append(addresses, net.JoinHostPort(value.A.String(), "53"))
			case *mdns.AAAA:
				addresses = append(addresses, net.JoinHostPort(value.AAAA.String(), "53"))
			}
		}
	}
	addresses = uniqueStrings(addresses)
	if len(addresses) == 0 {
		return nil, fmt.Errorf("could not resolve authoritative nameserver %s", nameserver)
	}
	return addresses, nil
}

func transferFromNameserver(ctx context.Context, zone, address string) ([]DNSRecord, error) {
	timeout := dnsExchangeTimeout(ctx)
	if timeout <= 0 {
		return nil, context.DeadlineExceeded
	}
	message := new(mdns.Msg)
	message.SetAxfr(mdns.Fqdn(zone))
	transfer := &mdns.Transfer{DialTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout}
	envelopes, err := transfer.In(message, address)
	if err != nil {
		return nil, err
	}
	records := make([]DNSRecord, 0)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case envelope, ok := <-envelopes:
			if !ok {
				if len(records) == 0 {
					return nil, errors.New("AXFR returned no records")
				}
				return uniqueDNSRecords(records), nil
			}
			if envelope.Error != nil {
				return nil, envelope.Error
			}
			for _, answer := range envelope.RR {
				if candidate, ok := dnsCandidateFromRR(answer, zone); ok {
					records = append(records, candidate.record)
				}
				if len(records) > maximumAXFRRecords {
					return nil, fmt.Errorf("AXFR exceeded the %d-record safety limit", maximumAXFRRecords)
				}
			}
		}
	}
}

func normalizeDNSName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func inDNSZone(name, zone string) bool {
	name = normalizeDNSName(name)
	zone = normalizeDNSName(zone)
	return name == zone || strings.HasSuffix(name, "."+zone)
}

func limitedDNSNames(names []string, maximum int) []string {
	names = uniqueDNSNames(names)
	if len(names) <= maximum {
		return names
	}
	return names[:maximum]
}

func uniqueDNSNames(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	result := make([]string, 0, len(names))
	for _, name := range names {
		name = normalizeDNSName(name)
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func uniqueDNSRecords(records []DNSRecord) []DNSRecord {
	indexes := make(map[string]int, len(records))
	result := make([]DNSRecord, 0, len(records))
	for _, record := range records {
		key := dnsRecordKey(record)
		if index, exists := indexes[key]; exists {
			// TTL counts down in caches and therefore does not identify a
			// resource record. Keep the largest observation as the clearest
			// approximation of the published TTL.
			if record.TTL > result[index].TTL {
				result[index].TTL = record.TTL
			}
			continue
		}
		indexes[key] = len(result)
		result = append(result, record)
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].Type != result[right].Type {
			return dnsTypeOrder(result[left].Type) < dnsTypeOrder(result[right].Type)
		}
		if result[left].Name != result[right].Name {
			return result[left].Name < result[right].Name
		}
		if result[left].Value != result[right].Value {
			return result[left].Value < result[right].Value
		}
		return result[left].TTL < result[right].TTL
	})
	return result
}

func dnsRecordKey(record DNSRecord) string {
	return record.Name + "\x00" + record.Type + "\x00" + record.Value
}

func dnsRecordSignature(record DNSRecord) string {
	return record.Type + "\x00" + record.Value
}

func dnsTypeOrder(recordType string) int {
	order := map[string]int{"SOA": 1, "NS": 2, "A": 3, "AAAA": 4, "CNAME": 5, "MX": 6, "TXT": 7, "CAA": 8, "HTTPS": 9, "SVCB": 10, "SRV": 11}
	if position, ok := order[recordType]; ok {
		return position
	}
	return 100
}

func appendDNSWarning(warnings []string, warning string) []string {
	warning = strings.TrimSpace(warning)
	if warning == "" {
		return warnings
	}
	for _, current := range warnings {
		if current == warning {
			return warnings
		}
	}
	if len(warnings) >= 8 {
		return warnings
	}
	return append(warnings, warning)
}
