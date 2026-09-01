package whodis

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultRWHOISPort = "4321"
	maximumRWHOISLine = 1 << 20
	maximumRWHOISData = 8 << 20
)

type rwhoisAdapter struct{ client *Client }

func (rwhoisAdapter) Protocol() Protocol { return ProtocolRWHOIS }

func (a rwhoisAdapter) Lookup(ctx context.Context, target Target, route RouteDecision) (Object, []Source, error) {
	endpoint := route.Endpoint
	seen := map[string]bool{}
	var mirrors []string
	var sources []Source
	var response rwhoisResponse
	for hop := 0; hop < 4; hop++ {
		automatic := route.DiscoverySource != "command line" || hop > 0
		key := strings.ToLower(endpoint)
		if seen[key] {
			return Object{}, sources, lookupError(ErrorProtocol, "RWhois referral loop detected", nil)
		}
		seen[key] = true
		var err error
		response, err = a.query(ctx, endpoint, target.Canonical, automatic)
		if err != nil {
			if len(mirrors) > 0 {
				endpoint, mirrors = mirrors[0], mirrors[1:]
				continue
			}
			return Object{}, sources, err
		}
		sources = append(sources, Source{Protocol: ProtocolRWHOIS, Endpoint: endpoint, Authority: rwhoisAuthority(endpoint), Raw: response.Raw})
		if response.ErrorCode != 0 && !(response.ErrorCode == 330 && len(response.Records) > 0) {
			return Object{}, sources, rwhoisStatusError(response)
		}
		candidates := response.referralCandidates(target)
		if len(candidates) == 0 {
			return normalizeRWHOIS(target, response), sources, nil
		}
		if len(response.Records) > 0 && strings.Contains(strings.ToLower(candidates[0]), "auth-area=.") {
			return normalizeRWHOIS(target, response), sources, nil
		}
		endpoint, mirrors = candidates[0], append(candidates[1:], mirrors...)
	}
	return normalizeRWHOIS(target, response), sources, nil
}

func (a rwhoisAdapter) query(ctx context.Context, endpoint, query string, automatic bool) (rwhoisResponse, error) {
	address, err := rwhoisAddress(endpoint)
	if err != nil {
		return rwhoisResponse{}, err
	}
	var connection net.Conn
	if automatic {
		connection, err = dialAutomaticContext(ctx, "tcp", address, a.client.timeout, a.client.networkPolicy)
	} else {
		connection, err = (&net.Dialer{Timeout: a.client.timeout}).DialContext(ctx, "tcp", address)
	}
	if err != nil {
		var typed *LookupError
		if errors.As(err, &typed) {
			return rwhoisResponse{}, typed
		}
		return rwhoisResponse{}, lookupError(ErrorUnavailable, "RWhois service is unavailable at "+endpoint, err)
	}
	defer connection.Close()
	return a.queryConnection(ctx, connection, query)
}

func (a rwhoisAdapter) queryConnection(ctx context.Context, connection net.Conn, query string) (rwhoisResponse, error) {
	deadline := time.Now().Add(a.client.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = connection.SetDeadline(deadline)
	stopCancelWatch := context.AfterFunc(ctx, func() {
		_ = connection.SetDeadline(time.Now())
		_ = connection.Close()
	})
	defer stopCancelWatch()

	reader := bufio.NewReaderSize(connection, 32<<10)
	banner, err := readRWHOISLine(reader)
	if err != nil {
		if ctx.Err() != nil {
			return rwhoisResponse{}, contextLookupError("RWhois query", ctx.Err())
		}
		return rwhoisResponse{}, rwhoisReadError("could not read RWhois banner", err)
	}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(banner)), "%rwhois") {
		return rwhoisResponse{}, lookupError(ErrorProtocol, "RWhois service returned an invalid banner", nil)
	}
	if _, err := io.WriteString(connection, query+"\r\n"); err != nil {
		return rwhoisResponse{}, lookupError(ErrorUnavailable, "could not send RWhois query", err)
	}

	var raw strings.Builder
	raw.WriteString(banner)
	if !strings.HasSuffix(banner, "\n") {
		raw.WriteByte('\n')
	}
	for raw.Len() <= maximumRWHOISData {
		line, readErr := readRWHOISLine(reader)
		if readErr != nil {
			if ctx.Err() != nil {
				return rwhoisResponse{}, contextLookupError("RWhois query", ctx.Err())
			}
			if errors.Is(readErr, io.EOF) {
				return rwhoisResponse{}, lookupError(ErrorProtocol, "RWhois service closed before a completion status", nil)
			}
			return rwhoisResponse{}, rwhoisReadError("could not read RWhois response", readErr)
		}
		raw.WriteString(line)
		if !strings.HasSuffix(line, "\n") {
			raw.WriteByte('\n')
		}
		if raw.Len() > maximumRWHOISData {
			return rwhoisResponse{}, lookupError(ErrorProtocol, "RWhois response exceeded 8 MiB", nil)
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(trimmed), "%ok") || strings.HasPrefix(strings.ToLower(trimmed), "%error") {
			response := parseRWHOIS(raw.String())
			return response, nil
		}
	}
	return rwhoisResponse{}, lookupError(ErrorProtocol, "RWhois response exceeded 8 MiB", nil)
}

func readRWHOISLine(reader *bufio.Reader) (string, error) {
	var line []byte
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(line)+len(fragment) > maximumRWHOISLine {
			return "", lookupError(ErrorProtocol, "RWhois response line exceeded 1 MiB", nil)
		}
		line = append(line, fragment...)
		if err == nil {
			return string(line), nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) && len(line) > 0 {
			return string(line), nil
		}
		return "", err
	}
}

func rwhoisReadError(message string, err error) error {
	if typed, ok := err.(*LookupError); ok {
		return typed
	}
	return lookupError(ErrorUnavailable, message, err)
}

type rwhoisResponse struct {
	Raw       string
	Records   []rwhoisRecord
	Referrals []string
	ErrorCode int
	ErrorText string
}

type rwhoisRecord struct {
	Class  string
	Fields map[string][]string
}

func parseRWHOIS(raw string) rwhoisResponse {
	response := rwhoisResponse{Raw: raw}
	var current *rwhoisRecord
	flush := func() {
		if current != nil && len(current.Fields) > 0 {
			response.Records = append(response.Records, *current)
		}
		current = nil
	}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 4<<10), maximumRWHOISLine)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			flush()
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "%referral") {
			if value := strings.TrimSpace(line[len("%referral"):]); value != "" {
				response.Referrals = append(response.Referrals, value)
			}
			continue
		}
		if strings.HasPrefix(lower, "%error") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				response.ErrorCode, _ = strconv.Atoi(fields[1])
			}
			if len(fields) > 2 {
				response.ErrorText = strings.Join(fields[2:], " ")
			}
			continue
		}
		if strings.HasPrefix(line, "%") {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		class := strings.ToLower(strings.TrimSpace(parts[0]))
		attribute := rwhoisKey(strings.SplitN(strings.TrimSpace(parts[1]), ";", 2)[0])
		value := strings.TrimSpace(parts[2])
		if class == "" || attribute == "" || value == "" {
			continue
		}
		if current == nil || current.Class != class || ((attribute == "id" || attribute == "classname") && len(current.Fields) > 0 && len(current.Fields[attribute]) > 0) {
			flush()
			current = &rwhoisRecord{Class: class, Fields: map[string][]string{}}
		}
		current.Fields[attribute] = appendUnique(current.Fields[attribute], value)
	}
	flush()
	return response
}

func (r rwhoisResponse) bestReferral(target Target) string {
	candidates := r.referralCandidates(target)
	if len(candidates) == 0 {
		return ""
	}
	return candidates[0]
}

func (r rwhoisResponse) referralCandidates(target Target) []string {
	type candidate struct {
		endpoint string
		score    int
	}
	var candidates []candidate
	seen := map[string]bool{}
	for _, value := range r.Referrals {
		endpoint, err := canonicalEndpoint(ProtocolRWHOIS, value)
		if err != nil {
			continue
		}
		key := strings.ToLower(endpoint)
		if seen[key] {
			continue
		}
		seen[key] = true
		candidates = append(candidates, candidate{endpoint: endpoint, score: rwhoisReferralScore(target, value)})
	}
	sort.SliceStable(candidates, func(left, right int) bool { return candidates[left].score > candidates[right].score })
	endpoints := make([]string, len(candidates))
	for index, candidate := range candidates {
		endpoints[index] = candidate.endpoint
	}
	return endpoints
}

func rwhoisReferralScore(target Target, value string) int {
	parsed, err := url.Parse(value)
	if err != nil {
		return 0
	}
	authority := strings.TrimPrefix(strings.TrimSpace(parsed.Path), "/auth-area=")
	if authority == "" || authority == "." {
		return 0
	}
	if decoded, err := url.PathUnescape(authority); err == nil {
		authority = decoded
	}
	switch target.Kind {
	case KindIP:
		address, err := netip.ParseAddr(strings.Split(target.Canonical, "/")[0])
		prefix, prefixErr := netip.ParsePrefix(authority)
		if err == nil && prefixErr == nil && prefix.Contains(address) {
			return prefix.Bits() + 1
		}
	case KindDomain:
		authority = strings.TrimSuffix(strings.ToLower(authority), ".")
		if target.Canonical == authority || strings.HasSuffix(target.Canonical, "."+authority) {
			return len(strings.Split(authority, ".")) + 1
		}
	case KindASN:
		if strings.EqualFold(strings.TrimPrefix(authority, "AS"), target.Canonical) {
			return 2
		}
	}
	return 1
}

func rwhoisStatusError(response rwhoisResponse) error {
	message := "RWhois service returned an error"
	if response.ErrorText != "" {
		message += ": " + response.ErrorText
	}
	switch response.ErrorCode {
	case 230, 336:
		return lookupError(ErrorNotFound, message, nil)
	}
	if response.ErrorCode >= 500 {
		return lookupError(ErrorUnavailable, message, nil)
	}
	return lookupError(ErrorProtocol, message, nil)
}

func normalizeRWHOIS(target Target, response rwhoisResponse) Object {
	object := Object{Kind: target.Kind, Extras: map[string][]string{}}
	for _, record := range response.Records {
		for key, values := range record.Fields {
			extra := record.Class + "." + key
			for _, value := range values {
				object.Extras[extra] = appendUnique(object.Extras[extra], value)
			}
		}
	}
	selected := chooseRWHOISRecord(target, response.Records)
	if selected == nil {
		if len(object.Extras) == 0 {
			object.Extras = nil
		}
		return object
	}

	object.Handle = firstRWHOIS(*selected, "id", "handle", "networkid")
	object.Name = firstRWHOIS(*selected, "networkname", "name", "domainname", "asname")
	object.Country = firstRWHOIS(*selected, "country", "countrycode")
	object.Registry = firstRWHOIS(*selected, "registry", "registrysource")
	object.Registrar = firstRWHOIS(*selected, "registrar", "registrarname")
	object.Status = allRWHOIS(*selected, "status", "networkstatus")
	object.Events = rwhoisEvents(*selected)

	switch target.Kind {
	case KindIP:
		object.NetworkType = firstRWHOIS(*selected, "networktype", "type", "assignmenttype")
		object.CIDR = allRWHOIS(*selected, "ipnetwork", "ipnetworkblock", "classipnetwork", "classipnetworkblock", "cidr")
		object.StartAddress = firstRWHOIS(*selected, "startaddress", "ipnetwork")
		object.EndAddress = firstRWHOIS(*selected, "endaddress")
	case KindDomain:
		object.Name = firstNonEmpty(firstRWHOIS(*selected, "domainname", "domain", "name"), target.Canonical)
		object.Nameservers = allRWHOIS(*selected, "nameserver", "nameservers", "nserver")
		object.DNSSEC = firstRWHOIS(*selected, "dnssec")
	case KindASN:
		object.ASN = firstNonEmpty(firstRWHOIS(*selected, "asn", "autnum", "number"), "AS"+target.Canonical)
		object.ASNName = firstRWHOIS(*selected, "asname", "name")
		object.ASNType = firstRWHOIS(*selected, "type", "asntype")
		object.Name = firstNonEmpty(object.Name, object.ASNName)
	}
	object.Entities = rwhoisEntities(*selected, response.Records)
	if len(object.Extras) == 0 {
		object.Extras = nil
	}
	return object
}

func chooseRWHOISRecord(target Target, records []rwhoisRecord) *rwhoisRecord {
	if target.Kind == KindIP {
		address, err := netip.ParseAddr(strings.Split(target.Canonical, "/")[0])
		if err != nil {
			return nil
		}
		bestBits := -1
		var best *rwhoisRecord
		for index := range records {
			record := &records[index]
			if record.Class != "network" && record.Class != "net" {
				continue
			}
			for _, network := range allRWHOIS(*record, "ipnetwork", "ipnetworkblock", "classipnetwork", "classipnetworkblock", "cidr") {
				prefix, err := netip.ParsePrefix(network)
				if err == nil && prefix.Contains(address) && prefix.Bits() > bestBits {
					best, bestBits = record, prefix.Bits()
				}
			}
		}
		if best != nil {
			return best
		}
	}
	classes := map[Kind][]string{
		KindDomain: {"domain"},
		KindASN:    {"asn", "autnum"},
	}
	for _, class := range classes[target.Kind] {
		for index := range records {
			if records[index].Class == class {
				return &records[index]
			}
		}
	}
	if len(records) > 0 {
		return &records[0]
	}
	return nil
}

func rwhoisEvents(record rwhoisRecord) []Event {
	groups := []struct {
		action string
		keys   []string
	}{
		{"registration", []string{"created", "creationdate", "registered", "registrationdate"}},
		{"last changed", []string{"updated", "lastmodified", "changed", "modified"}},
		{"expiration", []string{"expiration", "expirationdate", "expiry", "expires"}},
	}
	var events []Event
	for _, group := range groups {
		for _, value := range allRWHOIS(record, group.keys...) {
			events = append(events, Event{Action: group.action, Date: value})
		}
	}
	return events
}

func rwhoisEntities(network rwhoisRecord, records []rwhoisRecord) []Entity {
	contacts := map[string]rwhoisRecord{}
	for _, record := range records {
		if record.Class != "contact" {
			continue
		}
		if id := strings.ToLower(firstRWHOIS(record, "id", "handle", "contactid")); id != "" {
			contacts[id] = record
		}
	}
	roles := []struct {
		role string
		keys []string
	}{
		{"administrative", []string{"admincontact", "administrativecontact"}},
		{"technical", []string{"techcontact", "technicalcontact"}},
		{"abuse", []string{"abusecontact"}},
	}
	var entities []Entity
	for _, role := range roles {
		for _, reference := range allRWHOIS(network, role.keys...) {
			contact, found := contacts[strings.ToLower(reference)]
			if !found {
				entities = append(entities, Entity{Roles: []string{role.role}, Handle: reference})
				continue
			}
			entities = append(entities, Entity{
				Roles:        []string{role.role},
				Handle:       firstRWHOIS(contact, "id", "handle"),
				Name:         firstRWHOIS(contact, "name", "fullname"),
				Organization: firstRWHOIS(contact, "organization", "orgname", "company"),
				Email:        firstRWHOIS(contact, "email", "emailaddress"),
				Phone:        firstRWHOIS(contact, "phone", "telephone"),
			})
		}
	}
	if organization := firstRWHOIS(network, "organizationname", "orgname", "owner"); organization != "" {
		entities = append(entities, Entity{Roles: []string{"registrant"}, Organization: organization, Name: organization})
	}
	return entities
}

func firstRWHOIS(record rwhoisRecord, keys ...string) string {
	for _, key := range keys {
		if values := record.Fields[rwhoisKey(key)]; len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func allRWHOIS(record rwhoisRecord, keys ...string) []string {
	var values []string
	for _, key := range keys {
		for _, value := range record.Fields[rwhoisKey(key)] {
			values = appendUnique(values, value)
		}
	}
	return values
}

func rwhoisKey(value string) string {
	return strings.NewReplacer(" ", "", "-", "", "_", "", ".", "").Replace(strings.ToLower(strings.TrimSpace(value)))
}

func canonicalRWHOISEndpoint(input string) (string, error) {
	value := strings.TrimSpace(input)
	if value == "" {
		return "", lookupError(ErrorInvalidInput, "RWhois server endpoint cannot be empty", nil)
	}
	if !strings.Contains(value, "://") {
		value = "rwhois://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil || !strings.EqualFold(parsed.Scheme, "rwhois") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", lookupError(ErrorInvalidInput, "RWhois server must be a host, host:port, or rwhois URL", err)
	}
	port := parsed.Port()
	if port == "" {
		port = defaultRWHOISPort
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return "", lookupError(ErrorInvalidInput, "RWhois server has an invalid port", err)
	}
	host := parsed.Hostname()
	if host == "" {
		return "", lookupError(ErrorInvalidInput, "RWhois server must include a host", nil)
	}
	endpoint := "rwhois://" + net.JoinHostPort(strings.Trim(host, "[]"), port)
	if parsed.Path != "" && parsed.Path != "/" {
		endpoint += "/" + strings.TrimPrefix(parsed.EscapedPath(), "/")
	}
	return endpoint, nil
}

func rwhoisAddress(endpoint string) (string, error) {
	canonical, err := canonicalRWHOISEndpoint(endpoint)
	if err != nil {
		return "", err
	}
	parsed, _ := url.Parse(canonical)
	return net.JoinHostPort(parsed.Hostname(), parsed.Port()), nil
}

func rwhoisAuthority(endpoint string) string {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return endpoint
	}
	return parsed.Host
}
