package whodis

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

const (
	ianaWHOIS        = "whois.iana.org"
	maximumWHOISData = 8 << 20
)

type whoisAdapter struct{ client *Client }

func (whoisAdapter) Protocol() Protocol { return ProtocolWHOIS }

func (a whoisAdapter) Lookup(ctx context.Context, target Target, route RouteDecision) (Object, []Source, error) {
	endpoint := route.Endpoint
	seen := map[string]bool{}
	var sources []Source
	var document whoisDocument
	for hop := 0; hop < 4; hop++ {
		automatic := route.DiscoverySource != "command line" || hop > 0
		if seen[strings.ToLower(endpoint)] {
			return Object{}, sources, lookupError(ErrorProtocol, "WHOIS referral loop detected", nil)
		}
		seen[strings.ToLower(endpoint)] = true
		raw, err := a.query(ctx, endpoint, whoisQuery(target), automatic)
		if err != nil {
			return Object{}, sources, err
		}
		document = parseWHOIS(raw)
		sources = append(sources, Source{Protocol: ProtocolWHOIS, Endpoint: endpoint, Authority: endpoint, Raw: raw})
		if whoisNotFound(raw) {
			return Object{}, sources, lookupError(ErrorNotFound, "registration object was not found by WHOIS authority", nil)
		}
		if rwhois := rwhoisReferral(document); rwhois != "" {
			route := RouteDecision{Protocol: ProtocolRWHOIS, Endpoint: rwhois, DiscoverySource: "WHOIS RWhois referral", Reason: "authoritative WHOIS service delegated the registration object"}
			object, rwhoisSources, err := a.client.lookupWithRoute(ctx, target, route)
			if err != nil {
				return Object{}, append(sources, rwhoisSources...), err
			}
			sources = append(sources, rwhoisSources...)
			return mergeObjects(object, normalizeWHOIS(target, document)), sources, nil
		}
		referral := whoisReferral(document)
		if referral == "" || strings.EqualFold(referral, endpoint) {
			return normalizeWHOIS(target, document), sources, nil
		}
		endpoint = referral
	}
	return normalizeWHOIS(target, document), sources, nil
}

func (a whoisAdapter) query(ctx context.Context, endpoint, query string, automatic bool) (string, error) {
	address := endpointWithPort(endpoint)
	var connection net.Conn
	var err error
	if automatic {
		connection, err = dialAutomaticContext(ctx, "tcp", address, a.client.timeout, a.client.networkPolicy)
	} else {
		connection, err = (&net.Dialer{Timeout: a.client.timeout}).DialContext(ctx, "tcp", address)
	}
	if err != nil {
		var typed *LookupError
		if errors.As(err, &typed) {
			return "", typed
		}
		return "", lookupError(ErrorUnavailable, "WHOIS service is unavailable at "+endpoint, err)
	}
	defer connection.Close()
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
	if _, err := io.WriteString(connection, query+"\r\n"); err != nil {
		return "", lookupError(ErrorUnavailable, "could not send WHOIS query", err)
	}
	payload, err := io.ReadAll(io.LimitReader(connection, maximumWHOISData+1))
	if err != nil {
		if ctx.Err() != nil {
			return "", contextLookupError("WHOIS query", ctx.Err())
		}
		return "", lookupError(ErrorUnavailable, "could not read WHOIS response", err)
	}
	if len(payload) > maximumWHOISData {
		return "", lookupError(ErrorProtocol, "WHOIS response exceeds the 8 MiB safety limit", nil)
	}
	if len(payload) == 0 {
		return "", lookupError(ErrorProtocol, "WHOIS service returned an empty response", nil)
	}
	return string(payload), nil
}

func contextLookupError(operation string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return lookupError(ErrorTimeout, operation+" timed out", err)
	}
	if errors.Is(err, context.Canceled) {
		return lookupError(ErrorCanceled, operation+" was canceled", err)
	}
	return lookupError(ErrorUnavailable, operation+" failed", err)
}

func (c *Client) discoverWHOIS(ctx context.Context, target Target) (RouteDecision, error) {
	adapter := whoisAdapter{client: c}
	raw, err := adapter.query(ctx, ianaWHOIS, ianaQuery(target), true)
	if err != nil {
		return RouteDecision{}, err
	}
	endpoint := whoisReferral(parseWHOIS(raw))
	if endpoint == "" {
		return RouteDecision{}, lookupError(ErrorDiscovery, "IANA did not publish a WHOIS referral for "+target.Canonical, nil)
	}
	return RouteDecision{
		Protocol: ProtocolWHOIS, Endpoint: endpoint, DiscoverySource: "IANA WHOIS referral", Reason: "no authoritative RDAP service was listed for target scope",
	}, nil
}

func endpointWithPort(endpoint string) string {
	endpoint = strings.TrimPrefix(strings.TrimSpace(endpoint), "whois://")
	endpoint = strings.TrimSuffix(endpoint, "/")
	if _, _, err := net.SplitHostPort(endpoint); err == nil {
		return endpoint
	}
	return net.JoinHostPort(strings.Trim(endpoint, "[]"), "43")
}

func whoisQuery(target Target) string {
	if target.Kind == KindASN {
		return "AS" + target.Canonical
	}
	return target.Canonical
}

func ianaQuery(target Target) string {
	if target.Kind == KindDomain {
		parts := strings.Split(target.Canonical, ".")
		return parts[len(parts)-1]
	}
	return whoisQuery(target)
}

type whoisDocument struct {
	Raw    string
	Fields map[string][]string
}

func parseWHOIS(raw string) whoisDocument {
	document := whoisDocument{Raw: raw, Fields: map[string][]string{}}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 4<<10), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if !found || strings.TrimSpace(value) == "" {
			continue
		}
		key = compactKey(key)
		document.Fields[key] = append(document.Fields[key], strings.TrimSpace(value))
	}
	return document
}

func compactKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.NewReplacer(" ", "", "-", "", "_", "", ".", "").Replace(value)
	return value
}

func firstField(document whoisDocument, keys ...string) string {
	for _, key := range keys {
		if values := document.Fields[compactKey(key)]; len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func allFields(document whoisDocument, keys ...string) []string {
	var output []string
	for _, key := range keys {
		for _, value := range document.Fields[compactKey(key)] {
			output = appendUnique(output, value)
		}
	}
	return output
}

func whoisReferral(document whoisDocument) string {
	value := firstField(document, "whois", "whois server", "referralserver", "refer", "referto")
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(value), "rwhois://") {
		return ""
	}
	value = strings.TrimPrefix(value, "whois://")
	value = strings.TrimSuffix(value, "/")
	if strings.ContainsAny(value, " \t/") {
		return ""
	}
	return value
}

func rwhoisReferral(document whoisDocument) string {
	for _, key := range []string{"referralserver", "refer", "referto", "whois", "whois server"} {
		for _, value := range document.Fields[compactKey(key)] {
			value = strings.TrimSpace(value)
			if !strings.HasPrefix(strings.ToLower(value), "rwhois://") {
				continue
			}
			if endpoint, err := canonicalEndpoint(ProtocolRWHOIS, value); err == nil {
				return endpoint
			}
		}
	}
	return ""
}

// probeRWHOISReferral follows ordinary WHOIS referrals only long enough to
// find an advertised RWhois authority. It is deliberately best-effort: it is
// used to enrich an already-successful RDAP response.
func (a whoisAdapter) probeRWHOISReferral(ctx context.Context, target Target, endpoint string) (Object, []Source, string, bool) {
	seen := map[string]bool{}
	var sources []Source
	for hop := 0; hop < 4; hop++ {
		if seen[strings.ToLower(endpoint)] {
			return Object{}, nil, "", false
		}
		seen[strings.ToLower(endpoint)] = true
		raw, err := a.query(ctx, endpoint, whoisQuery(target), true)
		if err != nil || whoisNotFound(raw) {
			return Object{}, nil, "", false
		}
		document := parseWHOIS(raw)
		sources = append(sources, Source{Protocol: ProtocolWHOIS, Endpoint: endpoint, Authority: endpoint, Raw: raw})
		if referral := rwhoisReferral(document); referral != "" {
			return normalizeWHOIS(target, document), sources, referral, true
		}
		referral := whoisReferral(document)
		if referral == "" || strings.EqualFold(referral, endpoint) {
			return Object{}, nil, "", false
		}
		endpoint = referral
	}
	return Object{}, nil, "", false
}

func whoisNotFound(raw string) bool {
	lower := strings.ToLower(raw)
	phrases := []string{
		"no match for", "no entries found", "no data found", "domain not found", "not found in database", "status: available",
	}
	for _, phrase := range phrases {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}

func normalizeWHOIS(target Target, document whoisDocument) Object {
	object := Object{Kind: target.Kind, Extras: map[string][]string{}}
	for key, values := range document.Fields {
		object.Extras[key] = append([]string(nil), values...)
	}
	switch target.Kind {
	case KindDomain:
		object.Name = firstField(document, "domain name", "domain", "domainname")
		object.Registrar = firstField(document, "registrar", "sponsoring registrar")
		object.Registry = firstField(document, "registry")
		object.DNSSEC = firstField(document, "dnssec")
		object.Status = allFields(document, "domain status", "status")
		object.Nameservers = allFields(document, "name server", "nameserver", "nserver")
	case KindIP:
		object.Name = firstField(document, "netname", "network name", "name")
		object.Handle = firstField(document, "netrange", "inetnum", "network")
		object.StartAddress = firstField(document, "netrange", "inetnum", "start address")
		object.EndAddress = firstField(document, "end address")
		object.CIDR = allFields(document, "cidr", "route", "route6")
		object.Country = firstField(document, "country")
		object.NetworkType = firstField(document, "nettype", "type", "status")
	case KindASN:
		object.ASN = "AS" + target.Canonical
		object.ASNName = firstField(document, "asname", "autnum", "name")
		object.Name = object.ASNName
		object.ASNType = firstField(document, "type")
		object.Country = firstField(document, "country")
	}
	object.Events = append(object.Events, whoisEvents(document)...)
	object.Entities = whoisEntities(document)
	if len(object.Extras) == 0 {
		object.Extras = nil
	}
	return object
}

func whoisEvents(document whoisDocument) []Event {
	groups := []struct {
		action string
		keys   []string
	}{
		{"registration", []string{"creation date", "created", "registered", "registration date"}},
		{"last changed", []string{"updated date", "last updated", "changed"}},
		{"expiration", []string{"registry expiry date", "expiration date", "expiry date", "expires"}},
	}
	var events []Event
	for _, group := range groups {
		for _, date := range allFields(document, group.keys...) {
			events = append(events, Event{Action: group.action, Date: date})
		}
	}
	return events
}

func whoisEntities(document whoisDocument) []Entity {
	roles := []struct{ role, prefix string }{
		{"registrant", "registrant"}, {"administrative", "admin"}, {"technical", "tech"}, {"abuse", "abuse"},
	}
	var entities []Entity
	for _, item := range roles {
		name := firstField(document, item.prefix+" name", item.prefix+"name")
		organization := firstField(document, item.prefix+" organization", item.prefix+"org", item.prefix+"organization")
		email := firstField(document, item.prefix+" email", item.prefix+"email")
		phone := firstField(document, item.prefix+" phone", item.prefix+"phone")
		if name != "" || organization != "" || email != "" || phone != "" {
			entities = append(entities, Entity{Roles: []string{item.role}, Name: name, Organization: organization, Email: email, Phone: phone})
		}
	}
	if registrar := firstField(document, "registrar"); registrar != "" {
		entities = append(entities, Entity{Roles: []string{"registrar"}, Name: registrar})
	}
	return entities
}
