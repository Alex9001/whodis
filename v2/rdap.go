package whodis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type rdapAdapter struct{ client *Client }

func (rdapAdapter) Protocol() Protocol { return ProtocolRDAP }

func (a rdapAdapter) Lookup(ctx context.Context, target Target, route RouteDecision) (Object, []Source, error) {
	resource := rdapResource(target)
	candidates := append([]string{route.Endpoint}, route.Alternates...)
	var record rdapRecord
	var source Source
	var err error
	for _, base := range candidates {
		endpoint := ensureTrailingSlash(base) + resource
		record, source, err = a.fetch(ctx, endpoint, route.DiscoverySource != "command line")
		if err == nil {
			break
		}
		if typed, ok := err.(*LookupError); !ok || typed.Kind != ErrorUnavailable {
			return Object{}, nil, err
		}
	}
	if err != nil {
		return Object{}, nil, err
	}
	object := normalizeRDAP(target.Kind, record)
	sources := []Source{source}

	// Registry responses occasionally point to a registrar's object through a
	// related link. Follow one same-object RDAP link so public registrar data is
	// not silently lost, while preventing unbounded remote traversal.
	for _, link := range record.Links {
		if !strings.EqualFold(link.Rel, "related") || link.Href == "" || !strings.HasPrefix(link.Href, "http") {
			continue
		}
		if !strings.Contains(link.Href, "/"+string(target.Kind)+"/") && !(target.Kind == KindASN && strings.Contains(link.Href, "/autnum/")) {
			continue
		}
		if follow, followSource, followErr := a.fetch(ctx, link.Href, true); followErr == nil {
			object = mergeObjects(object, normalizeRDAP(target.Kind, follow))
			sources = append(sources, followSource)
		}
		break
	}
	return object, sources, nil
}

func rdapResource(target Target) string {
	switch target.Kind {
	case KindDomain:
		return "domain/" + url.PathEscape(target.Canonical)
	case KindIP:
		return "ip/" + url.PathEscape(target.Canonical)
	case KindASN:
		return "autnum/" + url.PathEscape(target.Canonical)
	default:
		return ""
	}
}

func (a rdapAdapter) fetch(ctx context.Context, endpoint string, automatic bool) (rdapRecord, Source, error) {
	var record rdapRecord
	var source Source
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		record, source, err = a.fetchOnce(ctx, endpoint, automatic)
		if err == nil || ctx.Err() != nil || !retryableRDAPFailure(err) || attempt == 1 {
			return record, source, err
		}
		timer := time.NewTimer(retryDelayForRDAPError(err))
		select {
		case <-ctx.Done():
			timer.Stop()
			return rdapRecord{}, Source{}, contextLookupError("RDAP query", ctx.Err())
		case <-timer.C:
		}
	}
	return record, source, err
}

func (a rdapAdapter) fetchOnce(ctx context.Context, endpoint string, automatic bool) (rdapRecord, Source, error) {
	if automatic {
		if err := validateAutomaticURL(ctx, endpoint, a.client.networkPolicy); err != nil {
			return rdapRecord{}, Source{}, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return rdapRecord{}, Source{}, lookupError(ErrorUnavailable, "could not prepare RDAP request", err)
	}
	req.Header.Set("Accept", "application/rdap+json, application/json;q=0.9")
	req.Header.Set("User-Agent", productUserAgent())
	transport := a.client.transport
	if automatic {
		transport = a.client.autoTransport
	}
	client := &http.Client{
		Timeout: a.client.timeout, Transport: transport,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 4 || (request.URL.Scheme != "https" && request.URL.Scheme != "http") {
				return http.ErrUseLastResponse
			}
			if len(via) > 0 && via[len(via)-1].URL.Scheme == "https" && request.URL.Scheme != "https" && !a.client.networkPolicy.AllowInsecureHTTP {
				return fmt.Errorf("RDAP redirect attempted an HTTPS downgrade")
			}
			if automatic {
				if err := validateAutomaticURL(request.Context(), request.URL.String(), a.client.networkPolicy); err != nil {
					return err
				}
			}
			return nil
		},
	}
	response, err := client.Do(req)
	if err != nil {
		return rdapRecord{}, Source{}, lookupError(ErrorUnavailable, "RDAP service is unavailable", err)
	}
	defer response.Body.Close()
	raw, err := readLimitedBody(response.Body, 8<<20)
	if err != nil {
		return rdapRecord{}, Source{}, lookupError(ErrorUnavailable, "could not read RDAP response", err)
	}
	switch response.StatusCode {
	case http.StatusNotFound:
		return rdapRecord{}, Source{}, lookupError(ErrorNotFound, "registration object was not found by RDAP authority", nil)
	case http.StatusTooManyRequests:
		message := "RDAP authority rate limited the request"
		if retry := response.Header.Get("Retry-After"); retry != "" {
			message += "; retry after " + retry
		}
		return rdapRecord{}, Source{}, lookupError(ErrorRateLimited, message, nil)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if response.StatusCode >= 500 {
			return rdapRecord{}, Source{}, lookupError(ErrorUnavailable, "RDAP service returned "+response.Status, nil)
		}
		return rdapRecord{}, Source{}, lookupError(ErrorProtocol, "RDAP service returned "+response.Status, nil)
	}
	var record rdapRecord
	if err := json.Unmarshal(raw, &record); err != nil || record.ObjectClassName == "" {
		return rdapRecord{}, Source{}, lookupError(ErrorProtocol, "RDAP service returned an invalid response", err)
	}
	return record, Source{Protocol: ProtocolRDAP, Endpoint: endpoint, Authority: response.Request.URL.Host, Raw: string(raw)}, nil
}

func retryableRDAPFailure(err error) bool {
	var typed *LookupError
	if !errors.As(err, &typed) {
		return false
	}
	return typed.Kind == ErrorUnavailable || typed.Kind == ErrorRateLimited
}

func retryDelayForRDAPError(err error) time.Duration {
	var typed *LookupError
	if errors.As(err, &typed) {
		if _, value, found := strings.Cut(typed.Message, "retry after "); found {
			return retryAfterDuration(value)
		}
	}
	return 250 * time.Millisecond
}

func retryAfterDuration(value string) time.Duration {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
		delay := time.Duration(seconds) * time.Second
		if delay > 5*time.Second {
			delay = 5 * time.Second
		}
		return delay
	}
	if when, err := http.ParseTime(value); err == nil {
		delay := time.Until(when)
		if delay < 0 {
			delay = 0
		}
		if delay > 5*time.Second {
			delay = 5 * time.Second
		}
		return delay
	}
	return 250 * time.Millisecond
}

type rdapRecord struct {
	ObjectClassName string       `json:"objectClassName"`
	Handle          string       `json:"handle"`
	LDHName         string       `json:"ldhName"`
	UnicodeName     string       `json:"unicodeName"`
	Name            string       `json:"name"`
	Type            string       `json:"type"`
	Country         string       `json:"country"`
	Port43          string       `json:"port43"`
	StartAddress    string       `json:"startAddress"`
	EndAddress      string       `json:"endAddress"`
	StartAutnum     *uint64      `json:"startAutnum"`
	EndAutnum       *uint64      `json:"endAutnum"`
	Status          []string     `json:"status"`
	Events          []rdapEvent  `json:"events"`
	Nameservers     []rdapNS     `json:"nameservers"`
	Entities        []rdapEntity `json:"entities"`
	Notices         []rdapNotice `json:"notices"`
	Remarks         []rdapNotice `json:"remarks"`
	Links           []rdapLink   `json:"links"`
	SecureDNS       *struct {
		DelegationSigned bool `json:"delegationSigned"`
	} `json:"secureDNS"`
	CIDR0CIDRs []struct {
		V4Prefix       string `json:"v4prefix"`
		V6Prefix       string `json:"v6prefix"`
		Length         int    `json:"length"`
		V4PrefixLength int    `json:"v4prefixLength"`
		V6PrefixLength int    `json:"v6prefixLength"`
	} `json:"cidr0_cidrs"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapNS struct {
	LDHName     string `json:"ldhName"`
	UnicodeName string `json:"unicodeName"`
}

type rdapEntity struct {
	Roles  []string          `json:"roles"`
	Handle string            `json:"handle"`
	VCard  []json.RawMessage `json:"vcardArray"`
}

type rdapNotice struct {
	Title       string     `json:"title"`
	Description []string   `json:"description"`
	Links       []rdapLink `json:"links"`
}

type rdapLink struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

func rdapPort43(sources []Source) string {
	for _, source := range sources {
		if source.Protocol != ProtocolRDAP || source.Raw == "" {
			continue
		}
		var record rdapRecord
		if json.Unmarshal([]byte(source.Raw), &record) == nil && strings.TrimSpace(record.Port43) != "" {
			return strings.TrimSpace(record.Port43)
		}
	}
	return ""
}

func normalizeRDAP(kind Kind, record rdapRecord) Object {
	object := Object{
		Kind: kind, Handle: record.Handle, Status: append([]string(nil), record.Status...), Country: record.Country,
		NetworkType: record.Type, Extras: map[string][]string{},
	}
	if kind == KindDomain {
		object.Name, object.UnicodeName = record.LDHName, record.UnicodeName
		if object.Name == "" {
			object.Name = record.Name
		}
		if record.SecureDNS != nil {
			if record.SecureDNS.DelegationSigned {
				object.DNSSEC = "signed"
			} else {
				object.DNSSEC = "unsigned"
			}
		}
	} else if kind == KindIP {
		object.Name = record.Name
		object.StartAddress, object.EndAddress = record.StartAddress, record.EndAddress
		for _, cidr := range record.CIDR0CIDRs {
			prefix, length := cidr.V4Prefix, cidr.V4PrefixLength
			if prefix == "" {
				prefix, length = cidr.V6Prefix, cidr.V6PrefixLength
			}
			if length == 0 {
				length = cidr.Length
			}
			if prefix != "" && length > 0 {
				object.CIDR = append(object.CIDR, fmt.Sprintf("%s/%d", prefix, length))
			}
		}
	} else if kind == KindASN {
		object.Name, object.ASNName, object.ASNType = record.Name, record.Name, record.Type
		if record.StartAutnum != nil {
			if record.EndAutnum != nil && *record.EndAutnum != *record.StartAutnum {
				object.ASN = fmt.Sprintf("AS%d-AS%d", *record.StartAutnum, *record.EndAutnum)
			} else {
				object.ASN = fmt.Sprintf("AS%d", *record.StartAutnum)
			}
		}
	}
	for _, event := range record.Events {
		object.Events = append(object.Events, Event(event))
	}
	for _, ns := range record.Nameservers {
		if ns.LDHName != "" {
			object.Nameservers = appendUnique(object.Nameservers, ns.LDHName)
		} else if ns.UnicodeName != "" {
			object.Nameservers = appendUnique(object.Nameservers, ns.UnicodeName)
		}
	}
	for _, entity := range record.Entities {
		normalized := normalizeEntity(entity)
		object.Entities = append(object.Entities, normalized)
		if hasRole(entity.Roles, "registrar") && normalized.Name != "" {
			object.Registrar = normalized.Name
		}
		if hasRole(entity.Roles, "registry") && normalized.Name != "" {
			object.Registry = normalized.Name
		}
	}
	for _, notice := range append(record.Notices, record.Remarks...) {
		links := make([]string, 0, len(notice.Links))
		for _, link := range notice.Links {
			if link.Href != "" {
				links = append(links, link.Href)
			}
		}
		object.Notices = append(object.Notices, Notice{Title: notice.Title, Description: notice.Description, Links: links})
	}
	if len(object.Extras) == 0 {
		object.Extras = nil
	}
	return object
}

func normalizeEntity(entity rdapEntity) Entity {
	result := Entity{Roles: append([]string(nil), entity.Roles...), Handle: entity.Handle}
	if len(entity.VCard) < 2 {
		return result
	}
	var card []json.RawMessage
	if json.Unmarshal(entity.VCard[1], &card) != nil {
		return result
	}
	for _, item := range card {
		var property []json.RawMessage
		if json.Unmarshal(item, &property) != nil || len(property) < 4 {
			continue
		}
		var name string
		_ = json.Unmarshal(property[0], &name)
		var value any
		if json.Unmarshal(property[3], &value) != nil {
			continue
		}
		text := vcardText(value)
		switch strings.ToLower(name) {
		case "fn":
			result.Name = text
		case "org":
			result.Organization = text
		case "email":
			result.Email = text
		case "tel":
			result.Phone = text
		}
	}
	if result.Name == "" {
		result.Name = result.Organization
	}
	return result
}

func vcardText(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			parts = append(parts, vcardText(item))
		}
		return strings.Join(parts, ", ")
	default:
		return ""
	}
}

func hasRole(roles []string, wanted string) bool {
	for _, role := range roles {
		if strings.EqualFold(role, wanted) {
			return true
		}
	}
	return false
}

func mergeObjects(base, supplement Object) Object {
	if base.Handle == "" {
		base.Handle = supplement.Handle
	}
	if base.Name == "" {
		base.Name = supplement.Name
	}
	if base.UnicodeName == "" {
		base.UnicodeName = supplement.UnicodeName
	}
	if base.Registrar == "" {
		base.Registrar = supplement.Registrar
	}
	if base.Registry == "" {
		base.Registry = supplement.Registry
	}
	if base.DNSSEC == "" {
		base.DNSSEC = supplement.DNSSEC
	}
	if base.StartAddress == "" {
		base.StartAddress = supplement.StartAddress
	}
	if base.EndAddress == "" {
		base.EndAddress = supplement.EndAddress
	}
	if base.Country == "" {
		base.Country = supplement.Country
	}
	if base.NetworkType == "" {
		base.NetworkType = supplement.NetworkType
	}
	if base.ASN == "" {
		base.ASN = supplement.ASN
	}
	if base.ASNName == "" {
		base.ASNName = supplement.ASNName
	}
	if base.ASNType == "" {
		base.ASNType = supplement.ASNType
	}
	for _, status := range supplement.Status {
		base.Status = appendUnique(base.Status, status)
	}
	for _, name := range supplement.Nameservers {
		base.Nameservers = appendUnique(base.Nameservers, name)
	}
	for _, cidr := range supplement.CIDR {
		base.CIDR = appendUnique(base.CIDR, cidr)
	}
	base.Events = append(base.Events, supplement.Events...)
	base.Entities = append(base.Entities, supplement.Entities...)
	base.Notices = append(base.Notices, supplement.Notices...)
	return base
}

func appendUnique(items []string, value string) []string {
	for _, item := range items {
		if strings.EqualFold(item, value) {
			return items
		}
	}
	return append(items, value)
}
