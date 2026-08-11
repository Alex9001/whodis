package whodis

import (
	"context"
	"fmt"
	"strings"

	mdns "github.com/miekg/dns"
)

// These SHA-256 DS records are the current IANA-published root trust anchor
// set. Keeping both KSK-2017 and pre-published KSK-2024 covers the scheduled
// October 2026 rollover without relying on the host resolver's AD bit.
var rootTrustAnchors = []mdns.DS{
	{Hdr: mdns.RR_Header{Name: ".", Rrtype: mdns.TypeDS, Class: mdns.ClassINET}, KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"},
	{Hdr: mdns.RR_Header{Name: ".", Rrtype: mdns.TypeDS, Class: mdns.ClassINET}, KeyTag: 38696, Algorithm: 8, DigestType: 2, Digest: "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"},
}

type dnssecValidator struct {
	provider *nativeDNSProvider
	resolver resolverSpec
	options  DNSOptions
	keys     map[string][]*mdns.DNSKEY
	states   map[string]string
}

func (provider *nativeDNSProvider) validateDNSSEC(ctx context.Context, response *mdns.Msg, resolver resolverSpec, options DNSOptions) (string, string) {
	if response == nil {
		return "indeterminate", "no DNS response to validate"
	}
	if response.Rcode == mdns.RcodeServerFailure {
		for _, extended := range extendedDNSErrors(response) {
			if strings.HasPrefix(extended, "6 ") {
				return "bogus", "resolver reported DNSSEC Bogus"
			}
		}
	}
	validator := &dnssecValidator{provider: provider, resolver: resolver, options: options, keys: make(map[string][]*mdns.DNSKEY), states: make(map[string]string)}
	rrsets, signatures := signedAnswerSets(response)
	if len(rrsets) == 0 || len(signatures) == 0 {
		return "indeterminate", "response contains no locally verifiable signed answer set"
	}
	for key, records := range rrsets {
		covered := signatures[key]
		if len(covered) == 0 {
			return "bogus", "a DNSSEC answer RRset has no covering RRSIG"
		}
		verified := false
		var lastErr error
		for _, signature := range covered {
			keys, state, err := validator.authenticatedKeys(ctx, signature.SignerName, 0)
			if err != nil {
				lastErr = err
				continue
			}
			if state != "secure" {
				return state, "signer does not have a secure chain to the root"
			}
			for _, keyRecord := range keys {
				if signature.KeyTag != keyRecord.KeyTag() || signature.Algorithm != keyRecord.Algorithm {
					continue
				}
				if err := signature.Verify(keyRecord, records); err == nil {
					verified = true
					break
				} else {
					lastErr = err
				}
			}
			if verified {
				break
			}
		}
		if !verified {
			if lastErr != nil {
				return "bogus", lastErr.Error()
			}
			return "bogus", "no authenticated DNSKEY verified an answer signature"
		}
	}
	return "secure", "validated locally to an IANA root trust anchor"
}

func signedAnswerSets(message *mdns.Msg) (map[string][]mdns.RR, map[string][]*mdns.RRSIG) {
	rrsets := make(map[string][]mdns.RR)
	signatures := make(map[string][]*mdns.RRSIG)
	for _, record := range message.Answer {
		if signature, ok := record.(*mdns.RRSIG); ok {
			key := rrsetKey(signature.Hdr.Name, signature.TypeCovered)
			signatures[key] = append(signatures[key], signature)
			continue
		}
		if record.Header().Rrtype == mdns.TypeOPT {
			continue
		}
		key := rrsetKey(record.Header().Name, record.Header().Rrtype)
		rrsets[key] = append(rrsets[key], record)
	}
	return rrsets, signatures
}

func rrsetKey(name string, recordType uint16) string {
	return strings.ToLower(mdns.Fqdn(name)) + "\x00" + fmt.Sprint(recordType)
}

func (validator *dnssecValidator) authenticatedKeys(ctx context.Context, zone string, depth int) ([]*mdns.DNSKEY, string, error) {
	zone = strings.ToLower(mdns.Fqdn(zone))
	if depth > 24 {
		return nil, "indeterminate", fmt.Errorf("DNSSEC chain exceeded delegation limit")
	}
	if keys, ok := validator.keys[zone]; ok {
		return keys, validator.states[zone], nil
	}
	response, err := validator.query(ctx, zone, mdns.TypeDNSKEY)
	if err != nil {
		return nil, "indeterminate", err
	}
	keys, signatures := dnskeyRecords(response, zone)
	if len(keys) == 0 {
		return nil, "bogus", fmt.Errorf("%s returned no DNSKEY records", zone)
	}
	if zone == "." {
		for _, key := range keys {
			if !matchesAnyDS(key, rootTrustAnchors) {
				continue
			}
			if verifiesDNSKEYSet(key, keys, signatures) {
				validator.keys[zone], validator.states[zone] = keys, "secure"
				return keys, "secure", nil
			}
		}
		return nil, "bogus", fmt.Errorf("root DNSKEY set did not match and verify with an IANA trust anchor")
	}

	dsResponse, err := validator.query(ctx, zone, mdns.TypeDS)
	if err != nil {
		return nil, "indeterminate", err
	}
	dsRecords, dsSignatures := dsRecords(dsResponse, zone)
	if len(dsRecords) == 0 {
		validator.states[zone] = "indeterminate"
		return keys, "indeterminate", nil
	}
	parent := parentDNSZone(zone)
	for _, signature := range dsSignatures {
		if signature.SignerName != "" {
			parent = strings.ToLower(mdns.Fqdn(signature.SignerName))
			break
		}
	}
	parentKeys, state, err := validator.authenticatedKeys(ctx, parent, depth+1)
	if err != nil || state != "secure" {
		return nil, state, err
	}
	if !verifyRRSetWithKeys(dsRRs(dsRecords), dsSignatures, parentKeys) {
		return nil, "bogus", fmt.Errorf("DS RRset for %s did not verify with authenticated parent keys", zone)
	}
	for _, key := range keys {
		if matchesAnyDS(key, dsRecords) && verifiesDNSKEYSet(key, keys, signatures) {
			validator.keys[zone], validator.states[zone] = keys, "secure"
			return keys, "secure", nil
		}
	}
	return nil, "bogus", fmt.Errorf("DNSKEY set for %s did not match its authenticated DS records", zone)
}

func (validator *dnssecValidator) query(ctx context.Context, name string, recordType uint16) (*mdns.Msg, error) {
	message := new(mdns.Msg)
	message.SetQuestion(mdns.Fqdn(name), recordType)
	message.RecursionDesired = true
	message.CheckingDisabled = true
	edns := validator.options.EDNS
	edns.DNSSEC = true
	applyEDNS(message, edns)
	response, _, err := validator.provider.exchangeMessage(ctx, message, validator.resolver)
	return response, err
}

func dnskeyRecords(message *mdns.Msg, zone string) ([]*mdns.DNSKEY, []*mdns.RRSIG) {
	var keys []*mdns.DNSKEY
	var signatures []*mdns.RRSIG
	if message == nil {
		return keys, signatures
	}
	for _, record := range message.Answer {
		switch value := record.(type) {
		case *mdns.DNSKEY:
			if strings.EqualFold(value.Hdr.Name, zone) {
				keys = append(keys, value)
			}
		case *mdns.RRSIG:
			if value.TypeCovered == mdns.TypeDNSKEY && strings.EqualFold(value.Hdr.Name, zone) {
				signatures = append(signatures, value)
			}
		}
	}
	return keys, signatures
}

func dsRecords(message *mdns.Msg, zone string) ([]mdns.DS, []*mdns.RRSIG) {
	var records []mdns.DS
	var signatures []*mdns.RRSIG
	if message == nil {
		return records, signatures
	}
	for _, record := range message.Answer {
		switch value := record.(type) {
		case *mdns.DS:
			if strings.EqualFold(value.Hdr.Name, zone) {
				records = append(records, *value)
			}
		case *mdns.RRSIG:
			if value.TypeCovered == mdns.TypeDS && strings.EqualFold(value.Hdr.Name, zone) {
				signatures = append(signatures, value)
			}
		}
	}
	return records, signatures
}

func dsRRs(records []mdns.DS) []mdns.RR {
	result := make([]mdns.RR, len(records))
	for index := range records {
		copy := records[index]
		result[index] = &copy
	}
	return result
}

func dnskeyRRs(records []*mdns.DNSKEY) []mdns.RR {
	result := make([]mdns.RR, len(records))
	for index, record := range records {
		result[index] = record
	}
	return result
}

func matchesAnyDS(key *mdns.DNSKEY, records []mdns.DS) bool {
	for _, record := range records {
		if key.KeyTag() != record.KeyTag || key.Algorithm != record.Algorithm {
			continue
		}
		calculated := key.ToDS(record.DigestType)
		if calculated != nil && strings.EqualFold(calculated.Digest, record.Digest) {
			return true
		}
	}
	return false
}

func verifiesDNSKEYSet(key *mdns.DNSKEY, records []*mdns.DNSKEY, signatures []*mdns.RRSIG) bool {
	for _, signature := range signatures {
		if signature.KeyTag == key.KeyTag() && signature.Algorithm == key.Algorithm && signature.Verify(key, dnskeyRRs(records)) == nil {
			return true
		}
	}
	return false
}

func verifyRRSetWithKeys(records []mdns.RR, signatures []*mdns.RRSIG, keys []*mdns.DNSKEY) bool {
	for _, signature := range signatures {
		for _, key := range keys {
			if signature.KeyTag == key.KeyTag() && signature.Algorithm == key.Algorithm && signature.Verify(key, records) == nil {
				return true
			}
		}
	}
	return false
}

func parentDNSZone(zone string) string {
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	if zone == "" {
		return "."
	}
	if index := strings.IndexByte(zone, '.'); index >= 0 {
		return zone[index+1:] + "."
	}
	return "."
}
