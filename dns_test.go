package whodis

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"
)

func TestDNSPatternScanDiscoversCommonRecordsAndSuppressesWildcards(t *testing.T) {
	result := fixtureDNSScanner(nil).patternScan(context.Background(), "example.test")
	if result.Method != "scan" || result.Complete {
		t.Fatalf("unexpected DNS result: %#v", result)
	}
	if !hasDNSRecord(result.Records, "example.test", "MX", "10 mail.example.test.") {
		t.Fatalf("MX record not discovered: %#v", result.Records)
	}
	if !hasDNSRecord(result.Records, "origin.example.test", "A", "192.0.2.31") {
		t.Fatalf("in-zone CNAME target was not followed: %#v", result.Records)
	}
	if hasDNSRecordName(result.Records, "api.example.test") {
		t.Fatalf("wildcard-derived api record should be suppressed: %#v", result.Records)
	}
	if !containsDNSWarning(result.Warnings, "wildcard DNS answers") {
		t.Fatalf("wildcard warning missing: %#v", result.Warnings)
	}
	if got, want := result.Nameservers, []string{"ns1.example.test"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("nameservers = %#v, want %#v", got, want)
	}
}

func TestDNSModesAndValidation(t *testing.T) {
	client := NewClient(ClientOptions{Adapters: []ProtocolAdapter{staticAdapter{protocol: ProtocolRDAP, object: Object{Kind: KindDomain, Name: "example.test"}}}})
	result, err := client.Lookup(context.Background(), "example.test", LookupOptions{
		Protocol: ProtocolRDAP, Server: "https://rdap.test/", Fallback: FallbackNone,
		DNSMode: DNSOff,
	})
	if err != nil || result.DNS != nil {
		t.Fatalf("DNS off = (%#v, %v), want no DNS result", result.DNS, err)
	}
	_, err = client.Lookup(context.Background(), "192.0.2.1", LookupOptions{DNSMode: DNSScan, DNSResolver: "127.0.0.1:5300"})
	var lookup *LookupError
	if !errors.As(err, &lookup) || lookup.Kind != ErrorInvalidInput {
		t.Fatalf("IP DNS scan error = %v, want invalid input", err)
	}
	_, err = client.Lookup(context.Background(), "example.test", LookupOptions{DNSMode: DNSOff, DNSResolver: "127.0.0.1:5300"})
	if !errors.As(err, &lookup) || lookup.Kind != ErrorInvalidInput {
		t.Fatalf("resolver with DNS off error = %v, want invalid input", err)
	}
}

func TestAXFRSuccessAndFallback(t *testing.T) {
	t.Run("successful transfer", func(t *testing.T) {
		scanner := fixtureDNSScanner(func(context.Context, string, []string) ([]DNSRecord, error) {
			return []DNSRecord{{Name: "example.test", Type: "A", TTL: 300, Value: "192.0.2.10"}}, nil
		})
		result := scanDNSWithScanner(context.Background(), "example.test", DNSAXFR, scanner)
		if result.Method != "axfr" || !result.Complete || !hasDNSRecord(result.Records, "example.test", "A", "192.0.2.10") {
			t.Fatalf("AXFR result = %#v", result)
		}
	})

	t.Run("refusal falls back to discovery", func(t *testing.T) {
		scanner := fixtureDNSScanner(func(context.Context, string, []string) ([]DNSRecord, error) {
			return nil, errors.New("transfer refused")
		})
		result := scanDNSWithScanner(context.Background(), "example.test", DNSAXFR, scanner)
		if result.Method != "scan" || result.Complete || !containsDNSWarning(result.Warnings, "AXFR was refused") {
			t.Fatalf("AXFR fallback = %#v", result)
		}
	})
}

func TestDNSResolverNormalization(t *testing.T) {
	for _, test := range []struct {
		value string
		want  string
	}{
		{"1.1.1.1", "1.1.1.1:53"},
		{"[2606:4700:4700::1111]:5353", "[2606:4700:4700::1111]:5353"},
		{"resolver.example", "resolver.example:53"},
	} {
		got, err := normalizeDNSResolver(test.value)
		if err != nil || got != test.want {
			t.Fatalf("normalizeDNSResolver(%q) = (%q, %v), want (%q, nil)", test.value, got, err, test.want)
		}
	}
	if _, err := normalizeDNSResolver("[2606:4700:4700::1111]:not-a-port"); err == nil {
		t.Fatal("an invalid resolver port should fail")
	}
}

func fixtureDNSScanner(transfer func(context.Context, string, []string) ([]DNSRecord, error)) dnsScanner {
	return dnsScanner{queryFunc: fixtureDNSQuery, transferFunc: transfer}
}

func fixtureDNSQuery(_ context.Context, name string, recordType uint16) ([]mdns.RR, error) {
	name = strings.ToLower(name)
	switch {
	case name == "example.test." && recordType == mdns.TypeNS:
		return []mdns.RR{testNS("example.test.", "ns1.example.test.")}, nil
	case name == "example.test." && recordType == mdns.TypeMX:
		return []mdns.RR{testMX("example.test.", 10, "mail.example.test.")}, nil
	case name == "example.test." && recordType == mdns.TypeA:
		return []mdns.RR{testA("example.test.", "192.0.2.10")}, nil
	case name == "www.example.test." && recordType == mdns.TypeA:
		return []mdns.RR{testCNAME("www.example.test.", "origin.example.test.")}, nil
	case name == "origin.example.test." && recordType == mdns.TypeA:
		return []mdns.RR{testA("origin.example.test.", "192.0.2.31")}, nil
	case name == "mail.example.test." && recordType == mdns.TypeA:
		return []mdns.RR{testA("mail.example.test.", "192.0.2.25")}, nil
	case strings.HasPrefix(name, "whodis-") && recordType == mdns.TypeA:
		return []mdns.RR{testA(name, "192.0.2.77")}, nil
	case name == "api.example.test." && recordType == mdns.TypeA:
		return []mdns.RR{testA(name, "192.0.2.77")}, nil
	}
	return nil, nil
}

func testHeader(name string, recordType uint16) mdns.RR_Header {
	return mdns.RR_Header{Name: name, Rrtype: recordType, Class: mdns.ClassINET, Ttl: 300}
}

func testA(name, address string) mdns.RR {
	return &mdns.A{Hdr: testHeader(name, mdns.TypeA), A: net.ParseIP(address)}
}

func testNS(name, nameserver string) mdns.RR {
	return &mdns.NS{Hdr: testHeader(name, mdns.TypeNS), Ns: nameserver}
}

func testMX(name string, preference uint16, target string) mdns.RR {
	return &mdns.MX{Hdr: testHeader(name, mdns.TypeMX), Preference: preference, Mx: target}
}

func testCNAME(name, target string) mdns.RR {
	return &mdns.CNAME{Hdr: testHeader(name, mdns.TypeCNAME), Target: target}
}

func hasDNSRecord(records []DNSRecord, name, recordType, value string) bool {
	for _, record := range records {
		if record.Name == name && record.Type == recordType && record.Value == value {
			return true
		}
	}
	return false
}

func hasDNSRecordName(records []DNSRecord, name string) bool {
	for _, record := range records {
		if record.Name == name {
			return true
		}
	}
	return false
}

func containsDNSWarning(warnings []string, fragment string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, fragment) {
			return true
		}
	}
	return false
}
