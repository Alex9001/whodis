package whodis

import "testing"

func TestRepresentativeAddressesBoundsWork(t *testing.T) {
	records := []DNSRecord{
		{Name: "example.test", Type: "A", Value: "192.0.2.1"},
		{Name: "example.test", Type: "A", Value: "192.0.2.2"},
		{Name: "www.example.test", Type: "AAAA", Value: "2001:db8::1"},
		{Name: "other.example.test", Type: "A", Value: "192.0.2.99"},
	}
	addresses := representativeAddresses(records, "example.test", 2)
	if len(addresses) != 2 || addresses[0] != "192.0.2.1" || addresses[1] != "192.0.2.2" {
		t.Fatalf("addresses = %#v", addresses)
	}
}

func TestAdvertisedServicesOnlyUsesBoundedDNSAdvertisedPorts(t *testing.T) {
	records := []DNSRecord{
		{Name: "_xmpp._tcp.example.test", Type: "SRV", Value: "0 5 5222 xmpp.example.test."},
		{Name: "example.test", Type: "HTTPS", Value: "1 . alpn=\"h2\" port=8443"},
		{Name: "bad.example.test", Type: "SRV", Value: "invalid"},
	}
	services := advertisedServices(records)
	if len(services) != 2 || services[0].Port != 5222 || services[1].Port != 8443 {
		t.Fatalf("services = %#v", services)
	}
}

func TestBuildFindingsIsDeterministicAndHasNoScore(t *testing.T) {
	report := &DiagnosisReport{
		DNS:          &DNSOperationResult{Inventory: &DNSResult{Records: []DNSRecord{{Name: "example.test", Type: "A", Value: "192.0.2.1"}}}},
		Delegation:   &DNSOperationResult{Trace: []DNSTraceHop{{Zone: ".", Rcode: "NOERROR"}}},
		Reachability: []AddressProbe{{Address: "192.0.2.1", Reachable: true}},
		HTTP:         []HTTPProbe{{URL: "https://example.test", Status: 200}},
		TLS:          []TLSProbe{{ServerName: "example.test", Verified: true}},
		Policies:     map[string][]string{"spf": {"v=spf1 -all"}},
	}
	first := buildFindings(report, nil, nil)
	second := buildFindings(report, nil, nil)
	if len(first) == 0 || len(first) != len(second) {
		t.Fatalf("findings = %#v / %#v", first, second)
	}
	for index := range first {
		if first[index].ID != second[index].ID || first[index].Severity != second[index].Severity || first[index].Summary != second[index].Summary {
			t.Fatalf("finding order changed at %d: %#v / %#v", index, first[index], second[index])
		}
	}
}
