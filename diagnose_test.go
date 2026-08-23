package whodis

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

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

func TestDiagnosticAddressesBlockNonPublicByDefault(t *testing.T) {
	allowed, warnings := diagnosticAddresses([]string{"8.8.8.8", "127.0.0.1", "192.0.2.1"}, NetworkPolicy{})
	if len(allowed) != 1 || allowed[0] != "8.8.8.8" || len(warnings) != 2 {
		t.Fatalf("allowed = %#v, warnings = %#v", allowed, warnings)
	}
	allowed, warnings = diagnosticAddresses([]string{"127.0.0.1"}, NetworkPolicy{AllowPrivate: true})
	if len(allowed) != 1 || allowed[0] != "127.0.0.1" || len(warnings) != 0 {
		t.Fatalf("private opt-in = %#v, %#v", allowed, warnings)
	}
}

func TestDiagnosticDialRequiresPrivateOptIn(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if connection, err := dialDiagnosticContext(context.Background(), "tcp", listener.Addr().String(), time.Second, NetworkPolicy{}); err == nil {
		connection.Close()
		t.Fatal("private diagnostic destination was allowed by default")
	} else if !diagnosticDestinationBlocked(err) {
		t.Fatalf("blocked error = %v", err)
	}
	accepted := make(chan struct{})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			connection.Close()
		}
		close(accepted)
	}()
	connection, err := dialDiagnosticContext(context.Background(), "tcp", listener.Addr().String(), time.Second, NetworkPolicy{AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("private opt-in connection was not accepted")
	}
}

func TestDiagnosticHTTPRedirectRejectsPrivateDestination(t *testing.T) {
	client := newDiagnosticHTTPClient(NetworkPolicy{}, time.Second, 5, nil)
	request := &http.Request{URL: &url.URL{Scheme: "https", Host: "127.0.0.1", Path: "/redirected"}}
	via := []*http.Request{{URL: &url.URL{Scheme: "https", Host: "example.test"}}}
	err := client.CheckRedirect(request, via)
	if err == nil || !diagnosticDestinationBlocked(err) {
		t.Fatalf("private redirect error = %v", err)
	}
}

func TestPolicyBlockedProbesAreIndeterminateFindings(t *testing.T) {
	httpProbe := HTTPProbe{URL: "https://private.test", Error: "blocked", policyBlocked: true}
	tlsProbe := TLSProbe{ServerName: "private.test", Error: "blocked", policyBlocked: true}
	if finding := httpFinding([]HTTPProbe{httpProbe}); finding.Severity != SeverityWarning {
		t.Fatalf("HTTP finding = %#v", finding)
	}
	if finding := tlsFinding([]TLSProbe{tlsProbe}); finding.Severity != SeverityWarning {
		t.Fatalf("TLS finding = %#v", finding)
	}
}

func TestProbeConcurrencyIsCancellationAware(t *testing.T) {
	provider := &nativeDiagnoseProvider{probeSlots: make(chan struct{}, 1)}
	release, ok := provider.acquireProbe(context.Background())
	if !ok {
		t.Fatal("first probe slot was not acquired")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, acquired := provider.acquireProbe(ctx); acquired {
		t.Fatal("canceled probe acquired a full slot")
	}
	release()
}
