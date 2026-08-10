package whodis

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseRWHOISSelectsLongestNetworkAndContacts(t *testing.T) {
	response := parseRWHOIS(`%rwhois V-1.5 example
network:ID:NET-WIDE
network:IP-Network:192.0.2.0/24
network:Network-Name:WIDE-NET

network:ID:NET-NARROW
network:IP-Network:192.0.2.128/25
network:Network-Name:NARROW-NET
network:Tech-Contact:TECH-1
network:Created:2024-01-02T03:04:05Z

contact:ID:TECH-1
contact:Name:Example Technical Contact
contact:Email:tech@example.test

%ok
`)
	object := normalizeRWHOIS(Target{Canonical: "192.0.2.129", Kind: KindIP}, response)
	if object.Handle != "NET-NARROW" || object.Name != "NARROW-NET" {
		t.Fatalf("selected object = %#v, want narrow network", object)
	}
	if len(object.CIDR) != 1 || object.CIDR[0] != "192.0.2.128/25" {
		t.Fatalf("CIDR = %#v, want narrow prefix", object.CIDR)
	}
	if len(object.Entities) != 1 || object.Entities[0].Email != "tech@example.test" {
		t.Fatalf("entities = %#v, want technical contact", object.Entities)
	}
	if len(object.Events) != 1 || object.Events[0].Action != "registration" {
		t.Fatalf("events = %#v, want registration event", object.Events)
	}
}

func TestRWHOISAdapterLookup(t *testing.T) {
	clientConnection, serverConnection := net.Pipe()
	defer clientConnection.Close()
	go func() {
		defer serverConnection.Close()
		_, _ = serverConnection.Write([]byte("%rwhois V-1.5 test\r\n"))
		query, err := bufio.NewReader(serverConnection).ReadString('\n')
		if err != nil {
			return
		}
		if strings.TrimSpace(query) != "192.0.2.1" {
			t.Errorf("query = %q, want canonical IP", strings.TrimSpace(query))
		}
		_, _ = serverConnection.Write([]byte("network:ID:NET-EXAMPLE\r\nnetwork:IP-Network:192.0.2.0/24\r\nnetwork:Network-Name:EXAMPLE\r\n%ok\r\n"))
	}()
	adapter := rwhoisAdapter{client: &Client{timeout: time.Second}}
	response, err := adapter.queryConnection(context.Background(), clientConnection, "192.0.2.1")
	if err != nil {
		t.Fatalf("queryConnection() error = %v", err)
	}
	object := normalizeRWHOIS(Target{Canonical: "192.0.2.1", Kind: KindIP}, response)
	if object.Name != "EXAMPLE" {
		t.Fatalf("object = %#v, want normalized RWhois response", object)
	}
	endpoint, err := canonicalEndpoint(ProtocolRWHOIS, "rwhois://example.test")
	if err != nil || endpoint != "rwhois://example.test:4321" {
		t.Fatalf("canonical RWhois endpoint = %q, %v", endpoint, err)
	}
}

func TestRWHOISReferralScoring(t *testing.T) {
	response := rwhoisResponse{Referrals: []string{
		"rwhois://wide.example/auth-area=192.0.2.0/24",
		"rwhois://narrow.example/auth-area=192.0.2.128/25",
	}}
	endpoint := response.bestReferral(Target{Canonical: "192.0.2.129", Kind: KindIP})
	if !strings.Contains(endpoint, "narrow.example") {
		t.Fatalf("best referral = %q, want narrow authority", endpoint)
	}
}

func TestWHOISRWHOISReferralAndEffectiveRoute(t *testing.T) {
	document := parseWHOIS("ReferralServer: rwhois://rwhois.example.test:4321/auth-area=192.0.2.0/24\n")
	endpoint := rwhoisReferral(document)
	if endpoint != "rwhois://rwhois.example.test:4321/auth-area=192.0.2.0/24" {
		t.Fatalf("rwhoisReferral() = %q", endpoint)
	}
	route := routedSources(RouteDecision{Protocol: ProtocolWHOIS, Endpoint: "whois.example.test"}, []Source{{Protocol: ProtocolWHOIS}, {Protocol: ProtocolRWHOIS, Endpoint: endpoint}})
	if route.Protocol != ProtocolRWHOIS || route.Endpoint != endpoint {
		t.Fatalf("effective route = %#v, want RWhois referral", route)
	}
}

func TestRWHOISRouteRequiresExplicitAuthority(t *testing.T) {
	client := NewClient(ClientOptions{CacheDirectory: t.TempDir()})
	if _, err := client.Route(context.Background(), "192.0.2.1", LookupOptions{Protocol: ProtocolRWHOIS}); err == nil {
		t.Fatal("Route() succeeded without an RWhois server")
	}
	route, err := client.Route(context.Background(), "192.0.2.1", LookupOptions{Protocol: ProtocolRWHOIS, Server: "rwhois.example.test"})
	if err != nil {
		t.Fatalf("Route() error = %v", err)
	}
	if route.Protocol != ProtocolRWHOIS || route.Endpoint != "rwhois://rwhois.example.test:4321" {
		t.Fatalf("route = %#v", route)
	}
}
