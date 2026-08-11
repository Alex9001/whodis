package whodis

import (
	"context"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"
)

func TestNativeDNSQueryCapturesAllSectionsAndMetadata(t *testing.T) {
	provider := &nativeDNSProvider{exchangeFunc: func(_ context.Context, request *mdns.Msg, _ resolverSpec) (*mdns.Msg, []byte, error) {
		response := new(mdns.Msg)
		response.SetReply(request)
		response.Authoritative = true
		response.Answer = []mdns.RR{testA("example.test.", "192.0.2.10")}
		response.Ns = []mdns.RR{testNS("example.test.", "ns1.example.test.")}
		response.Extra = []mdns.RR{testA("ns1.example.test.", "192.0.2.53")}
		raw, err := response.Pack()
		return response, raw, err
	}}
	result, err := provider.Query(context.Background(), "example.test", DNSOptions{Types: []string{"A"}, Resolvers: []string{"tcp://192.0.2.53"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Messages) != 1 {
		t.Fatalf("messages = %#v", result.Messages)
	}
	message := result.Messages[0]
	if message.Transport != "tcp" || !message.Flags.Authoritative || message.Rcode != "NOERROR" {
		t.Fatalf("metadata = %#v", message)
	}
	if len(message.Answer) != 1 || len(message.Authority) != 1 || len(message.Additional) != 1 || len(message.Raw) == 0 {
		t.Fatalf("sections = %#v", message)
	}
}

func TestDNSCompareNormalizesTTLAndOrder(t *testing.T) {
	messages := []DNSMessage{
		{Resolver: "one", Rcode: "NOERROR", Answer: []DNSRecord{{Name: "example.test", Type: "A", TTL: 30, Value: "192.0.2.1"}}},
		{Resolver: "two", Rcode: "NOERROR", Answer: []DNSRecord{{Name: "example.test", Type: "A", TTL: 300, Value: "192.0.2.1"}}},
		{Resolver: "three", Rcode: "NOERROR", Answer: []DNSRecord{{Name: "example.test", Type: "A", TTL: 30, Value: "192.0.2.2"}}},
	}
	differences := compareDNSMessages(messages)
	if len(differences) != 1 || differences[0].Resolver != "three" {
		t.Fatalf("differences = %#v", differences)
	}
}

func TestResolverURIParsing(t *testing.T) {
	specs, err := parseResolverSpecs([]string{"udp://1.1.1.1", "tcp://[2606:4700:4700::1111]:5353", "tls://dns.example", "https://dns.example/dns-query", "h3://dns.example/dns-query", "doq://dns.example", "sdns://AQcAAAAAAAAAEzE5Mi4wLjIuMTo0NDM"})
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 7 || specs[0].address != "1.1.1.1:53" || specs[1].address != "[2606:4700:4700::1111]:5353" || specs[2].address != "dns.example:853" || specs[3].transport != "https" || specs[4].transport != "h3" || specs[5].address != "dns.example:853" || specs[6].transport != "dnscrypt" {
		t.Fatalf("resolver specs = %#v", specs)
	}
}

func TestAuthoritativeOnlyRejectsNonAuthoritativeSuccess(t *testing.T) {
	provider := &nativeDNSProvider{exchangeFunc: func(_ context.Context, request *mdns.Msg, _ resolverSpec) (*mdns.Msg, []byte, error) {
		response := new(mdns.Msg)
		response.SetReply(request)
		response.Answer = []mdns.RR{testA("example.test.", "192.0.2.10")}
		return response, nil, nil
	}}
	result, err := provider.Query(context.Background(), "example.test", DNSOptions{
		Types: []string{"A"}, Resolvers: []string{"192.0.2.53"}, AuthoritativeOnly: true,
	})
	if err == nil || result == nil || len(result.Messages) != 0 {
		t.Fatalf("result = %#v, error = %v; want unavailable after filtering", result, err)
	}
}

func TestConsensusQueryRecordsNormalizedDifferences(t *testing.T) {
	provider := &nativeDNSProvider{exchangeFunc: func(_ context.Context, request *mdns.Msg, resolver resolverSpec) (*mdns.Msg, []byte, error) {
		response := new(mdns.Msg)
		response.SetReply(request)
		address := "192.0.2.1"
		if strings.Contains(resolver.original, "second") {
			address = "192.0.2.2"
		}
		response.Answer = []mdns.RR{testA("example.test.", address)}
		return response, nil, nil
	}}
	result, err := provider.Query(context.Background(), "example.test", DNSOptions{
		Types: []string{"A"}, Resolvers: []string{"first.test", "second.test"}, Strategy: ResolverConsensus,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Messages) != 2 || len(result.Differences) != 1 {
		t.Fatalf("consensus result = %#v", result)
	}
}

func TestValidateDNSOptionsRejectsMalformedEDNS(t *testing.T) {
	for _, options := range []DNSOptions{
		{EDNS: EDNSOptions{BufferSize: 511}},
		{EDNS: EDNSOptions{ECS: "not-a-prefix"}},
		{EDNS: EDNSOptions{Cookie: "abcd"}},
		{GlobalpingLimit: 11},
		{Transfer: TransferOptions{TSIGName: "key.example"}},
	} {
		if err := ValidateDNSOptions(options); err == nil {
			t.Fatalf("ValidateDNSOptions(%#v) succeeded", options)
		}
	}
}
