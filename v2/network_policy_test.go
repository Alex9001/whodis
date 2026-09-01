package whodis

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestPublicNetworkAddressRejectsPrivateAndSpecialUseRanges(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.1.1", "192.0.2.1", "198.18.0.1", "203.0.113.1", "::1", "fc00::1", "fe80::1", "2001:db8::1", "::ffff:127.0.0.1"} {
		if publicNetworkAddress(netip.MustParseAddr(value)) {
			t.Errorf("%s was treated as a public referral destination", value)
		}
	}
	for _, value := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888"} {
		if !publicNetworkAddress(netip.MustParseAddr(value)) {
			t.Errorf("%s was rejected as non-public", value)
		}
	}
}

func TestAutomaticDialRejectsPrivateLiteralBeforeConnecting(t *testing.T) {
	connection, err := dialAutomaticContext(context.Background(), "tcp", "127.0.0.1:43", time.Second, NetworkPolicy{})
	if connection != nil {
		_ = connection.Close()
		t.Fatal("automatic dial unexpectedly connected to a private address")
	}
	if err == nil {
		t.Fatal("automatic dial accepted a private address")
	}
}
