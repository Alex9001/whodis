package whodis

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// NetworkPolicy controls exceptional access to private network destinations.
// Automatically discovered referrals and diagnostic targets remain restricted
// to public addresses by default.
type NetworkPolicy struct {
	AllowPrivate      bool `json:"allow_private,omitempty" yaml:"allow_private,omitempty"`
	AllowInsecureHTTP bool `json:"allow_insecure_http,omitempty" yaml:"allow_insecure_http,omitempty"`
}

func validateAutomaticURL(ctx context.Context, endpoint string, policy NetworkPolicy) error {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Hostname() == "" {
		return lookupError(ErrorProtocol, "automatic referral returned an invalid URL", err)
	}
	if parsed.Scheme != "https" && !policy.AllowInsecureHTTP {
		return lookupError(ErrorProtocol, "automatic RDAP referrals must use HTTPS", nil)
	}
	return validateAutomaticHost(ctx, parsed.Hostname(), policy)
}

func validateAutomaticHost(ctx context.Context, host string, policy NetworkPolicy) error {
	_, err := permittedAutomaticAddresses(ctx, host, policy)
	return err
}

func permittedAutomaticAddresses(ctx context.Context, host string, policy NetworkPolicy) ([]netip.Addr, error) {
	return permittedNetworkAddresses(ctx, host, policy, "automatic referral")
}

var errPrivateNetworkDestination = errors.New("private network destination blocked")

func permittedDiagnosticAddresses(ctx context.Context, host string, policy NetworkPolicy) ([]netip.Addr, error) {
	return permittedNetworkAddresses(ctx, host, policy, "diagnostic destination")
}

func permittedNetworkAddresses(ctx context.Context, host string, policy NetworkPolicy, description string) ([]netip.Addr, error) {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return nil, lookupError(ErrorProtocol, description+" returned an empty host", nil)
	}
	var addresses []netip.Addr
	if address, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{address}
	} else {
		resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, lookupError(ErrorUnavailable, "could not resolve "+description, err)
		}
		addresses = resolved
	}
	if len(addresses) == 0 {
		return nil, lookupError(ErrorUnavailable, description+" has no addresses", nil)
	}
	if !policy.AllowPrivate {
		for _, address := range addresses {
			if !publicNetworkAddress(address) {
				return nil, lookupError(ErrorProtocol, fmt.Sprintf("%s resolved to non-public address %s and was blocked", description, address), errPrivateNetworkDestination)
			}
		}
	}
	return addresses, nil
}

func diagnosticDestinationBlocked(err error) bool {
	return errors.Is(err, errPrivateNetworkDestination)
}

// dialDiagnosticContext resolves and validates a target-derived host at dial
// time, then connects to the approved address directly. This prevents a DNS
// change between validation and connection from bypassing NetworkPolicy.
func dialDiagnosticContext(ctx context.Context, network, address string, timeout time.Duration, policy NetworkPolicy) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, lookupError(ErrorProtocol, "diagnostic destination returned an invalid network address", err)
	}
	addresses, err := permittedDiagnosticAddresses(ctx, host, policy)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: timeout}
	var lastErr error
	for _, candidate := range addresses {
		connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
		if dialErr == nil {
			return connection, nil
		}
		lastErr = dialErr
	}
	return nil, lookupError(ErrorUnavailable, "diagnostic destination is unavailable", lastErr)
}

// dialAutomaticContext resolves a referral once and dials the approved IP
// address directly. This closes the DNS-rebinding gap between validation and
// connection while preserving the original hostname for HTTP TLS validation.
func dialAutomaticContext(ctx context.Context, network, address string, timeout time.Duration, policy NetworkPolicy) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, lookupError(ErrorProtocol, "automatic referral returned an invalid network address", err)
	}
	addresses, err := permittedAutomaticAddresses(ctx, host, policy)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: timeout}
	var lastErr error
	for _, candidate := range addresses {
		connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
		if dialErr == nil {
			return connection, nil
		}
		lastErr = dialErr
	}
	return nil, lookupError(ErrorUnavailable, "automatic referral host is unavailable", lastErr)
}

func publicNetworkAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() {
		return false
	}
	for _, prefix := range nonPublicNetworkPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var nonPublicNetworkPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}
