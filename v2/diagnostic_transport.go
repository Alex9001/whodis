package whodis

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

func newDiagnosticHTTPClient(policy NetworkPolicy, timeout time.Duration, redirectLimit int, onRedirect func(string)) *http.Client {
	transport := &http.Transport{
		TLSHandshakeTimeout:    minimumDuration(timeout, 4*time.Second),
		ResponseHeaderTimeout:  minimumDuration(timeout, 5*time.Second),
		MaxResponseHeaderBytes: 1 << 20,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialDiagnosticContext(ctx, network, address, minimumDuration(timeout, 4*time.Second), policy)
		},
	}
	client := &http.Client{Transport: transport, Timeout: timeout}
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if onRedirect != nil {
			onRedirect(request.URL.String())
		}
		if len(via) >= redirectLimit {
			return fmt.Errorf("too many redirects")
		}
		if request.URL.Scheme != "https" && request.URL.Scheme != "http" {
			return fmt.Errorf("unsupported redirect scheme %q", request.URL.Scheme)
		}
		_, err := permittedDiagnosticAddresses(request.Context(), request.URL.Hostname(), policy)
		return err
	}
	return client
}

func minimumDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func diagnosticProbeError(scope string, err error) (string, bool) {
	if err == nil {
		return "", false
	}
	message := strings.TrimSpace(scope)
	if message != "" {
		message += ": "
	}
	message += err.Error()
	return message, diagnosticDestinationBlocked(err)
}
