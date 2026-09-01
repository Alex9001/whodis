package whodis

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const bootstrapFixture = `{"version":"1","publication":"2026-01-01T00:00:00Z","services":[[["com"],["https://rdap.example/"]]]}`

func bootstrapResponse(status int, body string, headers http.Header) *http.Response {
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: headers, Body: io.NopCloser(strings.NewReader(body))}
}

func TestBootstrapCacheUsesETagAndNotModified(t *testing.T) {
	requests := 0
	cache := newBootstrapCache(t.TempDir())
	cache.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			return bootstrapResponse(http.StatusOK, bootstrapFixture, http.Header{"Etag": {"fixture"}, "Cache-Control": {"max-age=60"}}), nil
		}
		if request.Header.Get("If-None-Match") != "fixture" {
			t.Fatalf("If-None-Match = %q", request.Header.Get("If-None-Match"))
		}
		return bootstrapResponse(http.StatusNotModified, "", http.Header{"Cache-Control": {"max-age=120"}}), nil
	})}
	first, err := cache.registry(context.Background(), bootstrapDNS, true, time.Second)
	if err != nil || len(first.Services) != 1 {
		t.Fatalf("first registry = %#v, %v", first, err)
	}
	second, err := cache.registry(context.Background(), bootstrapDNS, true, time.Second)
	if err != nil || len(second.Services) != 1 || requests != 2 {
		t.Fatalf("second registry = %#v, %v; requests=%d", second, err, requests)
	}
}

func TestBootstrapCacheFallsBackToStaleValidPayload(t *testing.T) {
	cache := newBootstrapCache(t.TempDir())
	cache.write(bootstrapDNS, bootstrapCacheEntry{Payload: []byte(bootstrapFixture), Expires: time.Now().Add(-time.Hour)})
	cache.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("offline")
	})}
	registry, err := cache.registry(context.Background(), bootstrapDNS, true, time.Second)
	if err != nil || len(registry.Services) != 1 {
		t.Fatalf("stale fallback = %#v, %v", registry, err)
	}
}

func TestBootstrapRejectsOversizedResponse(t *testing.T) {
	cache := newBootstrapCache(t.TempDir())
	cache.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return bootstrapResponse(http.StatusOK, strings.Repeat(" ", (5<<20)+1), http.Header{}), nil
	})}
	if _, err := cache.registry(context.Background(), bootstrapDNS, true, time.Second); err == nil {
		t.Fatal("oversized bootstrap payload was accepted")
	}
}
