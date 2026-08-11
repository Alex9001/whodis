package whodis

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"
)

func TestQueryGlobalpingUsesExplicitEndpointAndReturnsStructuredAnswers(t *testing.T) {
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
		}
		response := &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header)}
		switch request.Method + " " + request.URL.Path {
		case "POST /v1/measurements":
			var payload struct {
				Target             string `json:"target"`
				Limit              int    `json:"limit"`
				MeasurementOptions struct {
					Query struct {
						Type string `json:"type"`
					} `json:"query"`
				} `json:"measurementOptions"`
			}
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				t.Error(err)
			}
			if payload.Target != "example.test" || payload.Limit != 2 || payload.MeasurementOptions.Query.Type != "A" {
				t.Errorf("payload = %#v", payload)
			}
			response.Body = io.NopCloser(strings.NewReader(`{"id":"measurement-1"}`))
		case "GET /v1/measurements/measurement-1":
			response.Body = io.NopCloser(strings.NewReader(`{"status":"finished","results":[{"probe":{"id":"probe-1","city":"Seattle","country":"US","network":"ExampleNet"},"result":{"statusCode":"NOERROR","resolver":"192.0.2.53","answers":[{"name":"example.test.","type":"A","ttl":300,"value":"192.0.2.1"}],"timings":{"total":12.5}}}]}`))
		default:
			response.StatusCode, response.Status = http.StatusNotFound, "404 Not Found"
			response.Body = io.NopCloser(strings.NewReader("not found"))
		}
		return response, nil
	})}

	measurements, err := queryGlobalping(context.Background(), "example.test", []uint16{mdns.TypeA}, DNSOptions{
		GlobalpingEndpoint: "https://globalping.test/v1", GlobalpingLimit: 2, GlobalpingToken: "test-token", GlobalpingHTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || len(measurements) != 1 || measurements[0].Location != "Seattle, US, ExampleNet" || measurements[0].Rcode != "NOERROR" || len(measurements[0].Answers) != 1 || measurements[0].Answers[0].Value != "192.0.2.1" {
		t.Fatalf("measurements = %#v (requests %d)", measurements, requests)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
