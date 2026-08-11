package whodis

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const defaultGlobalpingEndpoint = "https://api.globalping.io/v1"

// RemoteDNSMeasurement is one explicitly requested Globalping probe result.
type RemoteDNSMeasurement struct {
	MeasurementID string        `json:"measurement_id" yaml:"measurement_id"`
	Status        string        `json:"status" yaml:"status"`
	Probe         string        `json:"probe,omitempty" yaml:"probe,omitempty"`
	Location      string        `json:"location,omitempty" yaml:"location,omitempty"`
	Resolver      string        `json:"resolver,omitempty" yaml:"resolver,omitempty"`
	Rcode         string        `json:"rcode,omitempty" yaml:"rcode,omitempty"`
	Duration      time.Duration `json:"duration_ns,omitempty" yaml:"duration_ns,omitempty"`
	Answers       []DNSRecord   `json:"answers,omitempty" yaml:"answers,omitempty"`
	Raw           string        `json:"raw,omitempty" yaml:"raw,omitempty"`
	Error         string        `json:"error,omitempty" yaml:"error,omitempty"`
}

func queryGlobalping(ctx context.Context, name string, types []uint16, options DNSOptions) ([]RemoteDNSMeasurement, error) {
	limit := options.GlobalpingLimit
	if limit == 0 {
		limit = 3
	}
	if limit < 1 || limit > 10 {
		return nil, lookupError(ErrorInvalidInput, "Globalping limit must be between 1 and 10", nil)
	}
	endpoint := strings.TrimRight(strings.TrimSpace(options.GlobalpingEndpoint), "/")
	if endpoint == "" {
		endpoint = defaultGlobalpingEndpoint
	}
	locations := make([]map[string]string, 0, len(options.GlobalpingLocations))
	for _, location := range options.GlobalpingLocations {
		if strings.TrimSpace(location) != "" {
			locations = append(locations, map[string]string{"magic": strings.TrimSpace(location)})
		}
	}
	client := options.GlobalpingHTTPClient
	if client == nil {
		client = &http.Client{Timeout: 12 * time.Second}
	}
	var measurements []RemoteDNSMeasurement
	var failures []string
	for _, typeID := range types {
		payload := map[string]any{
			"target": name, "type": "dns", "limit": limit, "locations": locations,
			"measurementOptions": map[string]any{"query": map[string]string{"type": dnsTypeName(typeID)}},
		}
		body, _ := json.Marshal(payload)
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/measurements", bytes.NewReader(body))
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("User-Agent", "whodis/1")
		if options.GlobalpingToken != "" {
			request.Header.Set("Authorization", "Bearer "+options.GlobalpingToken)
		}
		response, err := client.Do(request)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 2<<20))
		_ = response.Body.Close()
		if readErr != nil {
			failures = append(failures, readErr.Error())
			continue
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			failures = append(failures, fmt.Sprintf("Globalping returned HTTP %s", response.Status))
			continue
		}
		var created struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(responseBody, &created); err != nil || created.ID == "" {
			failures = append(failures, "Globalping returned an invalid measurement ID")
			continue
		}
		results, err := pollGlobalping(ctx, client, endpoint, created.ID, options.GlobalpingToken)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		measurements = append(measurements, results...)
	}
	if len(failures) > 0 {
		return measurements, lookupError(ErrorUnavailable, "Globalping: "+strings.Join(uniqueStrings(failures), "; "), nil)
	}
	return measurements, nil
}

func pollGlobalping(ctx context.Context, client *http.Client, endpoint, id, token string) ([]RemoteDNSMeasurement, error) {
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/measurements/"+id, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("User-Agent", "whodis/1")
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := client.Do(request)
		if err != nil {
			return nil, err
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 8<<20))
		_ = response.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return nil, fmt.Errorf("measurement %s returned HTTP %s", id, response.Status)
		}
		var status struct {
			Status  string `json:"status"`
			Results []struct {
				Probe struct {
					ID      string `json:"id"`
					City    string `json:"city"`
					Country string `json:"country"`
					Network string `json:"network"`
				} `json:"probe"`
				Result struct {
					StatusCode any    `json:"statusCode"`
					Resolver   string `json:"resolver"`
					RawOutput  string `json:"rawOutput"`
					Answers    []struct {
						Name  string `json:"name"`
						Type  string `json:"type"`
						TTL   uint32 `json:"ttl"`
						Value string `json:"value"`
					} `json:"answers"`
					Timings struct {
						Total float64 `json:"total"`
					} `json:"timings"`
				} `json:"result"`
			} `json:"results"`
		}
		if err := json.Unmarshal(body, &status); err != nil {
			return nil, err
		}
		if status.Status == "in-progress" || status.Status == "queued" {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(750 * time.Millisecond):
				continue
			}
		}
		measurements := make([]RemoteDNSMeasurement, 0, len(status.Results))
		for _, item := range status.Results {
			measurement := RemoteDNSMeasurement{MeasurementID: id, Status: status.Status, Probe: item.Probe.ID, Location: strings.Trim(strings.Join([]string{item.Probe.City, item.Probe.Country, item.Probe.Network}, ", "), ", "), Resolver: item.Result.Resolver, Rcode: fmt.Sprint(item.Result.StatusCode), Duration: time.Duration(item.Result.Timings.Total * float64(time.Millisecond)), Raw: item.Result.RawOutput}
			if number, ok := item.Result.StatusCode.(float64); ok {
				measurement.Rcode = strconv.Itoa(int(number))
			}
			for _, answer := range item.Result.Answers {
				measurement.Answers = append(measurement.Answers, DNSRecord{Name: normalizeDNSName(answer.Name), Type: answer.Type, TTL: answer.TTL, Value: answer.Value})
			}
			measurements = append(measurements, measurement)
		}
		return measurements, nil
	}
}
