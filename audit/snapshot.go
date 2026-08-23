package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Alex9001/whodis/v2"
)

// NewSnapshot creates a sanitized immutable snapshot value.
func NewSnapshot(requests []whodis.Request, batch whodis.BatchReport, generator GeneratorInfo, label string) (Snapshot, error) {
	if len(requests) == 0 || len(batch.Reports) == 0 || len(requests) != len(batch.Reports) {
		return Snapshot{}, fmt.Errorf("snapshot requests and reports must be non-empty and have matching lengths")
	}
	createdAt := time.Now().UTC()
	replay := make([]ReplayRequest, len(requests))
	for index, request := range requests {
		if request.Operation == whodis.OperationDNSTransfer || request.Diagnose.Remote || request.Diagnose.Trace || len(request.Investigation.Enrichments) > 0 {
			return Snapshot{}, fmt.Errorf("zone transfers, remote/path diagnoses, and third-party enrichments cannot be snapshotted")
		}
		replay[index] = sanitizeRequest(request)
	}
	sanitized := sanitizeBatch(batch)
	fingerprint, _ := json.Marshal(struct {
		CreatedAt time.Time
		Requests  []ReplayRequest
	}{createdAt, replay})
	sum := sha256.Sum256(fingerprint)
	id := "snap_" + createdAt.Format("20060102T150405Z") + "_" + hex.EncodeToString(sum[:4])
	return Snapshot{
		SchemaVersion: SnapshotSchemaVersion, ID: id, Label: strings.TrimSpace(label), CreatedAt: createdAt,
		Generator: generator, Requests: replay, Batch: sanitized,
	}, nil
}

func sanitizeRequest(request whodis.Request) ReplayRequest {
	timeout := ""
	if request.Timeout > 0 {
		timeout = request.Timeout.String()
	}
	dns := request.DNS
	dns.Resolvers = append([]string(nil), request.DNS.Resolvers...)
	dns.Transfer.TSIGSecret = ""
	dns.GlobalpingToken = ""
	dns.GlobalpingHTTPClient = nil
	dns.GlobalpingEndpoint = ""
	for index := range dns.Resolvers {
		dns.Resolvers[index] = sanitizeSnapshotEndpoint(dns.Resolvers[index])
	}
	return ReplayRequest{
		Operation: request.Operation, Target: request.Target, Timeout: timeout,
		Registration: RegistrationOptions{Protocol: request.Registration.Protocol, Fallback: request.Registration.Fallback, Server: sanitizeSnapshotEndpoint(request.Registration.Server), RefreshBootstrap: request.Registration.RefreshBootstrap},
		DNS:          dns, Diagnose: ReplayDiagnoseOptions{Trace: request.Diagnose.Trace, Remote: request.Diagnose.Remote, MaxAddresses: request.Diagnose.MaxAddresses},
		Investigation: ReplayInvestigationOptions{RelatedLimit: request.Investigation.RelatedLimit, ExternalLinkTemplate: request.Investigation.ExternalLinkTemplate},
	}
}

func sanitizeBatch(batch whodis.BatchReport) whodis.BatchReport {
	encoded, _ := json.Marshal(batch)
	var sanitized whodis.BatchReport
	_ = json.Unmarshal(encoded, &sanitized)
	for reportIndex := range sanitized.Reports {
		report := &sanitized.Reports[reportIndex]
		report.RequestID = ""
		if report.Registration != nil {
			report.Registration.Route.Endpoint = sanitizeSnapshotEndpoint(report.Registration.Route.Endpoint)
			if report.Registration.FallbackFrom != nil {
				report.Registration.FallbackFrom.Endpoint = sanitizeSnapshotEndpoint(report.Registration.FallbackFrom.Endpoint)
			}
			for index := range report.Registration.Sources {
				report.Registration.Sources[index].Endpoint = sanitizeSnapshotEndpoint(report.Registration.Sources[index].Endpoint)
				report.Registration.Sources[index].Authority = sanitizeSnapshotEndpoint(report.Registration.Sources[index].Authority)
			}
		}
		sanitizeDNS(report.DNS)
		if report.Diagnosis != nil {
			sanitizeDNS(report.Diagnosis.DNS)
			sanitizeDNS(report.Diagnosis.Delegation)
			for index := range report.Diagnosis.Reachability {
				report.Diagnosis.Reachability[index].Duration = 0
			}
			for index := range report.Diagnosis.HTTP {
				report.Diagnosis.HTTP[index].Duration = 0
			}
			for index := range report.Diagnosis.TLS {
				report.Diagnosis.TLS[index].Duration = 0
			}
			for index := range report.Diagnosis.Mail {
				report.Diagnosis.Mail[index].Duration = 0
			}
			for index := range report.Diagnosis.Services {
				report.Diagnosis.Services[index].Duration = 0
			}
			for index := range report.Diagnosis.Path {
				report.Diagnosis.Path[index].Duration = 0
			}
		}
	}
	return sanitized
}

func sanitizeDNS(result *whodis.DNSOperationResult) {
	if result == nil {
		return
	}
	for index := range result.Messages {
		result.Messages[index].Raw = nil
		result.Messages[index].ID = 0
		result.Messages[index].Duration = 0
		result.Messages[index].Resolver = sanitizeSnapshotEndpoint(result.Messages[index].Resolver)
		result.Messages[index].Server = sanitizeSnapshotEndpoint(result.Messages[index].Server)
	}
	for index := range result.Trace {
		result.Trace[index].Duration = 0
		result.Trace[index].Server = sanitizeSnapshotEndpoint(result.Trace[index].Server)
	}
	for index := range result.Remote {
		result.Remote[index].Resolver = sanitizeSnapshotEndpoint(result.Remote[index].Resolver)
	}
}

// Requests reconstructs safe engine requests from the snapshot.
func (snapshot Snapshot) RequestsForReplay() ([]whodis.Request, error) {
	return snapshot.RequestsForReplayWithOptions(ReplayOptions{})
}

// RequestsForReplayWithOptions reconstructs engine requests. Restoring custom
// network endpoints requires an explicit opt-in because imported snapshots are
// otherwise an SSRF and configuration-execution boundary.
func (snapshot Snapshot) RequestsForReplayWithOptions(options ReplayOptions) ([]whodis.Request, error) {
	if err := validateSnapshot(snapshot); err != nil {
		return nil, err
	}
	requests := make([]whodis.Request, len(snapshot.Requests))
	for index, saved := range snapshot.Requests {
		if !options.AllowCustomEndpoints && replayUsesCustomEndpoints(saved) {
			return nil, fmt.Errorf("snapshot request %d contains custom network endpoints; allow them only when the snapshot is trusted", index)
		}
		timeout := time.Duration(0)
		if saved.Timeout != "" {
			value, err := time.ParseDuration(saved.Timeout)
			if err != nil {
				return nil, fmt.Errorf("snapshot request %d has invalid timeout: %w", index, err)
			}
			timeout = value
		}
		requests[index] = whodis.Request{
			Operation: saved.Operation, Target: saved.Target, Timeout: timeout, DNS: saved.DNS,
			Registration:  whodis.LookupOptions{Protocol: saved.Registration.Protocol, Fallback: saved.Registration.Fallback, Server: saved.Registration.Server, Timeout: timeout, RefreshBootstrap: saved.Registration.RefreshBootstrap},
			Diagnose:      whodis.DiagnoseOptions{DNS: saved.DNS, Timeout: timeout, Trace: saved.Diagnose.Trace, Remote: saved.Diagnose.Remote, MaxAddresses: saved.Diagnose.MaxAddresses},
			Investigation: whodis.InvestigationOptions{DNS: saved.DNS, RelatedLimit: saved.Investigation.RelatedLimit, ExternalLinkTemplate: saved.Investigation.ExternalLinkTemplate},
		}
	}
	return requests, nil
}

func replayUsesCustomEndpoints(request ReplayRequest) bool {
	if strings.TrimSpace(request.Registration.Server) != "" {
		return true
	}
	for _, resolver := range request.DNS.Resolvers {
		switch strings.ToLower(strings.TrimSpace(resolver)) {
		case "", "system", "system://", "authoritative":
		default:
			return true
		}
	}
	return false
}

func sanitizeSnapshotEndpoint(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || !strings.Contains(value, "://") || strings.HasPrefix(strings.ToLower(value), "sdns://") {
		return value
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return value
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	return parsed.String()
}
