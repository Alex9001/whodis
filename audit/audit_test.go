package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Alex9001/whodis/v2"
)

func snapshotFixture(t *testing.T, ttl uint32, records []whodis.DNSRecord) Snapshot {
	t.Helper()
	if records == nil {
		records = []whodis.DNSRecord{{Name: "example.test", Type: "NS", TTL: ttl, Value: "ns1.example.test"}}
	}
	request := whodis.Request{Operation: whodis.OperationInspect, Target: "example.test", Timeout: 20 * time.Second, DNS: whodis.DNSOptions{Transfer: whodis.TransferOptions{TSIGSecret: "secret"}}}
	batch := whodis.BatchReport{SchemaVersion: whodis.ReportSchemaVersion, Reports: []whodis.Report{{
		SchemaVersion: whodis.ReportSchemaVersion, RequestID: "transient", Operation: whodis.OperationInspect,
		Subject: whodis.Subject{Original: "example.test", Canonical: "example.test", Kind: whodis.SubjectRegistrableDomain, RegistrationDomain: "example.test"}, ObservedAt: time.Now().UTC(),
		Registration: &whodis.RegistrationResult{Object: whodis.Object{Events: []whodis.Event{{Action: "expiration", Date: time.Now().Add(10 * 24 * time.Hour).UTC().Format(time.RFC3339)}}}},
		DNS:          &whodis.DNSOperationResult{Mode: "inventory", Inventory: &whodis.DNSResult{Records: records}, Messages: []whodis.DNSMessage{{ID: 123, Duration: time.Second, Raw: []byte("wire")}}},
	}}}
	snapshot, err := NewSnapshot([]whodis.Request{request}, batch, GeneratorInfo{Name: "whodis", Version: "test"}, "baseline")
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestSnapshotSanitizesSecretsAndTransientDNSData(t *testing.T) {
	snapshot := snapshotFixture(t, 300, nil)
	if snapshot.Requests[0].DNS.Transfer.TSIGSecret != "" {
		t.Fatal("TSIG secret was retained")
	}
	message := snapshot.Batch.Reports[0].DNS.Messages[0]
	if message.ID != 0 || message.Duration != 0 || len(message.Raw) != 0 || snapshot.Batch.Reports[0].RequestID != "" {
		t.Fatalf("transient data retained: %#v", message)
	}
}

func TestFileStoreRoundTripAndPermissions(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := snapshotFixture(t, 300, nil)
	path, err := store.Put(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Get("baseline")
	if err != nil || loaded.ID != snapshot.ID {
		t.Fatalf("loaded = %#v, err = %v", loaded, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("snapshot mode = %v, err = %v", info.Mode().Perm(), err)
		}
	}
}

func TestFileStoreRejectsUnsafeSnapshotIdentity(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := snapshotFixture(t, 300, nil)
	snapshot.ID = "../../outside"
	if _, err := store.Put(snapshot); err == nil {
		t.Fatal("Put accepted a path-traversing snapshot ID")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(store.Directory), "outside.whodis.json")); !os.IsNotExist(err) {
		t.Fatalf("unexpected file outside snapshot store: %v", err)
	}
}

func TestSnapshotRejectsUnsafeReplayOperations(t *testing.T) {
	for name, mutate := range map[string]func(*Snapshot){
		"zone transfer": func(snapshot *Snapshot) {
			snapshot.Requests[0].Operation = whodis.OperationDNSTransfer
			snapshot.Batch.Reports[0].Operation = whodis.OperationDNSTransfer
		},
		"remote diagnosis": func(snapshot *Snapshot) {
			snapshot.Requests[0].Diagnose.Remote = true
		},
		"path trace": func(snapshot *Snapshot) {
			snapshot.Requests[0].Diagnose.Trace = true
		},
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := snapshotFixture(t, 300, nil)
			mutate(&snapshot)
			if _, err := snapshot.RequestsForReplay(); err == nil || !strings.Contains(err.Error(), "unsafe replay") {
				t.Fatalf("RequestsForReplay error = %v", err)
			}
		})
	}
}

func TestSnapshotInvestigationReplayIsLocalAndSchemaV4RemainsReadable(t *testing.T) {
	base := snapshotFixture(t, 300, nil)
	base.Requests[0].Operation = whodis.OperationInvestigate
	base.Requests[0].Investigation = ReplayInvestigationOptions{RelatedLimit: 40, LinkProviders: []string{"otx", "virustotal"}}
	base.Batch.Reports[0].Operation = whodis.OperationInvestigate
	requests, err := base.RequestsForReplay()
	if err != nil || len(requests) != 1 || requests[0].Investigation.RelatedLimit != 40 || strings.Join(requests[0].Investigation.LinkProviders, ",") != "otx,virustotal" || len(requests[0].Investigation.Enrichments) != 0 || requests[0].Investigation.OTXEndpoint != "" || requests[0].Investigation.OTXToken != "" {
		t.Fatalf("local investigation replay = %#v, %v", requests, err)
	}

	legacy := snapshotFixture(t, 300, nil)
	legacy.Batch.SchemaVersion = 4
	legacy.Batch.Reports[0].SchemaVersion = 4
	if _, err := legacy.RequestsForReplay(); err != nil {
		t.Fatalf("schema-v4 snapshot no longer replays: %v", err)
	}
}

func TestSnapshotRejectsThirdPartyInvestigationEnrichment(t *testing.T) {
	request := whodis.Request{Operation: whodis.OperationInvestigate, Target: "example.test", Investigation: whodis.InvestigationOptions{Enrichments: []string{"otx"}}}
	batch := snapshotFixture(t, 300, nil).Batch
	batch.Reports[0].Operation = whodis.OperationInvestigate
	if _, err := NewSnapshot([]whodis.Request{request}, batch, GeneratorInfo{Name: "whodis", Version: "test"}, ""); err == nil || !strings.Contains(err.Error(), "third-party") {
		t.Fatalf("NewSnapshot enrichment error = %v", err)
	}
}

func TestSnapshotRejectsMismatchedReportSubject(t *testing.T) {
	snapshot := snapshotFixture(t, 300, nil)
	snapshot.Batch.Reports[0].Subject.Canonical = "other.test"
	if _, err := snapshot.RequestsForReplay(); err == nil || !strings.Contains(err.Error(), "subject does not match") {
		t.Fatalf("RequestsForReplay error = %v", err)
	}
}

func TestSnapshotReplayRequiresTrustForCustomEndpoints(t *testing.T) {
	snapshot := snapshotFixture(t, 300, nil)
	snapshot.Requests[0].DNS.Resolvers = []string{"https://127.0.0.1/dns-query"}
	if _, err := snapshot.RequestsForReplay(); err == nil || !strings.Contains(err.Error(), "custom network endpoints") {
		t.Fatalf("safe replay error = %v", err)
	}
	requests, err := snapshot.RequestsForReplayWithOptions(ReplayOptions{AllowCustomEndpoints: true})
	if err != nil || len(requests) != 1 || len(requests[0].DNS.Resolvers) != 1 {
		t.Fatalf("trusted replay = %#v, %v", requests, err)
	}
}

func TestSnapshotSanitizesEndpointCredentials(t *testing.T) {
	request := whodis.Request{
		Operation: whodis.OperationInspect,
		Target:    "example.test",
		Registration: whodis.LookupOptions{
			Protocol: whodis.ProtocolRDAP,
			Server:   "https://user:secret@rdap.example.test/base?token=secret#fragment",
		},
		DNS: whodis.DNSOptions{Resolvers: []string{"https://user:secret@dns.example.test/dns-query?token=secret"}},
	}
	batch := snapshotFixture(t, 300, nil).Batch
	snapshot, err := NewSnapshot([]whodis.Request{request}, batch, GeneratorInfo{Name: "whodis", Version: "test"}, "")
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(snapshot.Requests[0])
	if strings.Contains(string(encoded), "secret") || strings.Contains(string(encoded), "token=") {
		t.Fatalf("credentials retained in %s", encoded)
	}
	if got := request.DNS.Resolvers[0]; got != "https://user:secret@dns.example.test/dns-query?token=secret" {
		t.Fatalf("NewSnapshot mutated the caller's request resolver: %q", got)
	}
}

func TestDiffIgnoresTTLAndOrderByDefault(t *testing.T) {
	before := snapshotFixture(t, 100, []whodis.DNSRecord{
		{Name: "example.test", Type: "NS", TTL: 100, Value: "ns1.example.test"},
		{Name: "example.test", Type: "A", TTL: 100, Value: "192.0.2.1"},
	})
	after := snapshotFixture(t, 200, []whodis.DNSRecord{
		{Name: "example.test", Type: "A", TTL: 200, Value: "192.0.2.1"},
		{Name: "example.test", Type: "NS", TTL: 200, Value: "ns1.example.test"},
	})
	changes, err := Diff(before, after, DiffOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(changes.Changes) != 0 {
		t.Fatalf("TTL/order produced changes: %#v", changes.Changes)
	}
	changes, err = Diff(before, after, DiffOptions{IncludeTTL: true})
	if err != nil || len(changes.Changes) == 0 {
		t.Fatalf("TTL-aware diff = %#v, %v", changes, err)
	}
}

func TestDiffCanonicalizesEquivalentRequestScope(t *testing.T) {
	before := snapshotFixture(t, 300, nil)
	after := snapshotFixture(t, 300, nil)
	before.Requests[0].Target = "EXAMPLE.TEST"
	before.Requests[0].DNS.Types = []string{"mx", "A"}
	before.Requests[0].DNS.Resolvers = []string{"system://z", "system://a"}
	after.Requests[0].DNS.Types = []string{"A", "MX"}
	after.Requests[0].DNS.Resolvers = []string{"system://a", "system://z"}
	changes, err := Diff(before, after, DiffOptions{})
	if err != nil || len(changes.Warnings) != 0 {
		t.Fatalf("equivalent scope diff = %#v, %v", changes, err)
	}
	if got := before.Requests[0].DNS.Types; len(got) != 2 || got[0] != "mx" || got[1] != "A" {
		t.Fatalf("Diff mutated the caller's DNS types: %#v", got)
	}
	if got := before.Requests[0].DNS.Resolvers; len(got) != 2 || got[0] != "system://z" || got[1] != "system://a" {
		t.Fatalf("Diff mutated the caller's DNS resolvers: %#v", got)
	}
}

func TestDiffRefusesIncompatibleRequestScope(t *testing.T) {
	before := snapshotFixture(t, 300, nil)
	after := snapshotFixture(t, 300, nil)
	before.Requests[0].DNS.Types = []string{"A"}
	after.Requests[0].DNS.Types = []string{"MX"}
	after.Batch.Reports[0].DNS.Inventory.Records = nil
	changes, err := Diff(before, after, DiffOptions{})
	if err != nil || len(changes.Changes) != 0 || len(changes.Warnings) != 1 {
		t.Fatalf("incompatible scope diff = %#v, %v", changes, err)
	}
}

func TestDiffDoesNotReportRemovalFromIncompleteProvider(t *testing.T) {
	before := snapshotFixture(t, 300, nil)
	after := snapshotFixture(t, 300, nil)
	after.Batch.Reports[0].DNS = nil
	after.Batch.Reports[0].Errors = []whodis.OperationError{{Operation: whodis.OperationDNSInventory, Provider: "dns", Kind: whodis.ErrorUnavailable, Message: "resolver timed out"}}
	changes, err := Diff(before, after, DiffOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(changes.Changes) != 0 || len(changes.Warnings) == 0 {
		t.Fatalf("incomplete-provider diff = %#v", changes)
	}
}

func TestScrutinyPromotesApproachingExpiration(t *testing.T) {
	snapshot := snapshotFixture(t, 300, nil)
	standard, err := Evaluate(snapshot.Batch, nil, EvaluateOptions{Scrutiny: ScrutinyStandard})
	if err != nil {
		t.Fatal(err)
	}
	strict, err := Evaluate(snapshot.Batch, nil, EvaluateOptions{Scrutiny: ScrutinyStrict})
	if err != nil {
		t.Fatal(err)
	}
	if standard.Summary.Failed != 0 || standard.Summary.Warnings == 0 {
		t.Fatalf("standard summary = %#v", standard.Summary)
	}
	if strict.Summary.Failed == 0 {
		t.Fatalf("strict summary = %#v", strict.Summary)
	}
}

func TestEvaluateAcceptsTopLevelFindingsWithoutDiagnosisDetails(t *testing.T) {
	snapshot := snapshotFixture(t, 300, nil)
	report := &snapshot.Batch.Reports[0]
	report.Findings = []whodis.Finding{{ID: "custom", Severity: whodis.SeverityError, Summary: "custom check failed"}}
	report.Diagnosis = nil
	result, err := Evaluate(snapshot.Batch, nil, EvaluateOptions{Scrutiny: ScrutinyStandard})
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.Failed == 0 {
		t.Fatalf("top-level finding was not evaluated: %#v", result)
	}
}

func TestEvaluateAttributesEveryPerReportResult(t *testing.T) {
	first := snapshotFixture(t, 300, nil).Batch.Reports[0]
	second := first
	second.Subject.Canonical = "second.example.test"
	second.Subject.Original = "second.example.test"
	second.Subject.RegistrationDomain = "example.test"
	batch := whodis.BatchReport{SchemaVersion: whodis.ReportSchemaVersion, Reports: []whodis.Report{first, second}}
	result, err := Evaluate(batch, nil, EvaluateOptions{Scrutiny: ScrutinyStandard})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]string{}
	for _, rule := range result.Results {
		if rule.ReportIndex == nil || rule.Subject == nil {
			t.Fatalf("unattributed rule = %#v", rule)
		}
		seen[*rule.ReportIndex] = rule.Subject.Canonical
	}
	if seen[0] != "example.test" || seen[1] != "second.example.test" {
		t.Fatalf("attribution = %#v", seen)
	}
}

func TestPolicyRejectsInvalidRuleConfiguration(t *testing.T) {
	policy := Policy{SchemaVersion: PolicySchemaVersion, Rules: []Rule{{
		ID: "expiry", Type: "minimum_registration_days", Severity: whodis.SeverityWarning,
		Config: json.RawMessage(`{"days":"thirty","typo":true}`),
	}}}
	if err := ValidatePolicy(policy); err == nil {
		t.Fatal("ValidatePolicy accepted invalid typed config")
	}
}
