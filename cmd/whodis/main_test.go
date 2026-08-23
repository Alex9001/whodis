package main

import (
	"bytes"
	"io"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/Alex9001/whodis/v2"
)

func TestParseArgsDetails(t *testing.T) {
	for _, format := range []string{"dashboard", "tree", "geekboys", "plain", "json", "yaml", "markdown", "raw"} {
		t.Run(format, func(t *testing.T) {
			options, err := parseArgs([]string{"example.com", "--" + format, "--details"})
			if err != nil {
				t.Fatalf("parseArgs() error = %v", err)
			}
			if !options.details || !options.formatSet || options.format != format {
				t.Fatalf("parseArgs() = %+v, want details and %s shortcut", options, format)
			}
			runtime := cliRuntime{
				getenv:        func(string) string { return "" },
				userConfigDir: func() (string, error) { return t.TempDir(), nil },
				isTerminal:    func(io.Writer) bool { return false },
			}
			if _, err := chooseFormat(options, &bytes.Buffer{}, runtime); err != nil {
				t.Fatalf("chooseFormat() error = %v", err)
			}
		})
	}
}

func TestParseArgsNoDetailsAndColorTracking(t *testing.T) {
	options, err := parseArgs([]string{"example.com", "--summary", "--color", "never"})
	if err != nil {
		t.Fatalf("parseArgs() error = %v", err)
	}
	if !options.detailsSet || options.details {
		t.Fatalf("details options = (set=%v, value=%v), want explicit summary", options.detailsSet, options.details)
	}
	if !options.colorSet || options.color != "never" {
		t.Fatalf("color options = (set=%v, value=%q), want explicit never", options.colorSet, options.color)
	}
}

func TestParseArgsDNSOptions(t *testing.T) {
	options, err := parseArgs([]string{"example.com"})
	if err != nil {
		t.Fatalf("parseArgs() error = %v", err)
	}
	if options.task != taskLookup || taskDNSMode(options.task) != whodis.DNSOff {
		t.Fatalf("default task = %q, want registration-only lookup", options.task)
	}

	for _, args := range [][]string{{"scan", "example.com"}, {"rdap", "scan", "example.com"}} {
		options, err = parseArgs(args)
		if err != nil || options.target != "example.com" || options.task != taskScan || taskDNSMode(options.task) != whodis.DNSScan {
			t.Fatalf("parseArgs(%q) = (%+v, %v), want target and scan mode", args, options, err)
		}
	}

	options, err = parseArgs([]string{"scan", "example.com", "--resolver", "1.1.1.1:5353"})
	if err != nil || options.task != taskScan || options.dnsResolver != "1.1.1.1:5353" {
		t.Fatalf("resolver DNS options = (%q, %q, %v), want scan and resolver", options.task, options.dnsResolver, err)
	}

	options, err = parseArgs([]string{"axfr", "example.com"})
	if err != nil || options.task != taskAXFR || taskDNSMode(options.task) != whodis.DNSAXFR {
		t.Fatalf("axfr command = (%q, %v), want axfr and no error", options.task, err)
	}

	for _, args := range [][]string{
		{"example.com", "--resolver", "1.1.1.1"},
		{"--dns", "example.com"},
		{"example.com", "--axfr"},
	} {
		if _, err := parseArgs(args); err == nil {
			t.Fatalf("parseArgs(%q) succeeded, want an error", args)
		}
	}
}

func TestParseArgsStructuredDNSAndDiagnose(t *testing.T) {
	options, err := parseArgs([]string{"dns", "query", "example.com", "A", "TYPE65", "--class", "IN", "--resolver", "udp://1.1.1.1", "--resolver", "https://dns.example/dns-query", "--strategy", "consensus", "--dnssec", "--nsid"})
	if err != nil {
		t.Fatal(err)
	}
	if options.task != taskDNSQuery || options.target != "example.com" || strings.Join(options.recordTypes, ",") != "A,TYPE65" || len(options.dnsResolvers) != 2 || options.resolverStrategy != whodis.ResolverConsensus || !options.edns.DNSSEC || !options.edns.NSID {
		t.Fatalf("DNS query options = %#v", options)
	}

	options, err = parseArgs([]string{"dns", "transfer", "example.com", "--ixfr", "--serial", "42", "--tls", "--tsig-name", "key.example", "--tsig-secret", "c2VjcmV0"})
	if err != nil {
		t.Fatal(err)
	}
	if options.task != taskDNSTransfer || options.transfer.Type != "IXFR" || options.transfer.Serial != 42 || !options.transfer.TLS {
		t.Fatalf("DNS transfer options = %#v", options)
	}

	options, err = parseArgs([]string{"diagnose", "example.com", "example.net", "--trace", "--remote"})
	if err != nil || options.task != taskDiagnose || len(options.targets) != 2 || !options.trace || !options.remote {
		t.Fatalf("diagnose options = (%#v, %v)", options, err)
	}

	options, err = parseArgs([]string{"diagnose", "example.com", "--remote", "--from", "US", "--limit", "2"})
	if err != nil || !options.remote || len(options.globalpingFrom) != 1 || options.globalpingLimit != 2 {
		t.Fatalf("remote diagnose options = (%#v, %v)", options, err)
	}
	if _, err = parseArgs([]string{"dns", "query", "example.com", "A", "--trace"}); err == nil {
		t.Fatal("dns query accepted diagnose-only --trace")
	}
}

func TestParseArgsInvestigateAndExplicitEnrichment(t *testing.T) {
	options, err := parseArgs([]string{"investigate", "example.com", "example.net", "--enrich", "otx", "--related-limit", "40", "--research-links", "otx,virustotal", "--investigation-link", "https://intel.example/{type}/{value}", "--otx-endpoint", "https://otx.example/api/v1"})
	if err != nil {
		t.Fatal(err)
	}
	if options.task != taskInvestigate || len(options.targets) != 2 || options.timeout != 30*time.Second || options.relatedLimit != 40 || strings.Join(options.enrichments, ",") != "otx" || strings.Join(options.linkProviders, ",") != "otx,virustotal" || options.otxEndpoint != "https://otx.example/api/v1" {
		t.Fatalf("investigate options = %#v", options)
	}
	for _, args := range [][]string{
		{"example.com", "--enrich", "otx"},
		{"investigate", "example.com", "--enrich", "unknown"},
		{"investigate", "example.com", "--research-links", "all,otx"},
		{"example.com", "--research-links", "core"},
		{"investigate", "example.com", "--enrich", "otx", "--save"},
		{"investigate", "example.com", "--investigation-link", "http://unsafe.example/{type}/{value}"},
		{"investigate", "example.com", "--otx-endpoint", "http://unsafe.example/api"},
	} {
		if _, err := parseArgs(args); err == nil {
			t.Fatalf("parseArgs(%q) succeeded, want an error", args)
		}
	}
	explicit, err := parseArgs([]string{"investigate", "example.com", "--timeout", "5s"})
	if err != nil || explicit.timeout != 5*time.Second {
		t.Fatalf("explicit investigation timeout = (%s, %v)", explicit.timeout, err)
	}
}

func TestRejectsOperationSpecificOptionsOnUnrelatedCommands(t *testing.T) {
	tests := [][]string{
		{"dns", "query", "example.com", "A", "--ixfr"},
		{"dns", "trace", "example.com", "A", "--globalping"},
		{"dns", "transfer", "example.com", "--tsig-algorithm", "hmac-sha256"},
	}
	for _, args := range tests {
		if _, err := parseArgs(args); err == nil {
			t.Fatalf("parseArgs(%q) succeeded, want an operation-specific option error", args)
		}
	}
}

func TestParseNoDNSSECOverride(t *testing.T) {
	options, err := parseArgs([]string{"dns", "query", "example.com", "A", "--no-dnssec"})
	if err != nil {
		t.Fatal(err)
	}
	if !options.dnssecSet || options.edns.DNSSEC {
		t.Fatalf("DNSSEC override = %#v", options)
	}
}

func TestParseExplicitCSVAndNDJSONFormats(t *testing.T) {
	for _, format := range []string{"csv", "ndjson"} {
		options, err := parseArgs([]string{"example.com", "--format", format})
		if err != nil || !options.formatSet || options.format != format {
			t.Fatalf("--format %s = (%+v, %v)", format, options, err)
		}
	}
}

func TestUsageIncludesDetailsAndDNS(t *testing.T) {
	var output bytes.Buffer
	printUsage(&output)
	for _, value := range []string{"inspect", "investigate", "--enrich otx", "dns transfer", "expires", "get <fields>", "--details", "--summary", "--resolver", "whodis config", "snapshot", "--format"} {
		if !strings.Contains(output.String(), value) {
			t.Fatalf("printUsage() output does not document %q:\n%s", value, output.String())
		}
	}
}

func TestResolveVersion(t *testing.T) {
	tests := []struct {
		name        string
		injected    string
		buildInfo   *debug.BuildInfo
		buildInfoOK bool
		want        string
	}{
		{
			name:        "injected release wins",
			injected:    "0.1.0",
			buildInfo:   &debug.BuildInfo{Main: debug.Module{Version: "v0.2.0"}},
			buildInfoOK: true,
			want:        "0.1.0",
		},
		{
			name:        "tagged go install uses module version",
			injected:    "dev",
			buildInfo:   &debug.BuildInfo{Main: debug.Module{Version: "v0.1.0"}},
			buildInfoOK: true,
			want:        "0.1.0",
		},
		{
			name:        "empty injected version uses module version",
			injected:    "",
			buildInfo:   &debug.BuildInfo{Main: debug.Module{Version: "v0.1.0"}},
			buildInfoOK: true,
			want:        "0.1.0",
		},
		{
			name:        "local build is development version",
			injected:    "dev",
			buildInfo:   &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}},
			buildInfoOK: true,
			want:        "dev",
		},
		{
			name:        "missing build information is development version",
			injected:    "dev",
			buildInfo:   nil,
			buildInfoOK: false,
			want:        "dev",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := resolveVersion(test.injected, test.buildInfo, test.buildInfoOK); got != test.want {
				t.Fatalf("resolveVersion() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestRunVersionUsesInjectedVersion(t *testing.T) {
	previousVersion := version
	version = "0.1.0"
	t.Cleanup(func() { version = previousVersion })

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if exitCode := run([]string{"--version"}, &stdout, &stderr); exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if got, want := stdout.String(), "whodis 0.1.0\n"; got != want {
		t.Fatalf("run() stdout = %q, want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("run() stderr = %q, want empty output", stderr.String())
	}
}

func TestGeneratedShellCompletions(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{"completion", shell}, &stdout, &stderr); code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "diagnose") || !strings.Contains(stdout.String(), "resolver") || !strings.Contains(stdout.String(), "allow-snapshot-endpoints") {
			t.Fatalf("completion %s = (code %d, stdout %q, stderr %q)", shell, code, stdout.String(), stderr.String())
		}
	}
}

func TestParseArgsBatchSelectors(t *testing.T) {
	options, err := parseArgs([]string{"get", "expiration,registrar", "google.com", "yahoo.com", "--jobs", "6"})
	if err != nil {
		t.Fatalf("parseArgs() error = %v", err)
	}
	if got, want := strings.Join(options.targets, ","), "google.com,yahoo.com"; got != want {
		t.Fatalf("targets = %q, want %q", got, want)
	}
	if options.jobs != 6 || len(options.fields) != 2 || options.fields[0] != whodis.FieldExpiration || options.fields[1] != whodis.FieldRegistrar {
		t.Fatalf("batch options = %#v", options)
	}
}

func TestParseArgsProtocolTaskGrammar(t *testing.T) {
	tests := []struct {
		args     []string
		protocol whodis.Protocol
		task     cliTask
		server   string
		fields   []whodis.ProjectionField
	}{
		{args: []string{"whois", "scan", "example.com"}, protocol: whodis.ProtocolWHOIS, task: taskScan},
		{args: []string{"rdap", "expires", "google.com"}, protocol: whodis.ProtocolRDAP, task: taskExpires, fields: []whodis.ProjectionField{whodis.FieldExpiration}},
		{args: []string{"rwhois", "get", "status", "192.0.2.1", "--server", "rwhois.example.net"}, protocol: whodis.ProtocolRWHOIS, task: taskGet, server: "rwhois.example.net", fields: []whodis.ProjectionField{whodis.FieldStatus}},
	}
	for _, test := range tests {
		options, err := parseArgs(test.args)
		if err != nil {
			t.Fatalf("parseArgs(%q) error = %v", test.args, err)
		}
		if options.protocol != test.protocol || options.task != test.task || options.server != test.server || strings.Join(projectionNames(options.fields), ",") != strings.Join(projectionNames(test.fields), ",") {
			t.Fatalf("parseArgs(%q) = %+v, want protocol/task/server/fields %q/%q/%q/%q", test.args, options, test.protocol, test.task, test.server, test.fields)
		}
	}
}

func TestParseArgsRejectsLegacyFlagsWithoutHints(t *testing.T) {
	for _, arg := range []string{"--dns", "--axfr", "--expiration", "--fields", "--protocol", "--fallback", "--refresh-bootstrap", "--no-details"} {
		_, err := parseArgs([]string{"example.com", arg})
		if err == nil || !strings.Contains(err.Error(), "unknown option "+arg) || strings.Contains(strings.ToLower(err.Error()), "instead") {
			t.Fatalf("parseArgs legacy %q error = %v, want generic unknown-option error", arg, err)
		}
	}
}

func TestParseArgsCommandConstraints(t *testing.T) {
	for _, args := range [][]string{
		{"rwhois", "example.com"},
		{"example.com", "--server", "whois.example.net"},
		{"whois", "example.com", "--server", "whois.example.net", "--strict"},
		{"whois", "example.com", "--refresh"},
		{"example.com", "--strict", "--try-both"},
		{"example.com", "--tree", "--json"},
		{"example.com", "--details", "--summary"},
	} {
		if _, err := parseArgs(args); err == nil {
			t.Fatalf("parseArgs(%q) succeeded, want error", args)
		}
	}
	if err := validateTaskTargets([]string{"8.8.8.8"}, taskScan); err == nil {
		t.Fatal("scan accepted an IP target, want a domain-only error")
	}
}

func TestParseArgsEscapesReservedTarget(t *testing.T) {
	options, err := parseArgs([]string{"whois", "--", "scan"})
	if err != nil || options.task != taskLookup || options.protocol != whodis.ProtocolWHOIS || len(options.targets) != 1 || options.targets[0] != "scan" {
		t.Fatalf("parseArgs escaped target = (%+v, %v), want WHOIS lookup for scan", options, err)
	}
}

func TestCommandHelp(t *testing.T) {
	for _, args := range [][]string{{"help", "scan"}, {"get", "--help"}, {"axfr", "--help"}} {
		var stdout, stderr bytes.Buffer
		if got := runWithRuntime(args, &stdout, &stderr, testRuntime(t.TempDir(), nil, false)); got != 0 || stdout.Len() == 0 || stderr.Len() != 0 {
			t.Fatalf("run(%q) = (%d, %q, %q), want command help", args, got, stdout.String(), stderr.String())
		}
	}
}

func TestAuditCommandHelp(t *testing.T) {
	tests := []struct {
		args []string
		want []string
	}{
		{args: []string{"snapshot", "list", "--help"}, want: []string{"snapshot list", "--json"}},
		{args: []string{"diff", "--help"}, want: []string{"--allow-snapshot-endpoints", "--markdown", "-o file"}},
		{args: []string{"check", "--help"}, want: []string{"--scrutiny", "--markdown", "-o file"}},
	}
	for _, test := range tests {
		var stdout, stderr bytes.Buffer
		if code := runWithRuntime(test.args, &stdout, &stderr, testRuntime(t.TempDir(), nil, false)); code != 0 || stderr.Len() != 0 {
			t.Fatalf("run(%q) = (%d, %q, %q), want command help", test.args, code, stdout.String(), stderr.String())
		}
		for _, value := range test.want {
			if !strings.Contains(stdout.String(), value) {
				t.Fatalf("run(%q) help does not include %q: %s", test.args, value, stdout.String())
			}
		}
	}
}

func projectionNames(fields []whodis.ProjectionField) []string {
	names := make([]string, len(fields))
	for index, field := range fields {
		names[index] = string(field)
	}
	return names
}

func TestResolveInputsReadsPipedTargets(t *testing.T) {
	runtime := cliRuntime{
		stdin:           strings.NewReader("# comment\ngoogle.com\n\nyahoo.com\n"),
		stdinIsTerminal: func() bool { return false },
	}
	inputs, err := resolveInputs(cliOptions{}, runtime)
	if err != nil {
		t.Fatalf("resolveInputs() error = %v", err)
	}
	if got, want := strings.Join(inputs, ","), "google.com,yahoo.com"; got != want {
		t.Fatalf("inputs = %q, want %q", got, want)
	}
}
