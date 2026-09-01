package main

import (
	"strings"
	"testing"
	"time"

	"github.com/Alex9001/whodis/v2/audit"
)

func TestParseCheckCLIOptions(t *testing.T) {
	options, help, err := parseCheckCLIOptions([]string{
		"example.com", "--active", "--against", "baseline", "--scrutiny", "strict",
		"--policy", "policy.yaml", "--webhook-env", "HOOK", "--markdown",
		"--output", "report.md", "--timeout", "45s", "--jobs", "8", "--save", "--label", "nightly",
	})
	if err != nil || help {
		t.Fatalf("parseCheckCLIOptions() = (%+v, %v, %v)", options, help, err)
	}
	if strings.Join(options.targets, ",") != "example.com" || !options.active || options.against != "baseline" ||
		options.scrutiny != audit.ScrutinyStrict || options.policy != "policy.yaml" || options.webhookEnv != "HOOK" ||
		options.format != "markdown" || options.output != "report.md" || options.timeout != 45*time.Second ||
		options.jobs != 8 || !options.save || options.label != "nightly" {
		t.Fatalf("parsed check options = %+v", options)
	}
}

func TestParseCheckCLIOptionsRejectsInvalidCombinations(t *testing.T) {
	for _, args := range [][]string{
		{"--active", "--passive", "example.com"},
		{"example.com", "--timeout", "never"},
		{"example.com", "--jobs", "0"},
		{"example.com", "--json", "--yaml"},
		{"example.com", "--unknown"},
		{"example.com", "--policy"},
	} {
		if _, _, err := parseCheckCLIOptions(args); err == nil {
			t.Fatalf("parseCheckCLIOptions(%q) succeeded", args)
		}
	}
}

func TestValidateCheckCLIOptions(t *testing.T) {
	for _, options := range []checkCLIOptions{
		{label: "nightly"},
		{snapshot: "saved", targets: []string{"example.com"}},
		{},
	} {
		if err := validateCheckCLIOptions(options); err == nil {
			t.Fatalf("validateCheckCLIOptions(%+v) succeeded", options)
		}
	}
	if err := validateCheckCLIOptions(checkCLIOptions{targets: []string{"example.com"}}); err != nil {
		t.Fatalf("valid target check rejected: %v", err)
	}
	if err := validateCheckCLIOptions(checkCLIOptions{snapshot: "saved"}); err != nil {
		t.Fatalf("valid offline check rejected: %v", err)
	}
}
