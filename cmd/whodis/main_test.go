package main

import (
	"bytes"
	"runtime/debug"
	"strings"
	"testing"
)

func TestParseArgsDetails(t *testing.T) {
	for _, format := range []string{"pretty", "plain", "json", "yaml", "markdown", "raw"} {
		t.Run(format, func(t *testing.T) {
			options, err := parseArgs([]string{"example.com", "--format", format, "--details"})
			if err != nil {
				t.Fatalf("parseArgs() error = %v", err)
			}
			if !options.details {
				t.Fatal("parseArgs() details = false, want true")
			}
			if _, err := chooseFormat(options); err != nil {
				t.Fatalf("chooseFormat() error = %v", err)
			}
		})
	}
}

func TestUsageIncludesDetails(t *testing.T) {
	var output bytes.Buffer
	printUsage(&output)
	if !strings.Contains(output.String(), "--details") {
		t.Fatalf("printUsage() output does not document --details:\n%s", output.String())
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
