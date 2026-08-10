package main

import (
	"bytes"
	"io"
	"runtime/debug"
	"strings"
	"testing"
)

func TestParseArgsDetails(t *testing.T) {
	for _, format := range []string{"dashboard", "tree", "geekboys", "plain", "json", "yaml", "markdown", "raw"} {
		t.Run(format, func(t *testing.T) {
			options, err := parseArgs([]string{"example.com", "--format", format, "--details"})
			if err != nil {
				t.Fatalf("parseArgs() error = %v", err)
			}
			if !options.details {
				t.Fatal("parseArgs() details = false, want true")
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
	options, err := parseArgs([]string{"example.com", "--details", "--no-details", "--color", "never"})
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

func TestUsageIncludesDetails(t *testing.T) {
	var output bytes.Buffer
	printUsage(&output)
	for _, value := range []string{"--details", "--no-details", "whodis config"} {
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
