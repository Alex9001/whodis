package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"

	"github.com/Alex9001/whodis"
)

func testRuntime(directory string, environment map[string]string, terminal bool) cliRuntime {
	return cliRuntime{
		getenv: func(name string) string {
			return environment[name]
		},
		userConfigDir: func() (string, error) {
			return directory, nil
		},
		isTerminal: func(io.Writer) bool {
			return terminal
		},
	}
}

func runCLIForTest(t *testing.T, runtime cliRuntime, args ...string) (int, string, string) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runWithRuntime(args, &stdout, &stderr, runtime)
	return code, stdout.String(), stderr.String()
}

func writeConfigForTest(t *testing.T, directory, contents string) string {
	t.Helper()
	path := filepath.Join(directory, "whodis", "config.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestConfigCommands(t *testing.T) {
	directory := t.TempDir()
	runtime := testRuntime(directory, nil, false)

	code, stdout, stderr := runCLIForTest(t, runtime, "config", "get", "format")
	if code != 0 || stdout != "auto\n" || stderr != "" {
		t.Fatalf("initial get = (%d, %q, %q), want (0, auto, empty)", code, stdout, stderr)
	}

	code, stdout, stderr = runCLIForTest(t, runtime, "config", "path")
	wantPath := filepath.Join(directory, "whodis", "config.json") + "\n"
	if code != 0 || stdout != wantPath || stderr != "" {
		t.Fatalf("path = (%d, %q, %q), want (0, %q, empty)", code, stdout, stderr, wantPath)
	}

	code, stdout, stderr = runCLIForTest(t, runtime, "config", "set", "format", "tree")
	if code != 0 || stdout != "" || stderr != "" {
		t.Fatalf("set = (%d, %q, %q), want success without output", code, stdout, stderr)
	}
	payload, err := os.ReadFile(strings.TrimSuffix(wantPath, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(payload), "{\n  \"format\": \"tree\"\n}\n"; got != want {
		t.Fatalf("saved config = %q, want %q", got, want)
	}

	code, stdout, stderr = runCLIForTest(t, runtime, "config", "get", "format")
	if code != 0 || stdout != "tree\n" || stderr != "" {
		t.Fatalf("saved get = (%d, %q, %q), want tree", code, stdout, stderr)
	}

	for attempt := 0; attempt < 2; attempt++ {
		code, stdout, stderr = runCLIForTest(t, runtime, "config", "unset", "format")
		if code != 0 || stdout != "" || stderr != "" {
			t.Fatalf("unset attempt %d = (%d, %q, %q), want success without output", attempt, code, stdout, stderr)
		}
	}
	code, stdout, stderr = runCLIForTest(t, runtime, "config", "get", "format")
	if code != 0 || stdout != "auto\n" || stderr != "" {
		t.Fatalf("get after unset = (%d, %q, %q), want auto", code, stdout, stderr)
	}
}

func TestConfigSetCanonicalizesHumanAliases(t *testing.T) {
	tests := map[string]string{
		"dashboard": "dashboard",
		"pretty":    "dashboard",
		"grid":      "dashboard",
		"current":   "dashboard",
		"tree":      "tree",
		"geekboys":  "geekboys",
		"geek-boys": "geekboys",
		"retro":     "geekboys",
		"plain":     "plain",
		"text":      "plain",
		"txt":       "plain",
	}
	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			directory := t.TempDir()
			runtime := testRuntime(directory, nil, false)
			code, _, stderr := runCLIForTest(t, runtime, "config", "set", "format", input)
			if code != 0 {
				t.Fatalf("set exit code = %d, stderr = %q", code, stderr)
			}
			code, stdout, stderr := runCLIForTest(t, runtime, "config", "get", "format")
			if code != 0 || stdout != want+"\n" || stderr != "" {
				t.Fatalf("get = (%d, %q, %q), want %q", code, stdout, stderr, want)
			}
		})
	}
}

func TestConfigSetRejectsMachineFormats(t *testing.T) {
	for _, format := range []string{"json", "yaml", "markdown", "raw", ""} {
		t.Run(format, func(t *testing.T) {
			runtime := testRuntime(t.TempDir(), nil, false)
			code, stdout, stderr := runCLIForTest(t, runtime, "config", "set", "format", format)
			if code != 2 || stdout != "" || !strings.Contains(stderr, "dashboard, tree, geekboys, or plain") {
				t.Fatalf("set = (%d, %q, %q), want usage error naming persistent formats", code, stdout, stderr)
			}
		})
	}
}

func TestConfigWritesReplaceAtomically(t *testing.T) {
	directory := t.TempDir()
	runtime := testRuntime(directory, nil, false)
	for _, format := range []string{"tree", "dashboard", "plain"} {
		if err := saveUserConfig(runtime, userConfig{Format: format}); err != nil {
			t.Fatalf("saveUserConfig(%q): %v", format, err)
		}
	}
	config, exists, err := loadUserConfig(runtime)
	if err != nil || !exists || config.Format != "plain" {
		t.Fatalf("loadUserConfig() = (%+v, %v, %v), want plain", config, exists, err)
	}
	entries, err := os.ReadDir(filepath.Join(directory, "whodis"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "config.json" {
		t.Fatalf("config directory entries = %v, want only config.json", entries)
	}
	if goruntime.GOOS != "windows" {
		info, err := entries[0].Info()
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("config permissions = %#o, want 0600", got)
		}
	}
}

func TestConfigReportsMalformedAndInvalidFiles(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		message  string
	}{
		{name: "invalid JSON", contents: "{", message: "could not parse config"},
		{name: "trailing JSON", contents: "{} {}", message: "multiple JSON values"},
		{name: "null", contents: "null", message: "expected a JSON object"},
		{name: "invalid format", contents: `{"format":"json"}`, message: "cannot be saved"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			path := writeConfigForTest(t, directory, test.contents)
			code, stdout, stderr := runCLIForTest(t, testRuntime(directory, nil, false), "config", "get", "format")
			if code != 1 || stdout != "" || !strings.Contains(stderr, path) || !strings.Contains(stderr, test.message) {
				t.Fatalf("get = (%d, %q, %q), want actionable error containing %q and %q", code, stdout, stderr, path, test.message)
			}
		})
	}
}

func TestChooseFormatPrecedence(t *testing.T) {
	t.Run("explicit format bypasses every lower source", func(t *testing.T) {
		runtime := cliRuntime{
			getenv: func(string) string {
				t.Fatal("environment should not be read")
				return ""
			},
			userConfigDir: func() (string, error) {
				t.Fatal("config should not be read")
				return "", nil
			},
			isTerminal: func(io.Writer) bool {
				t.Fatal("terminal should not be inspected")
				return false
			},
		}
		format, err := chooseFormat(cliOptions{format: "tree", formatSet: true, output: "result.json"}, &bytes.Buffer{}, runtime)
		if err != nil || format != whodis.FormatTree {
			t.Fatalf("chooseFormat() = (%q, %v), want tree", format, err)
		}
	})

	for _, test := range []struct {
		name   string
		output string
		want   whodis.Format
	}{
		{name: "recognized extension", output: "result.geekboys", want: whodis.FormatGeekBoys},
		{name: "recognized extension alias", output: "result.grid", want: whodis.FormatPretty},
		{name: "unknown extension", output: "result.unknown", want: whodis.FormatPlain},
		{name: "missing extension", output: "result", want: whodis.FormatPlain},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := cliRuntime{
				getenv: func(string) string {
					t.Fatal("environment should not be read for a named output")
					return ""
				},
				userConfigDir: func() (string, error) {
					t.Fatal("config should not be read for a named output")
					return "", nil
				},
				isTerminal: func(io.Writer) bool {
					t.Fatal("terminal should not be inspected for a named output")
					return false
				},
			}
			format, err := chooseFormat(cliOptions{output: test.output}, &bytes.Buffer{}, runtime)
			if err != nil || format != test.want {
				t.Fatalf("chooseFormat() = (%q, %v), want %q", format, err, test.want)
			}
		})
	}

	t.Run("environment bypasses invalid config", func(t *testing.T) {
		directory := t.TempDir()
		writeConfigForTest(t, directory, "{")
		format, err := chooseFormat(cliOptions{}, &bytes.Buffer{}, testRuntime(directory, map[string]string{formatEnvironmentVariable: "json"}, false))
		if err != nil || format != whodis.FormatJSON {
			t.Fatalf("chooseFormat() = (%q, %v), want json", format, err)
		}
	})

	t.Run("saved format applies to terminal and pipe", func(t *testing.T) {
		for _, terminal := range []bool{false, true} {
			directory := t.TempDir()
			writeConfigForTest(t, directory, `{"format":"tree"}`)
			format, err := chooseFormat(cliOptions{output: "-"}, &bytes.Buffer{}, testRuntime(directory, nil, terminal))
			if err != nil || format != whodis.FormatTree {
				t.Fatalf("terminal=%v: chooseFormat() = (%q, %v), want tree", terminal, format, err)
			}
		}
	})

	t.Run("automatic terminal selection", func(t *testing.T) {
		for _, test := range []struct {
			terminal bool
			want     whodis.Format
		}{{terminal: true, want: whodis.FormatPretty}, {terminal: false, want: whodis.FormatPlain}} {
			format, err := chooseFormat(cliOptions{}, &bytes.Buffer{}, testRuntime(t.TempDir(), nil, test.terminal))
			if err != nil || format != test.want {
				t.Fatalf("terminal=%v: chooseFormat() = (%q, %v), want %q", test.terminal, format, err, test.want)
			}
		}
	})
}

func TestEnvironmentAcceptsEveryFormatAndAlias(t *testing.T) {
	tests := map[string]whodis.Format{
		"dashboard": whodis.FormatPretty,
		"pretty":    whodis.FormatPretty,
		"grid":      whodis.FormatPretty,
		"current":   whodis.FormatPretty,
		"tree":      whodis.FormatTree,
		"geekboys":  whodis.FormatGeekBoys,
		"geek-boys": whodis.FormatGeekBoys,
		"retro":     whodis.FormatGeekBoys,
		"plain":     whodis.FormatPlain,
		"text":      whodis.FormatPlain,
		"txt":       whodis.FormatPlain,
		"json":      whodis.FormatJSON,
		"yaml":      whodis.FormatYAML,
		"yml":       whodis.FormatYAML,
		"markdown":  whodis.FormatMarkdown,
		"md":        whodis.FormatMarkdown,
		"raw":       whodis.FormatRaw,
	}
	for value, want := range tests {
		t.Run(value, func(t *testing.T) {
			format, err := chooseFormat(cliOptions{}, &bytes.Buffer{}, testRuntime(t.TempDir(), map[string]string{formatEnvironmentVariable: value}, false))
			if err != nil || format != want {
				t.Fatalf("chooseFormat() = (%q, %v), want %q", format, err, want)
			}
		})
	}
}

func TestChooseFormatReportsInvalidEnvironmentAndConfig(t *testing.T) {
	t.Run("invalid environment", func(t *testing.T) {
		_, err := chooseFormat(cliOptions{}, &bytes.Buffer{}, testRuntime(t.TempDir(), map[string]string{formatEnvironmentVariable: "bogus"}, false))
		if err == nil || !strings.Contains(err.Error(), formatEnvironmentVariable) || !strings.Contains(err.Error(), "bogus") {
			t.Fatalf("chooseFormat() error = %v, want actionable environment error", err)
		}
	})
	t.Run("malformed config", func(t *testing.T) {
		directory := t.TempDir()
		path := writeConfigForTest(t, directory, "{")
		runtime := testRuntime(directory, nil, false)
		_, err := chooseFormat(cliOptions{}, &bytes.Buffer{}, runtime)
		if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "parse") {
			t.Fatalf("chooseFormat() error = %v, want actionable config error", err)
		}
		code, stdout, stderr := runCLIForTest(t, runtime, "example.com")
		if code != 1 || stdout != "" || !strings.Contains(stderr, path) {
			t.Fatalf("lookup with malformed config = (%d, %q, %q), want runtime error 1", code, stdout, stderr)
		}
	})
	t.Run("unavailable config directory falls back to automatic output", func(t *testing.T) {
		runtime := testRuntime("", nil, false)
		runtime.userConfigDir = func() (string, error) { return "", errors.New("no config home") }
		format, err := chooseFormat(cliOptions{}, &bytes.Buffer{}, runtime)
		if err != nil || format != whodis.FormatPlain {
			t.Fatalf("chooseFormat() = (%q, %v), want automatic plain output", format, err)
		}
	})
}

func TestConfigCommandReportsUnavailableDirectory(t *testing.T) {
	runtime := testRuntime("", nil, false)
	runtime.userConfigDir = func() (string, error) { return "", errors.New("no config home") }
	code, stdout, stderr := runCLIForTest(t, runtime, "config", "path")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "no config home") {
		t.Fatalf("config path = (%d, %q, %q), want actionable directory error", code, stdout, stderr)
	}
}

func TestConfigCommandValidationAndLookupEscape(t *testing.T) {
	runtime := testRuntime(t.TempDir(), nil, false)
	for _, test := range []struct {
		args    []string
		message string
	}{
		{args: []string{"config"}, message: "requires set, get, unset, or path"},
		{args: []string{"config", "unknown"}, message: "unknown config command"},
		{args: []string{"config", "get", "other"}, message: "config get format"},
		{args: []string{"config", "set", "format"}, message: "config set format"},
		{args: []string{"config", "unset", "other"}, message: "config unset format"},
		{args: []string{"config", "path", "extra"}, message: "accepts no arguments"},
	} {
		code, stdout, stderr := runCLIForTest(t, runtime, test.args...)
		if code != 2 || stdout != "" || !strings.Contains(stderr, test.message) {
			t.Fatalf("run(%v) = (%d, %q, %q), want usage error containing %q", test.args, code, stdout, stderr, test.message)
		}
	}

	options, err := parseArgs([]string{"--", "config"})
	if err != nil || options.target != "config" {
		t.Fatalf("parseArgs(-- config) = (%+v, %v), want literal config target", options, err)
	}
}
