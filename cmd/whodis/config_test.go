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
		stdin: strings.NewReader(""),
		getenv: func(name string) string {
			return environment[name]
		},
		userConfigDir: func() (string, error) {
			return directory, nil
		},
		isTerminal: func(io.Writer) bool {
			return terminal
		},
		stdinIsTerminal: func() bool { return terminal },
	}
}

func wizardRuntime(directory, input string) cliRuntime {
	runtime := testRuntime(directory, nil, true)
	runtime.stdin = strings.NewReader(input)
	return runtime
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

func boolPointer(value bool) *bool { return &value }

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

func TestConfigPreferencesPreserveEachOtherAndReset(t *testing.T) {
	directory := t.TempDir()
	runtime := testRuntime(directory, nil, false)
	for _, args := range [][]string{
		{"config", "set", "format", "tree"},
		{"config", "set", "color", "never"},
		{"config", "set", "details", "expanded"},
	} {
		code, stdout, stderr := runCLIForTest(t, runtime, args...)
		if code != 0 || stdout != "" || stderr != "" {
			t.Fatalf("run(%v) = (%d, %q, %q), want success", args, code, stdout, stderr)
		}
	}
	for key, want := range map[string]string{"format": "tree\n", "color": "never\n", "details": "expanded\n"} {
		code, stdout, stderr := runCLIForTest(t, runtime, "config", "get", key)
		if code != 0 || stdout != want || stderr != "" {
			t.Fatalf("get %s = (%d, %q, %q), want %q", key, code, stdout, stderr, want)
		}
	}

	code, _, stderr := runCLIForTest(t, runtime, "config", "unset", "color")
	if code != 0 || stderr != "" {
		t.Fatalf("unset color = (%d, %q), want success", code, stderr)
	}
	config, exists, err := loadUserConfig(runtime)
	if err != nil || !exists || config.Format != "tree" || config.Color != "" || config.Details == nil || !*config.Details {
		t.Fatalf("config after unset color = (%+v, %v, %v), want tree/expanded only", config, exists, err)
	}

	for _, args := range [][]string{
		{"config", "set", "format", "auto"},
		{"config", "set", "details", "auto"},
	} {
		code, _, stderr = runCLIForTest(t, runtime, args...)
		if code != 0 || stderr != "" {
			t.Fatalf("run(%v) = (%d, %q), want success", args, code, stderr)
		}
	}
	if _, exists, err := loadUserConfig(runtime); err != nil || exists {
		t.Fatalf("config after clearing every preference = (exists=%v, err=%v), want absent", exists, err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		code, _, stderr = runCLIForTest(t, runtime, "config", "reset")
		if code != 0 || stderr != "" {
			t.Fatalf("reset attempt %d = (%d, %q), want success", attempt, code, stderr)
		}
	}
}

func TestConfigAcceptsLegacyFormatAndDetailsAliases(t *testing.T) {
	directory := t.TempDir()
	runtime := testRuntime(directory, nil, false)
	writeConfigForTest(t, directory, `{"format":"tree"}`)
	for _, test := range []struct {
		value string
		want  string
	}{
		{value: "expanded", want: "expanded"},
		{value: "off", want: "summary"},
		{value: "on", want: "expanded"},
		{value: "auto", want: "auto"},
	} {
		code, _, stderr := runCLIForTest(t, runtime, "config", "set", "details", test.value)
		if code != 0 || stderr != "" {
			t.Fatalf("set details %q = (%d, %q), want success", test.value, code, stderr)
		}
		code, stdout, stderr := runCLIForTest(t, runtime, "config", "get", "details")
		if code != 0 || stdout != test.want+"\n" || stderr != "" {
			t.Fatalf("get details after %q = (%d, %q, %q), want %q", test.value, code, stdout, stderr, test.want)
		}
	}
	code, _, stderr := runCLIForTest(t, runtime, "config", "set", "color", "always")
	if code != 0 || stderr != "" {
		t.Fatalf("set color = (%d, %q), want success", code, stderr)
	}
	config, exists, err := loadUserConfig(runtime)
	if err != nil || !exists || config.Format != "tree" || config.Color != "always" {
		t.Fatalf("legacy config was not preserved: (%+v, %v, %v)", config, exists, err)
	}
}

func TestConfigWizardSavesAllPreferences(t *testing.T) {
	directory := t.TempDir()
	code, stdout, stderr := runCLIForTest(t, wizardRuntime(directory, "3\n2\n3\n2\n4\n2\ny\n"), "config")
	if code != 0 || stderr != "" {
		t.Fatalf("wizard = (%d, %q, %q), want success", code, stdout, stderr)
	}
	for _, text := range []string{"Whodis preferences", "1/6  Output format", "2/6  Color", "3/6  Registry notices", "4/6  Default DNS resolver", "5/6  Multiple resolver behavior", "6/6  DNSSEC requests", "Review", "Saved preferences to"} {
		if !strings.Contains(stdout, text) {
			t.Errorf("wizard output missing %q:\n%s", text, stdout)
		}
	}
	config, exists, err := loadUserConfig(testRuntime(directory, nil, false))
	if err != nil || !exists || config.Format != "tree" || config.Color != "always" || config.Details == nil || !*config.Details || resolverPreset(config.DNSResolvers) != "cloudflare" || config.ResolverStrategy != "consensus" || config.DNSSEC == nil || !*config.DNSSEC {
		t.Fatalf("wizard config = (%+v, %v, %v), want tree/always/expanded", config, exists, err)
	}
}

func TestConfigWizardRetriesInvalidSelection(t *testing.T) {
	directory := t.TempDir()
	code, stdout, stderr := runCLIForTest(t, wizardRuntime(directory, "9\n2\n1\n2\n1\n1\n1\ny\n"), "config")
	if code != 0 || stderr != "" || !strings.Contains(stdout, "Please enter 1-5") {
		t.Fatalf("wizard retry = (%d, %q, %q), want successful retry", code, stdout, stderr)
	}
	config, exists, err := loadUserConfig(testRuntime(directory, nil, false))
	if err != nil || !exists || config.Format != "dashboard" || config.Color != "" || config.Details == nil || *config.Details {
		t.Fatalf("wizard retry config = (%+v, %v, %v), want dashboard/auto/summary", config, exists, err)
	}
}

func TestConfigWizardCancellationAndNoChangeAreSafe(t *testing.T) {
	directory := t.TempDir()
	runtime := testRuntime(directory, nil, false)
	if err := saveUserConfig(runtime, userConfig{Format: "tree", Color: "never", Details: boolPointer(false)}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "whodis", "config.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	for name, input := range map[string]string{
		"declined confirmation": "\n\n\n\n\n\nn\n",
		"quit at prompt":        "q\n",
		"EOF":                   "",
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runCLIForTest(t, wizardRuntime(directory, input), "config", "wizard")
			if code != 0 || stderr != "" || !strings.Contains(stdout, "Cancelled; no changes were saved.") {
				t.Fatalf("wizard %s = (%d, %q, %q), want safe cancellation", name, code, stdout, stderr)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("wizard %s changed config: before=%q after=%q err=%v", name, before, after, err)
			}
		})
	}

	code, stdout, stderr := runCLIForTest(t, wizardRuntime(directory, "\n\n\n\n\n\ny\n"), "config")
	if code != 0 || stderr != "" || !strings.Contains(stdout, "No changes needed") {
		t.Fatalf("unchanged wizard = (%d, %q, %q), want no-op", code, stdout, stderr)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("no-op wizard changed config: before=%q after=%q err=%v", before, after, err)
	}
}

func TestConfigWizardRejectsNonTerminalAndMalformedConfig(t *testing.T) {
	directory := t.TempDir()
	code, stdout, stderr := runCLIForTest(t, testRuntime(directory, nil, false), "config")
	if code != 2 || stdout != "" || !strings.Contains(stderr, "interactive config requires a terminal") {
		t.Fatalf("non-terminal wizard = (%d, %q, %q), want terminal error", code, stdout, stderr)
	}
	path := writeConfigForTest(t, directory, "{")
	code, stdout, stderr = runCLIForTest(t, wizardRuntime(directory, ""), "config")
	if code != 1 || stdout != "" || !strings.Contains(stderr, path) {
		t.Fatalf("malformed wizard = (%d, %q, %q), want actionable error", code, stdout, stderr)
	}
	code, stdout, stderr = runCLIForTest(t, testRuntime(directory, nil, false), "config", "reset")
	if code != 0 || stdout != "" || stderr != "" {
		t.Fatalf("reset malformed config = (%d, %q, %q), want success", code, stdout, stderr)
	}
}

func TestChoosePresentationPrecedenceAndLazyConfig(t *testing.T) {
	directory := t.TempDir()
	runtime := testRuntime(directory, nil, false)
	if err := saveUserConfig(runtime, userConfig{Color: "always", Details: boolPointer(true)}); err != nil {
		t.Fatal(err)
	}
	color, details, err := choosePresentation(cliOptions{}, whodis.FormatTree, runtime)
	if err != nil || color != "always" || !details {
		t.Fatalf("saved presentation = (%q, %v, %v), want always/expanded", color, details, err)
	}
	color, details, err = choosePresentation(cliOptions{color: "never", colorSet: true, details: false, detailsSet: true}, whodis.FormatTree, runtime)
	if err != nil || color != "never" || details {
		t.Fatalf("explicit presentation = (%q, %v, %v), want never/summary", color, details, err)
	}

	writeConfigForTest(t, directory, `{"color":"invalid","details":true}`)
	color, details, err = choosePresentation(cliOptions{}, whodis.FormatGeekBoys, runtime)
	if err != nil || color != "auto" || !details {
		t.Fatalf("GeekBoys should ignore saved color = (%q, %v, %v)", color, details, err)
	}
	if _, _, err := choosePresentation(cliOptions{}, whodis.FormatTree, runtime); err == nil || !strings.Contains(err.Error(), "color") {
		t.Fatalf("tree should report invalid saved color, got %v", err)
	}
	writeConfigForTest(t, directory, "{")
	color, details, err = choosePresentation(cliOptions{}, whodis.FormatJSON, runtime)
	if err != nil || color != "auto" || details {
		t.Fatalf("machine output should bypass malformed display config = (%q, %v, %v)", color, details, err)
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
			message := "dashboard, tree, geekboys, or plain"
			if format == "" {
				message = "format requires a value"
			}
			if code != 2 || stdout != "" || !strings.Contains(stderr, message) {
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
		{args: []string{"config"}, message: "interactive config requires a terminal"},
		{args: []string{"config", "unknown"}, message: "unknown config command"},
		{args: []string{"config", "get", "other"}, message: "unknown preference"},
		{args: []string{"config", "set", "format"}, message: "config set format"},
		{args: []string{"config", "unset", "other"}, message: "unknown preference"},
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
