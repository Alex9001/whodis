package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Alex9001/whodis"
)

const formatEnvironmentVariable = "WHODIS_FORMAT"

var errConfigDirectoryUnavailable = errors.New("user configuration directory unavailable")

type savedConfigError struct {
	err error
}

func (err *savedConfigError) Error() string { return err.err.Error() }
func (err *savedConfigError) Unwrap() error { return err.err }

type cliRuntime struct {
	stdin           io.Reader
	getenv          func(string) string
	userConfigDir   func() (string, error)
	isTerminal      func(io.Writer) bool
	stdinIsTerminal func() bool
}

// userConfig contains only presentation defaults. Empty format and color mean
// automatic selection; a nil Details value means the renderer's compact
// default. The pointer preserves a deliberate saved summary preference.
type userConfig struct {
	Format  string `json:"format,omitempty"`
	Color   string `json:"color,omitempty"`
	Details *bool  `json:"details,omitempty"`
}

func defaultCLIRuntime() cliRuntime {
	return cliRuntime{
		stdin:           os.Stdin,
		getenv:          os.Getenv,
		userConfigDir:   os.UserConfigDir,
		isTerminal:      writerIsTerminal,
		stdinIsTerminal: standardInputIsTerminal,
	}
}

func configFilePath(runtime cliRuntime) (string, error) {
	base, err := runtime.userConfigDir()
	if err != nil {
		return "", fmt.Errorf("%w: %v", errConfigDirectoryUnavailable, err)
	}
	if strings.TrimSpace(base) == "" {
		return "", fmt.Errorf("%w: path is empty", errConfigDirectoryUnavailable)
	}
	return filepath.Join(base, "whodis", "config.json"), nil
}

func loadUserConfig(runtime cliRuntime) (userConfig, bool, error) {
	path, err := configFilePath(runtime)
	if err != nil {
		return userConfig{}, false, err
	}
	payload, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return userConfig{}, false, nil
	}
	if err != nil {
		return userConfig{}, false, fmt.Errorf("could not read config %s: %w", path, err)
	}

	var config *userConfig
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&config); err != nil {
		return userConfig{}, false, fmt.Errorf("could not parse config %s: %w", path, err)
	}
	if config == nil {
		return userConfig{}, false, fmt.Errorf("could not parse config %s: expected a JSON object", path)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return userConfig{}, false, fmt.Errorf("could not parse config %s: %w", path, err)
	}
	return *config, true, nil
}

func loadOptionalUserConfig(runtime cliRuntime) (userConfig, bool, error) {
	config, exists, err := loadUserConfig(runtime)
	if errors.Is(err, errConfigDirectoryUnavailable) {
		return userConfig{}, false, nil
	}
	return config, exists, err
}

func saveUserConfig(runtime cliRuntime, config userConfig) error {
	path, err := configFilePath(runtime)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("could not create config directory %s: %w", directory, err)
	}
	payload, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("could not encode config: %w", err)
	}
	payload = append(payload, '\n')

	temporary, err := os.CreateTemp(directory, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("could not create temporary config in %s: %w", directory, err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("could not secure temporary config %s: %w", temporaryPath, err)
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("could not write temporary config %s: %w", temporaryPath, err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("could not sync temporary config %s: %w", temporaryPath, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("could not close temporary config %s: %w", temporaryPath, err)
	}
	if err := replaceConfigFile(temporaryPath, path); err != nil {
		return fmt.Errorf("could not replace config %s: %w", path, err)
	}
	removeTemporary = false
	return nil
}

func removeUserConfig(runtime cliRuntime) error {
	path, err := configFilePath(runtime)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("could not remove config %s: %w", path, err)
	}
	return nil
}

func configIsEmpty(config userConfig) bool {
	return strings.TrimSpace(config.Format) == "" && strings.TrimSpace(config.Color) == "" && config.Details == nil
}

func configsEqual(left, right userConfig) bool {
	if left.Format != right.Format || left.Color != right.Color {
		return false
	}
	if left.Details == nil || right.Details == nil {
		return left.Details == nil && right.Details == nil
	}
	return *left.Details == *right.Details
}

func saveOrRemoveUserConfig(runtime cliRuntime, config userConfig) error {
	if configIsEmpty(config) {
		return removeUserConfig(runtime)
	}
	return saveUserConfig(runtime, config)
}

func parsePersistentFormat(value string) (whodis.Format, string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "auto") {
		return "", "auto", nil
	}
	format, err := whodis.ParseFormat(value)
	if err != nil {
		return "", "", fmt.Errorf("%w; choose auto, dashboard, tree, geekboys, or plain", err)
	}
	switch format {
	case whodis.FormatPretty:
		return format, "dashboard", nil
	case whodis.FormatTree:
		return format, "tree", nil
	case whodis.FormatGeekBoys:
		return format, "geekboys", nil
	case whodis.FormatPlain:
		return format, "plain", nil
	default:
		return "", "", fmt.Errorf("format %q cannot be saved; choose auto, dashboard, tree, geekboys, or plain", value)
	}
}

func parsePersistentColor(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto":
		return "auto", nil
	case "always", "never":
		return strings.ToLower(strings.TrimSpace(value)), nil
	default:
		return "", fmt.Errorf("color %q cannot be saved; choose auto, always, or never", value)
	}
}

func parsePersistentDetails(value string) (*bool, string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto":
		return nil, "auto", nil
	case "summary", "false", "off":
		choice := false
		return &choice, "summary", nil
	case "expanded", "true", "on":
		choice := true
		return &choice, "expanded", nil
	default:
		return nil, "", fmt.Errorf("details %q cannot be saved; choose auto, summary, or expanded", value)
	}
}

func persistentDetailsValue(value *bool) string {
	if value == nil {
		return "auto"
	}
	if *value {
		return "expanded"
	}
	return "summary"
}

func validateUserConfig(config userConfig) error {
	if _, _, err := parsePersistentFormat(config.Format); err != nil {
		return err
	}
	if _, err := parsePersistentColor(config.Color); err != nil {
		return err
	}
	return nil
}

func canonicalUserConfig(config userConfig) (userConfig, error) {
	_, format, err := parsePersistentFormat(config.Format)
	if err != nil {
		return userConfig{}, err
	}
	color, err := parsePersistentColor(config.Color)
	if err != nil {
		return userConfig{}, err
	}
	canonical := userConfig{Details: config.Details}
	if format != "auto" {
		canonical.Format = format
	}
	if color != "auto" {
		canonical.Color = color
	}
	return canonical, nil
}

func modifyUserConfig(runtime cliRuntime, modify func(*userConfig) error) error {
	config, exists, err := loadUserConfig(runtime)
	if err != nil {
		return err
	}
	if !exists {
		config = userConfig{}
	}
	if err := validateUserConfig(config); err != nil {
		return err
	}
	if err := modify(&config); err != nil {
		return err
	}
	config, err = canonicalUserConfig(config)
	if err != nil {
		return err
	}
	return saveOrRemoveUserConfig(runtime, config)
}

func configValue(config userConfig, key string) (string, error) {
	switch key {
	case "format":
		_, value, err := parsePersistentFormat(config.Format)
		return value, err
	case "color":
		return parsePersistentColor(config.Color)
	case "details":
		return persistentDetailsValue(config.Details), nil
	default:
		return "", fmt.Errorf("unknown preference %q", key)
	}
}

func setConfigValue(config *userConfig, key, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s requires a value", key)
	}
	switch key {
	case "format":
		_, canonical, err := parsePersistentFormat(value)
		if err != nil {
			return err
		}
		if canonical == "auto" {
			config.Format = ""
		} else {
			config.Format = canonical
		}
		return nil
	case "color":
		canonical, err := parsePersistentColor(value)
		if err != nil {
			return err
		}
		if canonical == "auto" {
			config.Color = ""
		} else {
			config.Color = canonical
		}
		return nil
	case "details":
		choice, _, err := parsePersistentDetails(value)
		if err != nil {
			return err
		}
		config.Details = choice
		return nil
	default:
		return fmt.Errorf("unknown preference %q; choose format, color, or details", key)
	}
}

func unsetConfigValue(config *userConfig, key string) error {
	switch key {
	case "format":
		config.Format = ""
	case "color":
		config.Color = ""
	case "details":
		config.Details = nil
	default:
		return fmt.Errorf("unknown preference %q; choose format, color, or details", key)
	}
	return nil
}

type wizardChoice struct {
	value       string
	label       string
	description string
}

func runConfig(args []string, stdout, stderr io.Writer, runtime cliRuntime) int {
	if len(args) == 0 || (len(args) == 1 && args[0] == "wizard") {
		return runConfigWizard(stdout, stderr, runtime)
	}

	switch args[0] {
	case "-h", "--help", "help":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "whodis: config help accepts no arguments")
			return 2
		}
		printConfigUsage(stdout)
		return 0
	case "path":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "whodis: config path accepts no arguments")
			return 2
		}
		path, err := configFilePath(runtime)
		if err != nil {
			fmt.Fprintln(stderr, "whodis:", err)
			return 1
		}
		fmt.Fprintln(stdout, path)
		return 0
	case "reset":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "whodis: config reset accepts no arguments")
			return 2
		}
		if err := removeUserConfig(runtime); err != nil {
			fmt.Fprintln(stderr, "whodis:", err)
			return 1
		}
		return 0
	case "get":
		if len(args) != 2 {
			fmt.Fprintln(stderr, "whodis: usage: whodis config get format|color|details")
			return 2
		}
		config, exists, err := loadUserConfig(runtime)
		if err != nil {
			fmt.Fprintln(stderr, "whodis:", err)
			return 1
		}
		if !exists {
			config = userConfig{}
		}
		if err := validateUserConfig(config); err != nil {
			printConfigValidationError(stderr, runtime, err)
			return 1
		}
		value, err := configValue(config, args[1])
		if err != nil {
			fmt.Fprintln(stderr, "whodis:", err)
			return 2
		}
		fmt.Fprintln(stdout, value)
		return 0
	case "set":
		if len(args) != 3 {
			fmt.Fprintln(stderr, "whodis: usage: whodis config set format|color|details <value>")
			return 2
		}
		if err := setConfigValue(&userConfig{}, args[1], args[2]); err != nil {
			fmt.Fprintln(stderr, "whodis:", err)
			return 2
		}
		if err := modifyUserConfig(runtime, func(config *userConfig) error {
			return setConfigValue(config, args[1], args[2])
		}); err != nil {
			printConfigMutationError(stderr, runtime, err)
			return 1
		}
		return 0
	case "unset":
		if len(args) != 2 {
			fmt.Fprintln(stderr, "whodis: usage: whodis config unset format|color|details")
			return 2
		}
		if err := unsetConfigValue(&userConfig{}, args[1]); err != nil {
			fmt.Fprintln(stderr, "whodis:", err)
			return 2
		}
		if err := modifyUserConfig(runtime, func(config *userConfig) error {
			return unsetConfigValue(config, args[1])
		}); err != nil {
			printConfigMutationError(stderr, runtime, err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "whodis: unknown config command %q\n", args[0])
		printConfigUsage(stderr)
		return 2
	}
}

func printConfigValidationError(stderr io.Writer, runtime cliRuntime, err error) {
	path, pathErr := configFilePath(runtime)
	if pathErr != nil {
		fmt.Fprintln(stderr, "whodis:", pathErr)
		return
	}
	fmt.Fprintf(stderr, "whodis: invalid preference in config %s: %v\n", path, err)
}

func printConfigMutationError(stderr io.Writer, runtime cliRuntime, err error) {
	if errors.Is(err, errConfigDirectoryUnavailable) {
		fmt.Fprintln(stderr, "whodis:", err)
		return
	}
	path, pathErr := configFilePath(runtime)
	if pathErr == nil && strings.Contains(err.Error(), "cannot be saved") {
		fmt.Fprintf(stderr, "whodis: invalid preference in config %s: %v\n", path, err)
		return
	}
	fmt.Fprintln(stderr, "whodis:", err)
}

func runConfigWizard(stdout, stderr io.Writer, runtime cliRuntime) int {
	if runtime.stdin == nil || runtime.stdinIsTerminal == nil || !runtime.stdinIsTerminal() || !runtime.isTerminal(stdout) {
		fmt.Fprintln(stderr, `whodis: interactive config requires a terminal; use "whodis config set ..." in scripts`)
		return 2
	}
	path, err := configFilePath(runtime)
	if err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 1
	}
	config, exists, err := loadUserConfig(runtime)
	if err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 1
	}
	if !exists {
		config = userConfig{}
	}
	if err := validateUserConfig(config); err != nil {
		printConfigValidationError(stderr, runtime, err)
		return 1
	}

	_, format, _ := parsePersistentFormat(config.Format)
	color, _ := parsePersistentColor(config.Color)
	details := persistentDetailsValue(config.Details)
	scanner := bufio.NewScanner(runtime.stdin)

	fmt.Fprintln(stdout, "Whodis preferences")
	fmt.Fprintln(stdout, "Enter a number, press Enter to keep the current choice, or type q to cancel.")

	format, cancelled, err := promptWizardChoice(scanner, stdout, 1, 3, "Output format", format, []wizardChoice{
		{value: "auto", label: "Auto", description: "dashboard in a terminal; plain text when piped or redirected"},
		{value: "dashboard", label: "Dashboard", description: "responsive panel grid that adapts to terminal width"},
		{value: "tree", label: "Tree", description: "hierarchical view for scanning relationships"},
		{value: "geekboys", label: "GeekBoys", description: "headerless retro ASCII layout; never emits ANSI color"},
		{value: "plain", label: "Plain", description: "simple label/value text for logs and pipelines"},
	})
	if wizardCancelledOrFailed(cancelled, err, stdout, stderr) {
		return wizardExitCode(err)
	}

	color, cancelled, err = promptWizardChoice(scanner, stdout, 2, 3, "Color", color, []wizardChoice{
		{value: "auto", label: "Auto", description: "use color only on a capable terminal; respect NO_COLOR"},
		{value: "always", label: "Always", description: "force ANSI color in dashboard and tree output"},
		{value: "never", label: "Never", description: "never emit ANSI color"},
	})
	if wizardCancelledOrFailed(cancelled, err, stdout, stderr) {
		return wizardExitCode(err)
	}

	details, cancelled, err = promptWizardChoice(scanner, stdout, 3, 3, "Registry notices", details, []wizardChoice{
		{value: "auto", label: "Auto", description: "use the compact summary behavior built into visual formats"},
		{value: "summary", label: "Summary", description: "always show only the deduplicated notice count"},
		{value: "expanded", label: "Expanded", description: "show deduplicated titles, descriptions, and links"},
	})
	if wizardCancelledOrFailed(cancelled, err, stdout, stderr) {
		return wizardExitCode(err)
	}

	draft := config
	if err := setConfigValue(&draft, "format", format); err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 1
	}
	if err := setConfigValue(&draft, "color", color); err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 1
	}
	if err := setConfigValue(&draft, "details", details); err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 1
	}
	draft, err = canonicalUserConfig(draft)
	if err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 1
	}

	fmt.Fprintln(stdout, "\nReview")
	fmt.Fprintf(stdout, "  Format : %s\n", wizardDisplayValue(format))
	fmt.Fprintf(stdout, "  Color  : %s\n", wizardDisplayValue(color))
	fmt.Fprintf(stdout, "  Notices: %s\n", wizardDisplayValue(details))
	fmt.Fprintf(stdout, "  File   : %s\n", path)
	confirmed, cancelled, err := promptWizardConfirmation(scanner, stdout)
	if wizardCancelledOrFailed(cancelled, err, stdout, stderr) {
		return wizardExitCode(err)
	}
	if !confirmed {
		fmt.Fprintln(stdout, "Cancelled; no changes were saved.")
		return 0
	}
	if configsEqual(config, draft) {
		if !exists {
			fmt.Fprintln(stdout, "No changes needed; Whodis is already using automatic defaults.")
			return 0
		}
		fmt.Fprintf(stdout, "No changes needed; preferences are already saved in %s.\n", path)
		return 0
	}
	if err := saveOrRemoveUserConfig(runtime, draft); err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 1
	}
	if configIsEmpty(draft) {
		fmt.Fprintln(stdout, "Saved preferences; Whodis is using automatic defaults.")
		return 0
	}
	fmt.Fprintf(stdout, "Saved preferences to %s. Command-line options still override these defaults.\n", path)
	return 0
}

func promptWizardChoice(scanner *bufio.Scanner, stdout io.Writer, step, total int, title, current string, choices []wizardChoice) (string, bool, error) {
	currentIndex := 1
	for index, choice := range choices {
		if choice.value == current {
			currentIndex = index + 1
			break
		}
	}
	fmt.Fprintf(stdout, "\n%d/%d  %s (current: %s)\n", step, total, title, wizardDisplayValue(current))
	for index, choice := range choices {
		fmt.Fprintf(stdout, "  %d. %-10s %s\n", index+1, choice.label, choice.description)
	}
	for {
		fmt.Fprintf(stdout, "Select [%d]: ", currentIndex)
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return "", false, err
			}
			return "", true, nil
		}
		answer := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if answer == "" {
			return current, false, nil
		}
		if answer == "0" || answer == "q" || answer == "quit" {
			return "", true, nil
		}
		for index, choice := range choices {
			if answer == fmt.Sprint(index+1) {
				return choice.value, false, nil
			}
		}
		fmt.Fprintf(stdout, "Please enter 1-%d, press Enter, or q to cancel.\n", len(choices))
	}
}

func promptWizardConfirmation(scanner *bufio.Scanner, stdout io.Writer) (bool, bool, error) {
	for {
		fmt.Fprint(stdout, "Save these preferences? [Y/n]: ")
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return false, false, err
			}
			return false, true, nil
		}
		switch strings.ToLower(strings.TrimSpace(scanner.Text())) {
		case "", "y", "yes":
			return true, false, nil
		case "n", "no", "q", "quit":
			return false, false, nil
		default:
			fmt.Fprintln(stdout, "Please enter y or n.")
		}
	}
}

func wizardCancelledOrFailed(cancelled bool, err error, stdout, stderr io.Writer) bool {
	if err != nil {
		fmt.Fprintln(stderr, "whodis: could not read setup input:", err)
		return true
	}
	if cancelled {
		fmt.Fprintln(stdout, "Cancelled; no changes were saved.")
		return true
	}
	return false
}

func wizardExitCode(err error) int {
	if err != nil {
		return 1
	}
	return 0
}

func wizardDisplayValue(value string) string {
	if value == "auto" {
		return "auto"
	}
	return value
}

func printConfigUsage(writer io.Writer) {
	fmt.Fprint(writer, `Usage:
  whodis config
  whodis config wizard
  whodis config set format auto|dashboard|tree|geekboys|plain
  whodis config set color auto|always|never
  whodis config set details auto|summary|expanded
  whodis config get format|color|details
  whodis config unset format|color|details
  whodis config reset
  whodis config path
`)
}
