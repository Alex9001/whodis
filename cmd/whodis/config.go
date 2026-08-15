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

	"github.com/Alex9001/whodis/v2"
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
	Format           string   `json:"format,omitempty"`
	Color            string   `json:"color,omitempty"`
	Details          *bool    `json:"details,omitempty"`
	DNSResolvers     []string `json:"dns_resolvers,omitempty"`
	ResolverStrategy string   `json:"resolver_strategy,omitempty"`
	DNSSEC           *bool    `json:"dnssec,omitempty"`
	Scrutiny         string   `json:"scrutiny,omitempty"`
	CheckActive      *bool    `json:"check_active,omitempty"`
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
	payload, err := os.ReadFile(path) // #nosec G304 -- path is derived from the OS user config directory and a fixed suffix.
	if errors.Is(err, os.ErrNotExist) {
		return userConfig{}, false, nil
	}
	if err != nil {
		return userConfig{}, false, fmt.Errorf("could not read config %s: %w", path, err)
	}

	var config *userConfig
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
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
	return strings.TrimSpace(config.Format) == "" && strings.TrimSpace(config.Color) == "" && config.Details == nil && len(config.DNSResolvers) == 0 && strings.TrimSpace(config.ResolverStrategy) == "" && config.DNSSEC == nil && strings.TrimSpace(config.Scrutiny) == "" && config.CheckActive == nil
}

func configsEqual(left, right userConfig) bool {
	if left.Format != right.Format || left.Color != right.Color || left.ResolverStrategy != right.ResolverStrategy || left.Scrutiny != right.Scrutiny || strings.Join(left.DNSResolvers, "\x00") != strings.Join(right.DNSResolvers, "\x00") {
		return false
	}
	if !equalOptionalBool(left.Details, right.Details) || !equalOptionalBool(left.DNSSEC, right.DNSSEC) || !equalOptionalBool(left.CheckActive, right.CheckActive) {
		return false
	}
	return true
}

func equalOptionalBool(left, right *bool) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
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
	if _, err := parsePersistentResolverStrategy(config.ResolverStrategy); err != nil {
		return err
	}
	if _, err := parsePersistentScrutiny(config.Scrutiny); err != nil {
		return err
	}
	if len(config.DNSResolvers) > 0 {
		if err := whodis.ValidateDNSOptions(whodis.DNSOptions{Resolvers: config.DNSResolvers}); err != nil {
			return err
		}
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
	strategy, err := parsePersistentResolverStrategy(config.ResolverStrategy)
	if err != nil {
		return userConfig{}, err
	}
	canonical := userConfig{Details: config.Details, DNSResolvers: append([]string(nil), config.DNSResolvers...), DNSSEC: config.DNSSEC, CheckActive: config.CheckActive}
	if format != "auto" {
		canonical.Format = format
	}
	if color != "auto" {
		canonical.Color = color
	}
	if strategy != "first" {
		canonical.ResolverStrategy = strategy
	}
	scrutiny, err := parsePersistentScrutiny(config.Scrutiny)
	if err != nil {
		return userConfig{}, err
	}
	if scrutiny != "standard" {
		canonical.Scrutiny = scrutiny
	}
	return canonical, nil
}

func parsePersistentScrutiny(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || value == "auto" || value == "standard" {
		return "standard", nil
	}
	if value == "basic" || value == "strict" {
		return value, nil
	}
	return "", fmt.Errorf("scrutiny %q cannot be saved; choose basic, standard, or strict", value)
}

func persistentCheckMode(value *bool) string {
	if value != nil && *value {
		return "active"
	}
	return "passive"
}

func parsePersistentResolverStrategy(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || value == "auto" {
		return "first", nil
	}
	switch whodis.ResolverStrategy(value) {
	case whodis.ResolverFirst, whodis.ResolverAll, whodis.ResolverFastest, whodis.ResolverRandom, whodis.ResolverConsensus:
		return value, nil
	default:
		return "", fmt.Errorf("resolver strategy %q cannot be saved; choose first, all, fastest, random, or consensus", value)
	}
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
	case "resolver":
		if len(config.DNSResolvers) == 0 {
			return "system", nil
		}
		return strings.Join(config.DNSResolvers, ","), nil
	case "strategy":
		return parsePersistentResolverStrategy(config.ResolverStrategy)
	case "dnssec":
		return persistentOptionalBool(config.DNSSEC), nil
	case "scrutiny":
		return parsePersistentScrutiny(config.Scrutiny)
	case "check-mode":
		return persistentCheckMode(config.CheckActive), nil
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
	case "resolver":
		if strings.EqualFold(strings.TrimSpace(value), "system") || strings.EqualFold(strings.TrimSpace(value), "auto") {
			config.DNSResolvers = nil
			return nil
		}
		var resolvers []string
		for _, resolver := range strings.Split(value, ",") {
			if strings.TrimSpace(resolver) != "" {
				resolvers = append(resolvers, strings.TrimSpace(resolver))
			}
		}
		if err := whodis.ValidateDNSOptions(whodis.DNSOptions{Resolvers: resolvers}); err != nil {
			return err
		}
		config.DNSResolvers = resolvers
		return nil
	case "strategy":
		strategy, err := parsePersistentResolverStrategy(value)
		if err != nil {
			return err
		}
		if strategy == "first" {
			config.ResolverStrategy = ""
		} else {
			config.ResolverStrategy = strategy
		}
		return nil
	case "dnssec":
		choice, err := parseOptionalBool(value)
		if err != nil {
			return err
		}
		config.DNSSEC = choice
		return nil
	case "scrutiny":
		scrutiny, err := parsePersistentScrutiny(value)
		if err != nil {
			return err
		}
		if scrutiny == "standard" {
			config.Scrutiny = ""
		} else {
			config.Scrutiny = scrutiny
		}
		return nil
	case "check-mode":
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "passive":
			config.CheckActive = nil
		case "active":
			choice := true
			config.CheckActive = &choice
		default:
			return fmt.Errorf("check-mode must be passive or active")
		}
		return nil
	default:
		return fmt.Errorf("unknown preference %q; choose format, color, details, resolver, strategy, dnssec, scrutiny, or check-mode", key)
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
	case "resolver":
		config.DNSResolvers = nil
	case "strategy":
		config.ResolverStrategy = ""
	case "dnssec":
		config.DNSSEC = nil
	case "scrutiny":
		config.Scrutiny = ""
	case "check-mode":
		config.CheckActive = nil
	default:
		return fmt.Errorf("unknown preference %q; choose format, color, details, resolver, strategy, dnssec, scrutiny, or check-mode", key)
	}
	return nil
}

func parseOptionalBool(value string) (*bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto":
		return nil, nil
	case "on", "true", "yes":
		choice := true
		return &choice, nil
	case "off", "false", "no":
		choice := false
		return &choice, nil
	default:
		return nil, fmt.Errorf("value %q must be auto, on, or off", value)
	}
}

func persistentOptionalBool(value *bool) string {
	if value == nil {
		return "auto"
	}
	if *value {
		return "on"
	}
	return "off"
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
			fmt.Fprintln(stderr, "whodis: usage: whodis config get format|color|details|resolver|strategy|dnssec|scrutiny|check-mode")
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
			fmt.Fprintln(stderr, "whodis: usage: whodis config set format|color|details|resolver|strategy|dnssec|scrutiny|check-mode <value>")
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
			fmt.Fprintln(stderr, "whodis: usage: whodis config unset format|color|details|resolver|strategy|dnssec|scrutiny|check-mode")
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
	resolver := resolverPreset(config.DNSResolvers)
	strategy, _ := parsePersistentResolverStrategy(config.ResolverStrategy)
	dnssec := persistentOptionalBool(config.DNSSEC)
	scrutiny, _ := parsePersistentScrutiny(config.Scrutiny)
	checkMode := persistentCheckMode(config.CheckActive)
	scanner := bufio.NewScanner(runtime.stdin)

	fmt.Fprintln(stdout, "Whodis preferences")
	fmt.Fprintln(stdout, "Enter a number, press Enter to keep the current choice, or type q to cancel.")

	format, cancelled, err := promptWizardChoice(scanner, stdout, 1, 8, "Output format", format, []wizardChoice{
		{value: "auto", label: "Auto", description: "dashboard in a terminal; plain text when piped or redirected"},
		{value: "dashboard", label: "Dashboard", description: "responsive panel grid that adapts to terminal width"},
		{value: "tree", label: "Tree", description: "hierarchical view for scanning relationships"},
		{value: "geekboys", label: "GeekBoys", description: "headerless retro ASCII layout; never emits ANSI color"},
		{value: "plain", label: "Plain", description: "simple label/value text for logs and pipelines"},
	})
	if wizardCancelledOrFailed(cancelled, err, stdout, stderr) {
		return wizardExitCode(err)
	}

	color, cancelled, err = promptWizardChoice(scanner, stdout, 2, 8, "Color", color, []wizardChoice{
		{value: "auto", label: "Auto", description: "use color only on a capable terminal; respect NO_COLOR"},
		{value: "always", label: "Always", description: "force ANSI color in dashboard and tree output"},
		{value: "never", label: "Never", description: "never emit ANSI color"},
	})
	if wizardCancelledOrFailed(cancelled, err, stdout, stderr) {
		return wizardExitCode(err)
	}

	details, cancelled, err = promptWizardChoice(scanner, stdout, 3, 8, "Registry notices", details, []wizardChoice{
		{value: "auto", label: "Auto", description: "use the compact summary behavior built into visual formats"},
		{value: "summary", label: "Summary", description: "always show only the deduplicated notice count"},
		{value: "expanded", label: "Expanded", description: "show deduplicated titles, descriptions, and links"},
	})
	if wizardCancelledOrFailed(cancelled, err, stdout, stderr) {
		return wizardExitCode(err)
	}

	resolverChoices := []wizardChoice{
		{value: "system", label: "System", description: "use the resolvers configured by the operating system"},
		{value: "cloudflare", label: "Cloudflare", description: "DNS-over-HTTPS through Cloudflare's public resolver"},
		{value: "quad9", label: "Quad9", description: "DNS-over-TLS through Quad9's public resolver"},
		{value: "google", label: "Google", description: "DNS-over-HTTPS through Google's public resolver"},
	}
	if resolver == "custom" {
		resolverChoices = append(resolverChoices, wizardChoice{value: "custom", label: "Custom", description: "keep the resolver URIs already stored in this config"})
	}
	resolver, cancelled, err = promptWizardChoice(scanner, stdout, 4, 8, "Default DNS resolver", resolver, resolverChoices)
	if wizardCancelledOrFailed(cancelled, err, stdout, stderr) {
		return wizardExitCode(err)
	}

	strategy, cancelled, err = promptWizardChoice(scanner, stdout, 5, 8, "Multiple resolver behavior", strategy, []wizardChoice{
		{value: "first", label: "First", description: "stop after the first successful resolver"},
		{value: "all", label: "All", description: "retain every resolver response"},
		{value: "fastest", label: "Fastest", description: "race resolvers and keep the first successful response"},
		{value: "consensus", label: "Consensus", description: "query all resolvers and compare normalized answers"},
	})
	if wizardCancelledOrFailed(cancelled, err, stdout, stderr) {
		return wizardExitCode(err)
	}

	dnssec, cancelled, err = promptWizardChoice(scanner, stdout, 6, 8, "DNSSEC requests", dnssec, []wizardChoice{
		{value: "auto", label: "Auto", description: "use each command's normal DNSSEC behavior"},
		{value: "on", label: "On", description: "request DNSSEC records by default"},
		{value: "off", label: "Off", description: "do not request DNSSEC records by default"},
	})
	if wizardCancelledOrFailed(cancelled, err, stdout, stderr) {
		return wizardExitCode(err)
	}

	scrutiny, cancelled, err = promptWizardChoice(scanner, stdout, 7, 8, "Check scrutiny", scrutiny, []wizardChoice{
		{value: "basic", label: "Basic", description: "fail only clear registration, DNS, or diagnostic problems"},
		{value: "standard", label: "Standard", description: "balanced default with warnings for approaching risks"},
		{value: "strict", label: "Strict", description: "promote warnings such as missing DNSSEC to failures"},
	})
	if wizardCancelledOrFailed(cancelled, err, stdout, stderr) {
		return wizardExitCode(err)
	}

	checkMode, cancelled, err = promptWizardChoice(scanner, stdout, 8, 8, "Default check mode", checkMode, []wizardChoice{
		{value: "passive", label: "Passive", description: "registration and DNS only; safe for routine checks"},
		{value: "active", label: "Active", description: "also probe published web, TLS, mail, and services"},
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
	if resolver != "custom" {
		draft.DNSResolvers = resolverPresetValues(resolver)
	}
	if err := setConfigValue(&draft, "strategy", strategy); err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 1
	}
	if err := setConfigValue(&draft, "dnssec", dnssec); err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 1
	}
	if err := setConfigValue(&draft, "scrutiny", scrutiny); err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 1
	}
	if err := setConfigValue(&draft, "check-mode", checkMode); err != nil {
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
	fmt.Fprintf(stdout, "  Resolver: %s\n", wizardDisplayValue(resolver))
	fmt.Fprintf(stdout, "  Strategy: %s\n", wizardDisplayValue(strategy))
	fmt.Fprintf(stdout, "  DNSSEC  : %s\n", wizardDisplayValue(dnssec))
	fmt.Fprintf(stdout, "  Scrutiny: %s\n", wizardDisplayValue(scrutiny))
	fmt.Fprintf(stdout, "  Check mode: %s\n", wizardDisplayValue(checkMode))
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

func resolverPreset(resolvers []string) string {
	if len(resolvers) == 0 {
		return "system"
	}
	joined := strings.Join(resolvers, "\x00")
	for _, name := range []string{"cloudflare", "quad9", "google"} {
		if joined == strings.Join(resolverPresetValues(name), "\x00") {
			return name
		}
	}
	return "custom"
}

func resolverPresetValues(name string) []string {
	switch name {
	case "cloudflare":
		return []string{"https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query"}
	case "quad9":
		return []string{"tls://dns.quad9.net"}
	case "google":
		return []string{"https://dns.google/dns-query"}
	default:
		return nil
	}
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
  whodis config set resolver system|<URI>[,<URI>...]
  whodis config set strategy first|all|fastest|random|consensus
  whodis config set dnssec auto|on|off
  whodis config set scrutiny basic|standard|strict
  whodis config set check-mode passive|active
  whodis config get format|color|details|resolver|strategy|dnssec|scrutiny|check-mode
  whodis config unset format|color|details|resolver|strategy|dnssec|scrutiny|check-mode
  whodis config reset
  whodis config path
`)
}
