package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/Alex9001/whodis"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

var version = "dev"

type cliOptions struct {
	target           string
	format           string
	formatSet        bool
	output           string
	protocol         whodis.Protocol
	fallback         whodis.FallbackMode
	server           string
	timeout          time.Duration
	refreshBootstrap bool
	dnsMode          whodis.DNSMode
	dnsModeSet       bool
	dnsResolver      string
	axfr             bool
	color            string
	colorSet         bool
	details          bool
	detailsSet       bool
	force            bool
	help             bool
	showVersion      bool
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	return runWithRuntime(args, stdout, stderr, defaultCLIRuntime())
}

func runWithRuntime(args []string, stdout, stderr io.Writer, runtime cliRuntime) int {
	if len(args) > 0 && args[0] == "config" {
		return runConfig(args[1:], stdout, stderr, runtime)
	}
	options, err := parseArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		printUsage(stderr)
		return 2
	}
	if options.help {
		printUsage(stdout)
		return 0
	}
	if options.showVersion {
		fmt.Fprintln(stdout, "whodis", resolvedVersion())
		return 0
	}
	if options.target == "" {
		fmt.Fprintln(stderr, "whodis: a target is required")
		printUsage(stderr)
		return 2
	}
	if options.colorSet {
		color, err := parsePersistentColor(options.color)
		if err != nil {
			fmt.Fprintln(stderr, "whodis: --color must be auto, always, or never")
			return 2
		}
		options.color = color
	}
	format, err := chooseFormat(options, stdout, runtime)
	if err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		var configError *savedConfigError
		if errors.As(err, &configError) {
			return 1
		}
		return 2
	}
	color, details, err := choosePresentation(options, format, runtime)
	if err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		var configError *savedConfigError
		if errors.As(err, &configError) {
			return 1
		}
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()
	client := whodis.NewClient(whodis.ClientOptions{Timeout: options.timeout})
	result, err := client.Lookup(ctx, options.target, whodis.LookupOptions{
		Protocol: options.protocol, Fallback: options.fallback, Server: options.server,
		Timeout: options.timeout, RefreshBootstrap: options.refreshBootstrap,
		DNSMode: options.dnsMode, DNSResolver: options.dnsResolver,
	})
	if err != nil {
		printLookupError(stderr, err, format)
		return exitCode(err)
	}

	writer, closeWriter, err := openOutput(options.output, options.force, stdout)
	if err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 1
	}
	defer closeWriter()
	if err := whodis.Render(writer, result, format, whodis.RenderOptions{Color: color, Details: details}); err != nil {
		fmt.Fprintln(stderr, "whodis: could not render output:", err)
		return 1
	}
	return 0
}

func resolvedVersion() string {
	buildInfo, ok := debug.ReadBuildInfo()
	return resolveVersion(version, buildInfo, ok)
}

func resolveVersion(injected string, buildInfo *debug.BuildInfo, buildInfoOK bool) string {
	if injected = normalizeVersion(injected); isReleaseVersion(injected) {
		return injected
	}
	if buildInfoOK && buildInfo != nil {
		if moduleVersion := normalizeVersion(buildInfo.Main.Version); isReleaseVersion(moduleVersion) {
			return moduleVersion
		}
	}
	return "dev"
}

func normalizeVersion(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 1 && value[0] == 'v' && value[1] >= '0' && value[1] <= '9' {
		return value[1:]
	}
	return value
}

func isReleaseVersion(value string) bool {
	return value != "" && value != "dev" && value != "(devel)"
}

func parseArgs(args []string) (cliOptions, error) {
	options := cliOptions{protocol: whodis.ProtocolAuto, fallback: whodis.FallbackUnavailable, timeout: 15 * time.Second, dnsMode: whodis.DNSAuto, color: "auto"}
	var targets []string
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--" {
			targets = append(targets, args[index+1:]...)
			break
		}
		name, inline, hasInline := strings.Cut(arg, "=")
		value := func() (string, error) {
			if hasInline {
				return inline, nil
			}
			if index+1 >= len(args) {
				return "", fmt.Errorf("%s requires a value", name)
			}
			index++
			return args[index], nil
		}
		switch name {
		case "-h", "--help":
			options.help = true
		case "--version":
			options.showVersion = true
		case "-f", "--format":
			v, err := value()
			if err != nil {
				return options, err
			}
			options.format, options.formatSet = v, true
		case "-o", "--output":
			v, err := value()
			if err != nil {
				return options, err
			}
			options.output = v
		case "--protocol":
			v, err := value()
			if err != nil {
				return options, err
			}
			options.protocol = whodis.Protocol(v)
		case "--fallback":
			v, err := value()
			if err != nil {
				return options, err
			}
			options.fallback = whodis.FallbackMode(v)
		case "--server":
			v, err := value()
			if err != nil {
				return options, err
			}
			options.server = v
		case "--timeout":
			v, err := value()
			if err != nil {
				return options, err
			}
			duration, err := time.ParseDuration(v)
			if err != nil || duration <= 0 {
				return options, fmt.Errorf("--timeout must be a positive duration")
			}
			options.timeout = duration
		case "--color":
			v, err := value()
			if err != nil {
				return options, err
			}
			options.color, options.colorSet = v, true
		case "--refresh-bootstrap":
			options.refreshBootstrap = true
		case "--dns":
			v, err := value()
			if err != nil {
				return options, err
			}
			options.dnsMode, options.dnsModeSet = whodis.DNSMode(strings.ToLower(strings.TrimSpace(v))), true
		case "--resolver":
			v, err := value()
			if err != nil {
				return options, err
			}
			options.dnsResolver = v
		case "--axfr":
			options.axfr = true
		case "--details":
			options.details, options.detailsSet = true, true
		case "--no-details":
			options.details, options.detailsSet = false, true
		case "--force":
			options.force = true
		default:
			if strings.HasPrefix(arg, "-") {
				return options, fmt.Errorf("unknown option %s", arg)
			}
			targets = append(targets, arg)
		}
	}
	if len(targets) > 1 {
		return options, fmt.Errorf("only one target may be queried at a time")
	}
	if len(targets) == 1 {
		options.target = targets[0]
	}
	if options.protocol != whodis.ProtocolAuto && options.protocol != whodis.ProtocolRDAP && options.protocol != whodis.ProtocolWHOIS {
		return options, fmt.Errorf("--protocol must be auto, rdap, or whois")
	}
	if options.fallback != whodis.FallbackUnavailable && options.fallback != whodis.FallbackNone && options.fallback != whodis.FallbackAnyError {
		return options, fmt.Errorf("--fallback must be unavailable, none, or any-error")
	}
	if options.axfr {
		if options.dnsModeSet && options.dnsMode != whodis.DNSAXFR {
			return options, fmt.Errorf("--axfr conflicts with --dns %s; use --dns axfr", options.dnsMode)
		}
		options.dnsMode = whodis.DNSAXFR
	}
	switch options.dnsMode {
	case whodis.DNSAuto, whodis.DNSOff, whodis.DNSScan, whodis.DNSAXFR:
	default:
		return options, fmt.Errorf("--dns must be auto, off, scan, or axfr")
	}
	if options.dnsResolver != "" && options.dnsMode == whodis.DNSOff {
		return options, fmt.Errorf("--resolver cannot be used with --dns off")
	}
	return options, nil
}

func chooseFormat(options cliOptions, stdout io.Writer, runtime cliRuntime) (whodis.Format, error) {
	if options.formatSet {
		return whodis.ParseFormat(options.format)
	}
	if options.output != "" && options.output != "-" {
		extension := strings.TrimPrefix(strings.ToLower(filepath.Ext(options.output)), ".")
		if extension != "" {
			if format, err := whodis.ParseFormat(extension); err == nil {
				return format, nil
			}
		}
		return whodis.FormatPlain, nil
	}
	if value := strings.TrimSpace(runtime.getenv(formatEnvironmentVariable)); value != "" {
		format, err := whodis.ParseFormat(value)
		if err != nil {
			return "", fmt.Errorf("invalid %s value: %w", formatEnvironmentVariable, err)
		}
		return format, nil
	}
	config, exists, err := loadOptionalUserConfig(runtime)
	if err != nil {
		return "", &savedConfigError{err: err}
	}
	if exists && strings.TrimSpace(config.Format) != "" {
		format, canonical, err := parsePersistentFormat(config.Format)
		if err != nil {
			path, pathErr := configFilePath(runtime)
			if pathErr != nil {
				return "", pathErr
			}
			return "", &savedConfigError{err: fmt.Errorf("invalid format in config %s: %w", path, err)}
		}
		if canonical != "auto" {
			return format, nil
		}
	}
	if runtime.isTerminal(stdout) {
		return whodis.FormatPretty, nil
	}
	return whodis.FormatPlain, nil
}

func choosePresentation(options cliOptions, format whodis.Format, runtime cliRuntime) (string, bool, error) {
	color := "auto"
	if options.colorSet {
		color = options.color
	}
	details := false
	if options.detailsSet {
		details = options.details
	}

	usesColor := format == whodis.FormatPretty || format == whodis.FormatTree
	usesDetails := format == whodis.FormatPretty || format == whodis.FormatTree || format == whodis.FormatGeekBoys
	if (!usesColor || options.colorSet) && (!usesDetails || options.detailsSet) {
		return color, details, nil
	}
	config, exists, err := loadOptionalUserConfig(runtime)
	if err != nil {
		return "", false, &savedConfigError{err: err}
	}
	if !exists {
		return color, details, nil
	}
	if usesColor && !options.colorSet && strings.TrimSpace(config.Color) != "" {
		color, err = parsePersistentColor(config.Color)
		if err != nil {
			return "", false, savedPreferenceError(runtime, "color", err)
		}
	}
	if usesDetails && !options.detailsSet && config.Details != nil {
		details = *config.Details
	}
	return color, details, nil
}

func savedPreferenceError(runtime cliRuntime, preference string, err error) error {
	path, pathErr := configFilePath(runtime)
	if pathErr != nil {
		return &savedConfigError{err: pathErr}
	}
	return &savedConfigError{err: fmt.Errorf("invalid %s in config %s: %w", preference, path, err)}
}

func writerIsTerminal(writer io.Writer) bool {
	type fileDescriptor interface {
		Fd() uintptr
	}
	output, ok := writer.(fileDescriptor)
	return ok && term.IsTerminal(int(output.Fd()))
}

func standardInputIsTerminal() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

func openOutput(path string, force bool, stdout io.Writer) (io.Writer, func(), error) {
	if path == "" || path == "-" {
		return stdout, func() {}, nil
	}
	flags := os.O_WRONLY | os.O_CREATE
	if force {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_EXCL
	}
	file, err := os.OpenFile(path, flags, 0o644)
	if err != nil {
		return nil, func() {}, fmt.Errorf("could not open %s: %w", path, err)
	}
	return file, func() { _ = file.Close() }, nil
}

func printLookupError(writer io.Writer, err error, format whodis.Format) {
	var lookup *whodis.LookupError
	if !errors.As(err, &lookup) {
		fmt.Fprintln(writer, "whodis:", err)
		return
	}
	if format == whodis.FormatJSON {
		_ = json.NewEncoder(writer).Encode(map[string]any{"error": map[string]string{"kind": string(lookup.Kind), "message": lookup.Error()}})
		return
	}
	if format == whodis.FormatYAML {
		payload, _ := yaml.Marshal(map[string]any{"error": map[string]string{"kind": string(lookup.Kind), "message": lookup.Error()}})
		_, _ = writer.Write(payload)
		return
	}
	fmt.Fprintln(writer, "whodis:", lookup.Error())
}

func exitCode(err error) int {
	var lookup *whodis.LookupError
	if !errors.As(err, &lookup) {
		return 1
	}
	switch lookup.Kind {
	case whodis.ErrorInvalidInput:
		return 2
	case whodis.ErrorNotFound:
		return 3
	case whodis.ErrorRateLimited:
		return 4
	default:
		return 1
	}
}

func printUsage(writer io.Writer) {
	fmt.Fprint(writer, `Usage:
  whodis <target> [options]
  whodis config
  whodis config set format|color|details <value>
  whodis config get format|color|details
  whodis config unset format|color|details
  whodis config reset
  whodis config path

Targets: domain names, IPv4/IPv6 addresses or CIDRs, and ASNs (AS15169).

Options:
  -f, --format <type>       dashboard, tree, geekboys, plain, json, yaml, markdown, or raw
  -o, --output <file|->     write to a file; format is inferred from extension
      --protocol <name>     auto (default), rdap, or whois
      --fallback <mode>     unavailable (default), none, or any-error
      --server <endpoint>   explicitly choose an RDAP URL or WHOIS server
      --timeout <duration>  request timeout (default: 15s)
      --refresh-bootstrap   refresh IANA RDAP service data
      --dns <mode>          auto (default), off, scan, or axfr
      --axfr                try an authoritative zone transfer; same as --dns axfr
      --resolver <address>  DNS resolver host or IP, with an optional port
      --color <mode>        auto (default), always, or never
      --details             expand notices in dashboard, tree, and geekboys output
      --no-details          summarize notices for this lookup
      --force               overwrite an existing output file
  -h, --help                show this help
      --version             show version

Environment:
  WHODIS_FORMAT             default output format when --format and file inference are absent

Examples:
  whodis example.com
  whodis -- config
  whodis example.com --format tree
  whodis config
  whodis config set format geekboys
  whodis config set color never
  whodis example.com --dns off
  whodis example.com --axfr
  whodis 8.8.8.8 --format json
  whodis AS15169 --output google-asn.yaml
  whodis example.cc --protocol whois --fallback none
`)
}
