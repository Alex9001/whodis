package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/Alex9001/whodis"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

var version = "dev"

type cliTask string

const (
	taskLookup  cliTask = "lookup"
	taskScan    cliTask = "scan"
	taskAXFR    cliTask = "axfr"
	taskExpires cliTask = "expires"
	taskGet     cliTask = "get"
)

type cliOptions struct {
	target           string // retained for single-target compatibility in callers/tests
	targets          []string
	inputSources     []cliInputSource
	fields           []whodis.ProjectionField
	jobs             int
	format           string
	formatSet        bool
	output           string
	task             cliTask
	protocol         whodis.Protocol
	protocolSet      bool
	fallback         whodis.FallbackMode
	fallbackSet      bool
	server           string
	timeout          time.Duration
	refreshBootstrap bool
	dnsResolver      string
	color            string
	colorSet         bool
	details          bool
	detailsSet       bool
	force            bool
	help             bool
	showVersion      bool
}

type cliInputSource struct {
	target string
	path   string
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	return runWithRuntime(args, stdout, stderr, defaultCLIRuntime())
}

func runWithRuntime(args []string, stdout, stderr io.Writer, runtime cliRuntime) int {
	if len(args) > 0 && args[0] == "config" {
		return runConfig(args[1:], stdout, stderr, runtime)
	}
	if len(args) > 0 && args[0] == "help" {
		return runHelp(args[1:], stdout, stderr)
	}
	options, err := parseArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		printUsage(stderr)
		return 2
	}
	if options.help {
		if options.task != taskLookup {
			printTaskUsage(stdout, options.task)
		} else if options.protocolSet {
			printProtocolsUsage(stdout)
		} else {
			printUsage(stdout)
		}
		return 0
	}
	if options.showVersion {
		fmt.Fprintln(stdout, "whodis", resolvedVersion())
		return 0
	}
	inputs, err := resolveInputs(options, runtime)
	if err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		if len(options.inputSources) == 0 {
			printUsage(stderr)
			return 2
		}
		return 1
	}
	if len(inputs) == 0 {
		fmt.Fprintln(stderr, "whodis: a target is required")
		printUsage(stderr)
		return 2
	}
	if err := validateTaskTargets(inputs, options.task); err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		printTaskUsage(stderr, options.task)
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
	if format == whodis.FormatRaw && (options.task != taskLookup || len(inputs) != 1 || len(options.fields) > 0) {
		fmt.Fprintln(stderr, "whodis: raw output requires one ordinary registration lookup")
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

	client := whodis.NewClient(whodis.ClientOptions{Timeout: options.timeout})
	lookupOptions := whodis.LookupOptions{
		Protocol: options.protocol, Fallback: options.fallback, Server: options.server,
		Timeout: options.timeout, RefreshBootstrap: options.refreshBootstrap,
		DNSMode: taskDNSMode(options.task), DNSResolver: options.dnsResolver,
	}
	if options.task == taskLookup && len(inputs) == 1 && len(options.fields) == 0 {
		ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
		defer cancel()
		result, err := client.Lookup(ctx, inputs[0], lookupOptions)
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

	batch, err := client.LookupBatch(context.Background(), inputs, whodis.BatchLookupOptions{LookupOptions: lookupOptions, Workers: options.jobs})
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
	if err := whodis.RenderBatch(writer, batch, format, whodis.BatchRenderOptions{RenderOptions: whodis.RenderOptions{Color: color, Details: details}, Fields: options.fields}); err != nil {
		fmt.Fprintln(stderr, "whodis: could not render output:", err)
		return 1
	}
	if batch.HasErrors() {
		failed := 0
		for _, item := range batch.Items {
			if item.Error != nil {
				failed++
			}
		}
		if len(batch.Items) == 1 {
			return batchExitCode(batch.Items[0].Error)
		}
		fmt.Fprintf(stderr, "whodis: %d of %d lookups failed\n", failed, len(batch.Items))
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
	options := cliOptions{task: taskLookup, protocol: whodis.ProtocolAuto, fallback: whodis.FallbackUnavailable, timeout: 15 * time.Second, color: "auto", jobs: 4}
	appendTarget := func(target string) {
		options.targets = append(options.targets, target)
		options.inputSources = append(options.inputSources, cliInputSource{target: target})
	}
	appendField := func(field whodis.ProjectionField) {
		for _, existing := range options.fields {
			if existing == field {
				return
			}
		}
		options.fields = append(options.fields, field)
	}
	remaining, err := parseCommandPrefix(args, &options, appendField)
	if err != nil {
		return options, err
	}
	for index := 0; index < len(remaining); index++ {
		arg := remaining[index]
		if arg == "--" {
			for _, target := range remaining[index+1:] {
				appendTarget(target)
			}
			break
		}
		name, inline, hasInline := strings.Cut(arg, "=")
		value := func() (string, error) {
			if hasInline {
				return inline, nil
			}
			if index+1 >= len(remaining) {
				return "", fmt.Errorf("%s requires a value", name)
			}
			index++
			return remaining[index], nil
		}
		switch name {
		case "-h", "--help":
			options.help = true
		case "--version":
			options.showVersion = true
		case "-o", "--output":
			v, err := value()
			if err != nil {
				return options, err
			}
			options.output = v
		case "-i", "--input":
			v, err := value()
			if err != nil {
				return options, err
			}
			if strings.TrimSpace(v) == "" {
				return options, fmt.Errorf("%s requires a non-empty path", name)
			}
			options.inputSources = append(options.inputSources, cliInputSource{path: v})
		case "-j", "--jobs":
			v, err := value()
			if err != nil {
				return options, err
			}
			jobs, err := strconv.Atoi(v)
			if err != nil || jobs < 1 || jobs > 32 {
				return options, fmt.Errorf("--jobs must be a whole number between 1 and 32")
			}
			options.jobs = jobs
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
		case "--refresh":
			options.refreshBootstrap = true
		case "--resolver":
			v, err := value()
			if err != nil {
				return options, err
			}
			options.dnsResolver = v
		case "--details":
			if options.detailsSet && !options.details {
				return options, fmt.Errorf("--details conflicts with --summary")
			}
			options.details, options.detailsSet = true, true
		case "--summary":
			if options.detailsSet && options.details {
				return options, fmt.Errorf("--summary conflicts with --details")
			}
			options.details, options.detailsSet = false, true
		case "--strict":
			if options.fallbackSet && options.fallback != whodis.FallbackNone {
				return options, fmt.Errorf("--strict conflicts with --try-both")
			}
			options.fallback, options.fallbackSet = whodis.FallbackNone, true
		case "--try-both":
			if options.fallbackSet && options.fallback != whodis.FallbackAnyError {
				return options, fmt.Errorf("--try-both conflicts with --strict")
			}
			options.fallback, options.fallbackSet = whodis.FallbackAnyError, true
		case "--dashboard", "--tree", "--geekboys", "--plain", "--json", "--yaml", "--markdown", "--raw":
			if hasInline {
				return options, fmt.Errorf("%s does not take a value", name)
			}
			if options.formatSet {
				return options, fmt.Errorf("only one output format shortcut may be used")
			}
			options.format, options.formatSet = strings.TrimPrefix(name, "--"), true
		case "--force":
			options.force = true
		default:
			if strings.HasPrefix(arg, "-") {
				return options, fmt.Errorf("unknown option %s", arg)
			}
			appendTarget(arg)
		}
	}
	if len(options.targets) > 0 {
		options.target = options.targets[0]
	}
	if err := validateCLIOptions(options); err != nil {
		return options, err
	}
	return options, nil
}

func parseCommandPrefix(args []string, options *cliOptions, appendField func(whodis.ProjectionField)) ([]string, error) {
	if len(args) == 0 || args[0] == "--" || strings.HasPrefix(args[0], "-") {
		return args, nil
	}
	index := 0
	switch args[index] {
	case string(whodis.ProtocolRDAP), string(whodis.ProtocolWHOIS), string(whodis.ProtocolRWHOIS):
		options.protocol, options.protocolSet = whodis.Protocol(args[index]), true
		index++
	}
	if index >= len(args) || args[index] == "--" || strings.HasPrefix(args[index], "-") {
		return args[index:], nil
	}
	switch args[index] {
	case string(taskScan):
		options.task = taskScan
		index++
	case string(taskAXFR):
		options.task = taskAXFR
		index++
	case string(taskExpires):
		options.task = taskExpires
		appendField(whodis.FieldExpiration)
		index++
	case string(taskGet):
		options.task = taskGet
		index++
		if index >= len(args) || args[index] == "--help" || args[index] == "-h" {
			if index < len(args) {
				options.help = true
				index++
			}
			return args[index:], nil
		}
		if strings.HasPrefix(args[index], "-") || args[index] == "--" {
			return nil, fmt.Errorf("get requires a comma-separated field list")
		}
		if err := parseFieldList(args[index], appendField); err != nil {
			return nil, err
		}
		index++
	}
	return args[index:], nil
}

func parseFieldList(value string, appendField func(whodis.ProjectionField)) error {
	for _, name := range strings.Split(value, ",") {
		field, err := whodis.ParseProjectionField(name)
		if err != nil {
			return err
		}
		appendField(field)
	}
	return nil
}

func validateCLIOptions(options cliOptions) error {
	if options.protocol == whodis.ProtocolRWHOIS && strings.TrimSpace(options.server) == "" && !options.help {
		return fmt.Errorf("rwhois requires --server")
	}
	if options.server != "" && !options.protocolSet {
		return fmt.Errorf("--server requires rdap, whois, or rwhois")
	}
	if options.server != "" && options.fallbackSet {
		return fmt.Errorf("--server cannot be combined with --strict or --try-both")
	}
	if options.refreshBootstrap && options.protocolSet && options.protocol != whodis.ProtocolRDAP {
		return fmt.Errorf("--refresh is only available with automatic routing or rdap")
	}
	if options.dnsResolver != "" && options.task != taskScan && options.task != taskAXFR {
		return fmt.Errorf("--resolver is only available with scan or axfr")
	}
	return nil
}

func taskDNSMode(task cliTask) whodis.DNSMode {
	switch task {
	case taskScan:
		return whodis.DNSScan
	case taskAXFR:
		return whodis.DNSAXFR
	default:
		return whodis.DNSOff
	}
}

func validateTaskTargets(inputs []string, task cliTask) error {
	if task != taskScan && task != taskAXFR {
		return nil
	}
	for _, input := range inputs {
		target, err := whodis.ParseTarget(input)
		if err == nil && target.Kind != whodis.KindDomain {
			return fmt.Errorf("%s requires domain targets; %q is an %s", task, input, target.Kind)
		}
	}
	return nil
}

func resolveInputs(options cliOptions, runtime cliRuntime) ([]string, error) {
	var inputs []string
	stdinUsed := false
	readSource := func(reader io.Reader, description string) error {
		if reader == nil {
			return fmt.Errorf("could not read %s", description)
		}
		values, err := readTargetLines(reader)
		if err != nil {
			return fmt.Errorf("could not read %s: %w", description, err)
		}
		inputs = append(inputs, values...)
		return nil
	}
	for _, source := range options.inputSources {
		if source.path == "" {
			inputs = append(inputs, source.target)
			continue
		}
		if source.path == "-" {
			if stdinUsed {
				return nil, fmt.Errorf("standard input can only be used once")
			}
			stdinUsed = true
			if err := readSource(runtime.stdin, "standard input"); err != nil {
				return nil, err
			}
			continue
		}
		file, err := os.Open(source.path)
		if err != nil {
			return nil, fmt.Errorf("could not open input file %s: %w", source.path, err)
		}
		err = readSource(file, source.path)
		closeErr := file.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, fmt.Errorf("could not close input file %s: %w", source.path, closeErr)
		}
	}
	if len(options.inputSources) == 0 && runtime.stdin != nil && runtime.stdinIsTerminal != nil && !runtime.stdinIsTerminal() {
		if err := readSource(runtime.stdin, "standard input"); err != nil {
			return nil, err
		}
	}
	return inputs, nil
}

func readTargetLines(reader io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4<<10), 1<<20)
	var inputs []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		inputs = append(inputs, line)
	}
	return inputs, scanner.Err()
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
	if len(options.fields) > 0 {
		if runtime.isTerminal(stdout) {
			return whodis.FormatPretty, nil
		}
		return whodis.FormatPlain, nil
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

func batchExitCode(err *whodis.BatchError) int {
	if err == nil {
		return 0
	}
	switch err.Kind {
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
  whodis [rdap|whois|rwhois] [scan|axfr|expires|get <fields>] [target ...] [options]
  whodis config
  whodis help [scan|axfr|expires|get|protocols|formats|advanced]

Targets: domain names, IPv4/IPv6 addresses or CIDRs, and ASNs (AS15169).

Commands:
  (none)                    full registration lookup (the default)
  scan                      registration plus public DNS discovery
  axfr                      registration plus an authoritative zone-transfer attempt
  expires                   expiration only; useful for one or many domains
  get <fields>              selected fields, comma-separated

Output shortcuts (choose one):
  --dashboard  --tree  --geekboys  --plain  --json  --yaml  --markdown  --raw

Common options:
  -i, --input <file|->      add newline-delimited targets; - reads standard input
  -o, --output <file|->     write to a file; format is inferred from its extension
  -j, --jobs <count>        concurrent batch lookups (default: 4; range: 1-32)
      --timeout <duration>  request timeout (default: 15s)
      --color <mode>        auto (default), always, or never
      --details             expand notices in visual output
      --summary             summarize notices in visual output
      --force               overwrite an existing output file
	  -h, --help                show this help
	      --version             show version

Routing and DNS:
      --server <endpoint>   explicit endpoint; requires rdap, whois, or rwhois
      --strict              do not fall back to another registration protocol
      --try-both            fall back after any protocol error
      --refresh             refresh IANA RDAP service data
      --resolver <address>  DNS resolver for scan or axfr

Environment:
  WHODIS_FORMAT             default output format when no shortcut or file inference applies

Examples:
  whodis example.com
  whodis scan example.com --tree
  whodis expires google.com yahoo.com
  whodis get expiration,registrar -i domains.txt -o results.txt
  printf 'google.com\nyahoo.com\n' | whodis expires
  whodis whois example.cc --strict
  whodis rwhois get status 23.228.169.1 --server rwhois.example.net
  whodis -- config
  whodis config
`)
}

func printTaskUsage(writer io.Writer, task cliTask) {
	switch task {
	case taskScan:
		fmt.Fprint(writer, `Usage: whodis [rdap|whois|rwhois] scan <domain> [<domain> ...] [options]

Looks up registration data and public DNS records (A, AAAA, CNAME, MX, NS, TXT, CAA, and more).
Only domain targets are accepted. Use --resolver <host[:port]> to choose the DNS resolver.

Example: whodis scan example.com --tree
`)
	case taskAXFR:
		fmt.Fprint(writer, `Usage: whodis [rdap|whois|rwhois] axfr <domain> [<domain> ...] [options]

Looks up registration data and attempts an authoritative DNS zone transfer. When transfer is unavailable,
Whodis keeps the regular DNS scan results and reports that limitation in the result.
Only domain targets are accepted. Use --resolver <host[:port]> to choose the DNS resolver.

Example: whodis axfr example.com --json
`)
	case taskExpires:
		fmt.Fprint(writer, `Usage: whodis [rdap|whois|rwhois] expires <target> [<target> ...] [options]

Returns only each target's expiration date. With a terminal it uses a compact grid; redirected output is plain text.

Example: whodis expires google.com yahoo.com -o expirations.txt
`)
	case taskGet:
		fmt.Fprint(writer, `Usage: whodis [rdap|whois|rwhois] get <fields> <target> [<target> ...] [options]

<fields> is a comma-separated list of: expiration, registration, updated, registrar, registry,
status, nameservers, dnssec, protocol.

Example: whodis get expiration,registrar,status google.com yahoo.com --plain
`)
	default:
		printUsage(writer)
	}
}

func printProtocolsUsage(writer io.Writer) {
	fmt.Fprint(writer, `Usage: whodis [rdap|whois|rwhois] [command] [target ...] [options]

Routing defaults to automatic selection. Put a protocol before the command to force it:
  whodis rdap example.com
  whodis whois scan example.com --strict
  whodis rwhois get status 192.0.2.1 --server rwhois.example.net

--server requires an explicit protocol. RWhois always requires --server.
--strict disables fallback; --try-both allows fallback after any protocol error.
--refresh refreshes IANA RDAP service data and is available with automatic routing or rdap.
`)
}

func printFormatsUsage(writer io.Writer) {
	fmt.Fprint(writer, `Output shortcuts:
  --dashboard  organized terminal dashboard (default on a terminal)
  --tree       indented registration view
  --geekboys   retro terminal view
  --plain      portable text
  --json       JSON
  --yaml       YAML
  --markdown   Markdown
  --raw        unmodified source response; one ordinary lookup only

Use exactly one shortcut. Without one, Whodis infers a format from --output, WHODIS_FORMAT,
saved preferences, and whether output is a terminal.
`)
}

func printAdvancedUsage(writer io.Writer) {
	fmt.Fprint(writer, `Advanced options:
  -i, --input <file|->      add newline-delimited targets; - reads standard input
  -o, --output <file|->     write to a file; refuses to overwrite unless --force is used
  -j, --jobs <count>        batch concurrency, from 1 through 32
      --timeout <duration>  per-lookup timeout
      --color <mode>        auto, always, or never
      --details             expand notices in dashboard, tree, and geekboys views
      --summary             summarize notices in those views
      --resolver <address>  DNS resolver for scan or axfr
      --server <endpoint>   explicit server, with rdap/whois/rwhois
      --strict              do not fall back to another registration protocol
      --try-both            fall back after any protocol error
      --refresh             refresh IANA RDAP service data
      --force               overwrite --output's existing file
`)
}

func runHelp(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stdout)
		return 0
	}
	if len(args) != 1 {
		fmt.Fprintln(stderr, "whodis: help accepts one topic")
		printUsage(stderr)
		return 2
	}
	switch args[0] {
	case string(taskScan), string(taskAXFR), string(taskExpires), string(taskGet):
		printTaskUsage(stdout, cliTask(args[0]))
	case "protocols":
		printProtocolsUsage(stdout)
	case "formats":
		printFormatsUsage(stdout)
	case "advanced":
		printAdvancedUsage(stdout)
	case "config":
		printConfigUsage(stdout)
	default:
		fmt.Fprintf(stderr, "whodis: unknown help topic %q\n", args[0])
		printUsage(stderr)
		return 2
	}
	return 0
}
