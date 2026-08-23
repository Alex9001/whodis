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

	"github.com/Alex9001/whodis/v2"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

var version = "dev"

type cliTask string

const (
	taskLookup       cliTask = "lookup"
	taskScan         cliTask = "scan"
	taskAXFR         cliTask = "axfr"
	taskExpires      cliTask = "expires"
	taskGet          cliTask = "get"
	taskDNSQuery     cliTask = "dns-query"
	taskDNSInventory cliTask = "dns-inventory"
	taskDNSCompare   cliTask = "dns-compare"
	taskDNSTrace     cliTask = "dns-trace"
	taskDNSTransfer  cliTask = "dns-transfer"
	taskDiagnose     cliTask = "diagnose"
	taskInvestigate  cliTask = "investigate"
)

type cliOptions struct {
	target            string // retained for single-target compatibility in callers/tests
	targets           []string
	inputSources      []cliInputSource
	fields            []whodis.ProjectionField
	jobs              int
	format            string
	formatSet         bool
	output            string
	task              cliTask
	protocol          whodis.Protocol
	protocolSet       bool
	fallback          whodis.FallbackMode
	fallbackSet       bool
	server            string
	timeout           time.Duration
	timeoutSet        bool
	refreshBootstrap  bool
	dnsResolver       string
	dnsResolvers      []string
	recordTypes       []string
	dnsClass          string
	resolverStrategy  whodis.ResolverStrategy
	edns              whodis.EDNSOptions
	dnssecSet         bool
	transfer          whodis.TransferOptions
	tsigSecretEnv     string
	tsigSecretFile    string
	allowPrivate      bool
	allowInsecureHTTP bool
	noRecursion       bool
	checkingDisabled  bool
	globalping        bool
	globalpingFrom    []string
	globalpingLimit   int
	trace             bool
	remote            bool
	enrichments       []string
	relatedLimit      int
	linkProviders     []string
	linkProvidersSet  bool
	investigationLink string
	otxEndpoint       string
	color             string
	colorSet          bool
	details           bool
	detailsSet        bool
	force             bool
	saveSnapshot      bool
	snapshotLabel     string
	help              bool
	showVersion       bool
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
	if code, handled := runAuditCommand(args, stdout, stderr, runtime); handled {
		return code
	}
	if len(args) > 0 && args[0] == "config" {
		return runConfig(args[1:], stdout, stderr, runtime)
	}
	if len(args) > 0 && args[0] == "help" {
		return runHelp(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "completion" {
		return runCompletion(args[1:], stdout, stderr)
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
	return runEngineTask(inputs, options, format, color, details, stdout, stderr, runtime)
}

func runEngineTask(inputs []string, options cliOptions, format whodis.Format, color string, details bool, stdout, stderr io.Writer, runtime cliRuntime) int {
	operation := whodis.OperationRegistration
	switch options.task {
	case taskScan:
		operation = whodis.OperationInspect
	case taskAXFR, taskDNSTransfer:
		operation = whodis.OperationDNSTransfer
	case taskDNSQuery:
		operation = whodis.OperationDNSQuery
	case taskDNSInventory:
		operation = whodis.OperationDNSInventory
	case taskDNSCompare:
		operation = whodis.OperationDNSCompare
	case taskDNSTrace:
		operation = whodis.OperationDNSTrace
	case taskDiagnose:
		operation = whodis.OperationDiagnose
	case taskInvestigate:
		operation = whodis.OperationInvestigate
	}
	recursive := !options.noRecursion
	if options.tsigSecretEnv != "" {
		options.transfer.TSIGSecret = strings.TrimSpace(runtime.getenv(options.tsigSecretEnv))
		if options.transfer.TSIGSecret == "" {
			fmt.Fprintf(stderr, "whodis: environment variable %s is empty\n", options.tsigSecretEnv)
			return 2
		}
	}
	if options.tsigSecretFile != "" {
		payload, err := os.ReadFile(options.tsigSecretFile)
		if err != nil {
			fmt.Fprintf(stderr, "whodis: could not read TSIG secret file: %v\n", err)
			return 2
		}
		options.transfer.TSIGSecret = strings.TrimSpace(string(payload))
		if options.transfer.TSIGSecret == "" {
			fmt.Fprintln(stderr, "whodis: TSIG secret file is empty")
			return 2
		}
	}
	if config, exists, err := loadOptionalUserConfig(runtime); err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 1
	} else if exists {
		if len(options.dnsResolvers) == 0 {
			options.dnsResolvers = append([]string(nil), config.DNSResolvers...)
		}
		if options.resolverStrategy == "" && config.ResolverStrategy != "" {
			options.resolverStrategy = whodis.ResolverStrategy(config.ResolverStrategy)
		}
		if !options.dnssecSet && config.DNSSEC != nil {
			options.edns.DNSSEC = *config.DNSSEC
		}
		if options.relatedLimit == 0 {
			options.relatedLimit = config.RelatedLimit
		}
		if !options.linkProvidersSet {
			options.linkProviders = append([]string(nil), config.ResearchLinks...)
		}
		if options.investigationLink == "" {
			options.investigationLink = config.InvestigationLink
		}
		if options.otxEndpoint == "" {
			options.otxEndpoint = config.OTXEndpoint
		}
	}
	dnsOptions := whodis.DNSOptions{
		Types: options.recordTypes, Class: options.dnsClass,
		Resolvers: options.dnsResolvers, Strategy: options.resolverStrategy,
		Recursive: &recursive, CheckingDisabled: options.checkingDisabled,
		EDNS: options.edns, Transfer: options.transfer, Globalping: options.globalping,
		GlobalpingLocations: options.globalpingFrom, GlobalpingLimit: options.globalpingLimit,
		GlobalpingToken: runtime.getenv("GLOBALPING_TOKEN"),
	}
	if options.task == taskDNSTrace && len(dnsOptions.Types) == 0 {
		dnsOptions.Types = []string{"A"}
	}
	registration := whodis.LookupOptions{
		Protocol: options.protocol, Fallback: options.fallback, Server: options.server,
		Timeout: options.timeout, RefreshBootstrap: options.refreshBootstrap,
	}
	requests := make([]whodis.Request, 0, len(inputs))
	for _, input := range inputs {
		request := whodis.Request{
			Operation: operation, Target: input, Timeout: options.timeout,
			Registration: registration, DNS: dnsOptions,
			Diagnose: whodis.DiagnoseOptions{DNS: dnsOptions, Timeout: options.timeout, Trace: options.trace, Remote: options.remote},
		}
		if operation == whodis.OperationInvestigate {
			request.Investigation = whodis.InvestigationOptions{
				DNS: dnsOptions, Enrichments: append([]string(nil), options.enrichments...),
				RelatedLimit: options.relatedLimit, LinkProviders: append([]string(nil), options.linkProviders...), ExternalLinkTemplate: options.investigationLink,
				OTXEndpoint: options.otxEndpoint, OTXToken: runtime.getenv("WHODIS_OTX_API_KEY"),
			}
		}
		requests = append(requests, request)
	}
	engine := whodis.NewEngine(whodis.EngineOptions{Timeout: options.timeout, NetworkPolicy: whodis.NetworkPolicy{AllowPrivate: options.allowPrivate, AllowInsecureHTTP: options.allowInsecureHTTP}})
	defer engine.Close()
	batch, err := engine.RunBatch(context.Background(), whodis.BatchRequest{Requests: requests, Workers: options.jobs})
	if err != nil {
		printLookupError(stderr, err, format)
		return exitCode(err)
	}
	writer, closeWriter, err := openOutput(options.output, options.force, stdout)
	if err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 1
	}
	var renderErr error
	if len(options.fields) > 0 {
		legacy := whodis.BatchResult{SchemaVersion: 1, Items: make([]whodis.BatchItem, len(batch.Reports))}
		for index := range batch.Reports {
			report := &batch.Reports[index]
			legacy.Items[index].Input = inputs[index]
			if report.Registration != nil {
				result := report.Registration.AsLookupResult(report.Subject, report.ObservedAt)
				legacy.Items[index].Result = &result
			} else if len(report.Errors) > 0 {
				legacy.Items[index].Error = &whodis.BatchError{Kind: report.Errors[0].Kind, Message: report.Errors[0].Message}
			}
		}
		renderErr = whodis.RenderBatch(writer, legacy, format, whodis.BatchRenderOptions{RenderOptions: whodis.RenderOptions{Color: color, Details: details, Width: cliOutputWidth(writer)}, Fields: options.fields})
	} else {
		renderErr = whodis.RenderBatchReport(writer, batch, format, whodis.RenderOptions{Color: color, Details: details, Width: cliOutputWidth(writer)})
	}
	if renderErr != nil {
		abortOutput(writer)
		fmt.Fprintln(stderr, "whodis: could not render output:", renderErr)
		return 1
	}
	if err := closeWriter(); err != nil {
		fmt.Fprintln(stderr, "whodis: could not finalize output:", err)
		return 1
	}
	if options.saveSnapshot {
		if id, saveErr := saveBatchSnapshot(requests, batch, options.snapshotLabel); saveErr != nil {
			fmt.Fprintln(stderr, "whodis: could not save snapshot:", saveErr)
			return 1
		} else {
			fmt.Fprintln(stderr, "whodis: saved snapshot", id)
		}
	}
	failures := 0
	for _, report := range batch.Reports {
		if len(report.Errors) > 0 {
			failures++
		}
	}
	if failures > 0 {
		fmt.Fprintf(stderr, "whodis: %d of %d operations completed with errors\n", failures, len(batch.Reports))
		if len(batch.Reports) == 1 && len(batch.Reports[0].Errors) > 0 {
			switch batch.Reports[0].Errors[0].Kind {
			case whodis.ErrorInvalidInput:
				return 2
			case whodis.ErrorNotFound:
				return 3
			case whodis.ErrorRateLimited:
				return 4
			}
		}
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
		case "-f", "--format":
			v, err := value()
			if err != nil {
				return options, err
			}
			if options.formatSet {
				return options, fmt.Errorf("only one output format may be selected")
			}
			if _, err := whodis.ParseFormat(v); err != nil {
				return options, err
			}
			options.format, options.formatSet = v, true
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
			options.timeoutSet = true
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
			options.dnsResolvers = append(options.dnsResolvers, v)
			if options.dnsResolver == "" {
				options.dnsResolver = v
			}
		case "--class":
			v, err := value()
			if err != nil {
				return options, err
			}
			options.dnsClass = v
		case "--strategy":
			v, err := value()
			if err != nil {
				return options, err
			}
			options.resolverStrategy = whodis.ResolverStrategy(strings.ToLower(v))
		case "--bufsize":
			v, err := value()
			if err != nil {
				return options, err
			}
			n, parseErr := strconv.ParseUint(v, 10, 16)
			if parseErr != nil || n < 512 {
				return options, fmt.Errorf("--bufsize must be between 512 and 65535")
			}
			options.edns.BufferSize = uint16(n)
		case "--dnssec":
			options.edns.DNSSEC = true
			options.dnssecSet = true
		case "--no-dnssec":
			options.edns.DNSSEC = false
			options.dnssecSet = true
		case "--nsid":
			options.edns.NSID = true
		case "--ecs":
			v, err := value()
			if err != nil {
				return options, err
			}
			options.edns.ECS = v
		case "--cookie":
			v, err := value()
			if err != nil {
				return options, err
			}
			options.edns.Cookie = v
		case "--padding":
			v, err := value()
			if err != nil {
				return options, err
			}
			n, parseErr := strconv.ParseUint(v, 10, 16)
			if parseErr != nil {
				return options, fmt.Errorf("--padding must be a whole number")
			}
			options.edns.Padding = uint16(n)
		case "--no-recursion":
			options.noRecursion = true
		case "--checking-disabled":
			options.checkingDisabled = true
		case "--ixfr":
			options.transfer.Type = "IXFR"
		case "--serial":
			v, err := value()
			if err != nil {
				return options, err
			}
			n, parseErr := strconv.ParseUint(v, 10, 32)
			if parseErr != nil {
				return options, fmt.Errorf("--serial must be a 32-bit unsigned integer")
			}
			options.transfer.Serial = uint32(n)
		case "--tsig-name":
			v, err := value()
			if err != nil {
				return options, err
			}
			options.transfer.TSIGName = v
		case "--tsig-secret":
			v, err := value()
			if err != nil {
				return options, err
			}
			options.transfer.TSIGSecret = v
		case "--tsig-secret-env":
			v, err := value()
			if err != nil {
				return options, err
			}
			options.tsigSecretEnv = v
		case "--tsig-secret-file":
			v, err := value()
			if err != nil {
				return options, err
			}
			options.tsigSecretFile = v
		case "--tsig-algorithm":
			v, err := value()
			if err != nil {
				return options, err
			}
			options.transfer.TSIGAlgo = v
		case "--tls":
			options.transfer.TLS = true
		case "--allow-private":
			options.allowPrivate = true
		case "--allow-insecure-http":
			options.allowInsecureHTTP = true
		case "--globalping":
			options.globalping = true
		case "--from":
			v, err := value()
			if err != nil {
				return options, err
			}
			options.globalpingFrom = append(options.globalpingFrom, v)
		case "--limit":
			v, err := value()
			if err != nil {
				return options, err
			}
			n, parseErr := strconv.Atoi(v)
			if parseErr != nil || n < 1 || n > 10 {
				return options, fmt.Errorf("--limit must be between 1 and 10")
			}
			options.globalpingLimit = n
		case "--trace":
			options.trace = true
		case "--remote":
			options.remote = true
		case "--enrich":
			v, err := value()
			if err != nil {
				return options, err
			}
			for _, provider := range strings.Split(v, ",") {
				provider = strings.ToLower(strings.TrimSpace(provider))
				if provider != "" {
					options.enrichments = append(options.enrichments, provider)
				}
			}
			if len(options.enrichments) == 0 {
				return options, fmt.Errorf("--enrich requires a provider name")
			}
		case "--related-limit":
			v, err := value()
			if err != nil {
				return options, err
			}
			n, parseErr := strconv.Atoi(v)
			if parseErr != nil || n < 1 || n > 100 {
				return options, fmt.Errorf("--related-limit must be between 1 and 100")
			}
			options.relatedLimit = n
		case "--investigation-link":
			v, err := value()
			if err != nil {
				return options, err
			}
			options.investigationLink = strings.TrimSpace(v)
		case "--research-links":
			v, err := value()
			if err != nil {
				return options, err
			}
			options.linkProviders = splitCommaValues(v)
			if len(options.linkProviders) == 0 {
				return options, fmt.Errorf("--research-links requires core, all, off, or provider IDs")
			}
			options.linkProvidersSet = true
		case "--otx-endpoint":
			v, err := value()
			if err != nil {
				return options, err
			}
			options.otxEndpoint = strings.TrimSpace(v)
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
		case "--dashboard", "--tree", "--geekboys", "--plain", "--json", "--yaml", "--csv", "--ndjson", "--markdown", "--raw":
			if hasInline {
				return options, fmt.Errorf("%s does not take a value", name)
			}
			if options.formatSet {
				return options, fmt.Errorf("only one output format shortcut may be used")
			}
			options.format, options.formatSet = strings.TrimPrefix(name, "--"), true
		case "--force":
			options.force = true
		case "--save":
			options.saveSnapshot = true
		case "--label":
			v, err := value()
			if err != nil {
				return options, err
			}
			options.snapshotLabel = strings.TrimSpace(v)
		default:
			if strings.HasPrefix(arg, "-") {
				return options, fmt.Errorf("unknown option %s", arg)
			}
			if isSingleDNSOperation(options.task) && options.task != taskDNSTransfer && len(options.targets) > 0 {
				options.recordTypes = append(options.recordTypes, arg)
			} else {
				appendTarget(arg)
			}
		}
	}
	if len(options.targets) > 0 {
		options.target = options.targets[0]
	}
	if options.task == taskInvestigate && !options.timeoutSet {
		options.timeout = 30 * time.Second
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
	case "lookup":
		options.task = taskLookup
		index++
	case "inspect":
		options.task = taskScan
		index++
	case "registration":
		options.task = taskLookup
		index++
	case "dns":
		index++
		if index >= len(args) || args[index] == "--help" || args[index] == "-h" {
			options.help = true
			options.task = taskDNSQuery
			if index < len(args) {
				index++
			}
			return args[index:], nil
		}
		switch args[index] {
		case "query":
			options.task = taskDNSQuery
		case "inventory":
			options.task = taskDNSInventory
		case "compare":
			options.task = taskDNSCompare
		case "trace":
			options.task = taskDNSTrace
		case "transfer":
			options.task = taskDNSTransfer
		default:
			return nil, fmt.Errorf("dns requires query, inventory, compare, trace, or transfer")
		}
		index++
	case "diagnose":
		options.task = taskDiagnose
		index++
	case "investigate":
		options.task = taskInvestigate
		index++
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

func splitCommaValues(value string) []string {
	var result []string
	for _, entry := range strings.Split(value, ",") {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry != "" {
			result = append(result, entry)
		}
	}
	return result
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
	if options.dnsResolver != "" && !supportsDNSOptions(options.task) {
		return fmt.Errorf("--resolver is only available with DNS operations, diagnose, or investigate")
	}
	if (options.dnsClass != "" || options.resolverStrategy != "" || options.edns != (whodis.EDNSOptions{}) || options.dnssecSet || options.noRecursion || options.checkingDisabled || options.globalping) && !supportsDNSOptions(options.task) {
		return fmt.Errorf("DNS query options require a DNS operation, diagnose, or investigate")
	}
	if (len(options.globalpingFrom) > 0 || options.globalpingLimit > 0) && !options.globalping && !options.remote {
		return fmt.Errorf("--from and --limit require --globalping or diagnose --remote")
	}
	if (options.trace || options.remote) && options.task != taskDiagnose {
		return fmt.Errorf("--trace and --remote require diagnose")
	}
	if (len(options.enrichments) > 0 || options.relatedLimit > 0 || options.linkProvidersSet || options.investigationLink != "" || options.otxEndpoint != "") && options.task != taskInvestigate {
		return fmt.Errorf("--enrich, --related-limit, --research-links, --investigation-link, and --otx-endpoint require investigate")
	}
	for _, provider := range options.enrichments {
		if provider != "otx" {
			return fmt.Errorf("unknown enrichment provider %q; choose otx", provider)
		}
	}
	if options.task == taskInvestigate {
		if err := whodis.ValidateInvestigationOptions(whodis.InvestigationOptions{
			RelatedLimit: options.relatedLimit, LinkProviders: options.linkProviders, ExternalLinkTemplate: options.investigationLink, OTXEndpoint: options.otxEndpoint,
		}); err != nil {
			return err
		}
	}
	if options.transfer != (whodis.TransferOptions{}) && options.task != taskDNSTransfer {
		return fmt.Errorf("--ixfr, --serial, --tls, and --tsig-* require dns transfer")
	}
	if options.globalping && options.task != taskDNSQuery && options.task != taskDNSCompare && options.task != taskDiagnose {
		return fmt.Errorf("--globalping requires dns query, dns compare, or diagnose")
	}
	if options.task == taskDNSTransfer && len(options.targets) > 1 {
		return fmt.Errorf("dns transfer accepts one zone at a time")
	}
	if options.transfer.TSIGName != "" && options.transfer.TSIGSecret == "" {
		if options.tsigSecretEnv == "" && options.tsigSecretFile == "" {
			return fmt.Errorf("--tsig-name requires --tsig-secret-env, --tsig-secret-file, or --tsig-secret")
		}
	}
	if options.transfer.TSIGSecret != "" && options.transfer.TSIGName == "" {
		return fmt.Errorf("--tsig-secret requires --tsig-name")
	}
	if (options.tsigSecretEnv != "" || options.tsigSecretFile != "") && options.transfer.TSIGName == "" {
		return fmt.Errorf("TSIG secret sources require --tsig-name")
	}
	if options.transfer.TSIGAlgo != "" && options.transfer.TSIGName == "" {
		return fmt.Errorf("--tsig-algorithm requires --tsig-name and --tsig-secret")
	}
	secretSources := 0
	if options.transfer.TSIGSecret != "" {
		secretSources++
	}
	if options.tsigSecretEnv != "" {
		secretSources++
	}
	if options.tsigSecretFile != "" {
		secretSources++
	}
	if secretSources > 1 {
		return fmt.Errorf("choose only one TSIG secret source")
	}
	if options.snapshotLabel != "" && !options.saveSnapshot {
		return fmt.Errorf("--label requires --save")
	}
	if options.saveSnapshot && (options.task == taskAXFR || options.task == taskDNSTransfer || options.remote || options.trace) {
		return fmt.Errorf("zone transfers and remote/path diagnoses cannot be snapshotted")
	}
	if options.saveSnapshot && len(options.enrichments) > 0 {
		return fmt.Errorf("third-party enrichment results cannot be snapshotted; omit --enrich")
	}
	return nil
}

func supportsDNSOptions(task cliTask) bool {
	switch task {
	case taskScan, taskAXFR, taskDNSQuery, taskDNSInventory, taskDNSCompare, taskDNSTrace, taskDNSTransfer, taskDiagnose, taskInvestigate:
		return true
	default:
		return false
	}
}

func isSingleDNSOperation(task cliTask) bool {
	switch task {
	case taskDNSQuery, taskDNSCompare, taskDNSTrace, taskDNSTransfer:
		return true
	default:
		return false
	}
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
	operation := whodis.OperationRegistration
	switch task {
	case taskScan:
		operation = whodis.OperationInspect
	case taskAXFR, taskDNSTransfer:
		operation = whodis.OperationDNSTransfer
	case taskDNSQuery:
		operation = whodis.OperationDNSQuery
	case taskDNSInventory:
		operation = whodis.OperationDNSInventory
	case taskDNSCompare:
		operation = whodis.OperationDNSCompare
	case taskDNSTrace:
		operation = whodis.OperationDNSTrace
	case taskDiagnose:
		operation = whodis.OperationDiagnose
	case taskInvestigate:
		operation = whodis.OperationInvestigate
	}
	for _, input := range inputs {
		if _, err := whodis.ParseSubject(input, operation); err != nil {
			return err
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

func cliOutputWidth(writer io.Writer) int {
	type fileDescriptor interface {
		Fd() uintptr
	}
	output, ok := writer.(fileDescriptor)
	if !ok || !term.IsTerminal(int(output.Fd())) {
		return 0
	}
	width, _, err := term.GetSize(int(output.Fd()))
	if err != nil {
		return 0
	}
	return width
}

func standardInputIsTerminal() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

func openOutput(path string, force bool, stdout io.Writer) (io.Writer, func() error, error) {
	if path == "" || path == "-" {
		return stdout, func() error { return nil }, nil
	}
	if !force {
		if _, err := os.Stat(path); err == nil {
			return nil, func() error { return nil }, fmt.Errorf("could not open %s: file exists (use --force to replace it)", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, func() error { return nil }, fmt.Errorf("could not inspect %s: %w", path, err)
		}
	}
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".whodis-output-*.tmp")
	if err != nil {
		return nil, func() error { return nil }, fmt.Errorf("could not create temporary output beside %s: %w", path, err)
	}
	if err := file.Chmod(0o644); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return nil, func() error { return nil }, fmt.Errorf("could not set output permissions: %w", err)
	}
	output := &atomicOutput{file: file, temporary: file.Name(), destination: path}
	return output, output.commit, nil
}

type atomicOutput struct {
	file        *os.File
	temporary   string
	destination string
	finished    bool
}

func (output *atomicOutput) Write(payload []byte) (int, error) {
	if output == nil || output.file == nil || output.finished {
		return 0, os.ErrClosed
	}
	return output.file.Write(payload)
}

func (output *atomicOutput) commit() error {
	if output == nil || output.finished {
		return nil
	}
	output.finished = true
	if err := output.file.Sync(); err != nil {
		_ = output.file.Close()
		_ = os.Remove(output.temporary)
		return err
	}
	if err := output.file.Close(); err != nil {
		_ = os.Remove(output.temporary)
		return err
	}
	if err := replaceConfigFile(output.temporary, output.destination); err != nil {
		_ = os.Remove(output.temporary)
		return err
	}
	return nil
}

func (output *atomicOutput) abort() {
	if output == nil || output.finished {
		return
	}
	output.finished = true
	_ = output.file.Close()
	_ = os.Remove(output.temporary)
}

func abortOutput(writer io.Writer) {
	if output, ok := writer.(*atomicOutput); ok {
		output.abort()
	}
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
  whodis <target>
  whodis registration <target...>
  whodis inspect <domain...>
  whodis dns query <name> [TYPE...]
  whodis dns inventory <domain...>
  whodis dns compare <name> [TYPE...]
  whodis dns trace <name> [TYPE]
  whodis dns transfer <zone>
  whodis diagnose <domain...>
  whodis investigate <domain...>
  whodis check <target...> [--scrutiny basic|standard|strict]
  whodis snapshot <list|show|remove|export|import|path> ...
  whodis diff <snapshot-a> <snapshot-b>|--live
  whodis expires <target...>
  whodis get <fields> <target...>
  whodis config
  whodis completion bash|zsh|fish|powershell
  whodis help [dns|diagnose|investigate|inspect|expires|get|protocols|formats|advanced]

Targets: domain names, IPv4/IPv6 addresses or CIDRs, and ASNs (AS15169).

Commands:
  (none), registration      automatic RDAP/WHOIS/RWhois registration lookup
  inspect                   registration plus public DNS inventory
  dns query                 arbitrary DNS types/classes through selected resolvers
  dns inventory             practical public record discovery for one or more domains
  dns compare               normalized answers across multiple resolvers
  dns trace                 iterative root-to-authority delegation trace
  dns transfer              explicit AXFR/IXFR, with optional TSIG and TLS
  diagnose                  bounded DNS, web, TLS, mail, and service checks
  investigate               evidence-backed web stack and infrastructure profile
  check                     evaluate live or saved state against health policy
  snapshot                  save and manage secret-free observations
  diff                      compare snapshots or a snapshot with live state
  expires, get              compact registration projections for batch use

Output (use -f/--format or one shortcut):
  dashboard  tree  geekboys  plain  json  yaml  csv  ndjson  markdown  raw

Common options:
  -i, --input <file|->      add newline-delimited targets; - reads standard input
  -o, --output <file|->     write to a file; format is inferred from its extension
  -f, --format <name>       select output format explicitly
  -j, --jobs <count>        concurrent batch lookups (default: 4; range: 1-32)
      --timeout <duration>  request timeout (default: 15s)
      --color <mode>        auto (default), always, or never
      --details             expand notices in visual output
      --summary             summarize notices in visual output
      --force               overwrite an existing output file
      --save                save a reusable, secret-free snapshot
      --label <name>        label a snapshot saved with --save (requires --save)
      --allow-private       allow automatic referrals to private addresses
      --allow-insecure-http allow automatic RDAP over HTTP
  -h, --help                show this help
      --version             show version

Registration routing:
      --server <endpoint>   explicit endpoint; requires rdap, whois, or rwhois
      --strict              do not fall back to another registration protocol
      --try-both            fall back after any protocol error
      --refresh             refresh IANA RDAP service data

DNS:
      --resolver <URI>      repeatable: system, udp/tcp/tls/https/h3/doq or sdns stamp
      --strategy <name>     first, all, fastest, random, or consensus
      --class <CLASS>       named or numeric DNS class (default: IN)
      --dnssec              request DNSSEC records
      --no-dnssec           override a saved DNSSEC default for this command
      --bufsize <bytes>     EDNS UDP payload size (default: 1232)
      --nsid                request EDNS Name Server Identifier
      --ecs <prefix>        send an explicit EDNS Client Subnet
      --cookie <hex>        send an explicit EDNS cookie
      --padding <bytes>     add EDNS padding
      --no-recursion        clear the recursion-desired bit
      --checking-disabled   set the DNSSEC checking-disabled bit
      --globalping          explicitly opt in to remote Globalping DNS probes
      --from <location>     repeatable Globalping location selector
      --limit <count>       Globalping probe limit (1-10; default: 3)

Investigation (explicit third-party enrichment is off by default):
      --enrich otx         query OTX passive DNS for discovered public web addresses
      --related-limit <n>  retain 1-100 related observations (default: 25)
      --research-links <selection>
                           core, all, off, or comma-separated provider IDs
      --investigation-link <template|off>
                           optional custom HTTPS pivot containing {type} and {value}
      --otx-endpoint <url> override the OTX API base URL

Environment:
  WHODIS_FORMAT             default output format when no shortcut or file inference applies
  WHODIS_OTX_API_KEY        optional OTX API key; never saved in Whodis configuration

Examples:
  whodis example.com
  whodis dns query example.com A AAAA MX
  whodis dns compare example.com A --resolver system --resolver https://1.1.1.1/dns-query
  whodis dns trace example.com NS
  whodis diagnose example.com --json
  whodis investigate example.com
  whodis investigate example.com --enrich otx --json
  whodis inspect example.com --tree
  whodis inspect example.com --save --label production
  whodis diff production --live
  whodis check example.com --scrutiny strict
  whodis expires google.com yahoo.com
  whodis get expiration,registrar -i domains.txt -o results.txt
  printf 'google.com\nyahoo.com\n' | whodis expires
  whodis whois example.cc --strict
  whodis rwhois get status 23.228.169.1 --server rwhois.example.net
  whodis -- config
  whodis config
`)
}

func runCompletion(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "whodis: usage: whodis completion bash|zsh|fish|powershell")
		return 2
	}
	commands := "lookup registration inspect dns diagnose investigate check snapshot diff expires get config help completion"
	options := "--format --dashboard --tree --geekboys --plain --json --yaml --csv --ndjson --markdown --raw --output --input --jobs --timeout --color --details --summary --force --save --label --active --passive --against --snapshot --scrutiny --policy --webhook-env --webhook-file --live --allow-snapshot-endpoints --include-ttl --server --strict --try-both --refresh --allow-private --allow-insecure-http --resolver --strategy --class --dnssec --no-dnssec --bufsize --nsid --ecs --cookie --padding --no-recursion --checking-disabled --ixfr --serial --tls --tsig-name --tsig-secret-env --tsig-secret-file --tsig-algorithm --globalping --from --limit --trace --remote --enrich --related-limit --research-links --investigation-link --otx-endpoint --help --version"
	switch strings.ToLower(args[0]) {
	case "bash":
		fmt.Fprintf(stdout, `_whodis_complete() {
  local cur prev
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  if [[ "$prev" == "dns" ]]; then COMPREPLY=( $(compgen -W "query inventory compare trace transfer" -- "$cur") ); return; fi
  if [[ "$cur" == -* ]]; then COMPREPLY=( $(compgen -W %q -- "$cur") ); return; fi
  COMPREPLY=( $(compgen -W %q -- "$cur") )
}
complete -F _whodis_complete whodis
`, options, commands)
	case "zsh":
		fmt.Fprintf(stdout, `#compdef whodis
_arguments '*:argument:->args'
case $state in
  args) _values 'command or option' %s %s ;;
esac
`, strings.ReplaceAll(commands, " ", " "), strings.ReplaceAll(options, " ", " "))
	case "fish":
		for _, command := range strings.Fields(commands) {
			fmt.Fprintf(stdout, "complete -c whodis -f -a %s\n", command)
		}
		for _, option := range strings.Fields(options) {
			fmt.Fprintf(stdout, "complete -c whodis -l %s\n", strings.TrimPrefix(option, "--"))
		}
	case "powershell":
		fmt.Fprintf(stdout, `Register-ArgumentCompleter -Native -CommandName whodis -ScriptBlock {
  param($wordToComplete)
  @(%s) | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
  }
}
`, powershellCompletionValues(append(strings.Fields(commands), strings.Fields(options)...)))
	default:
		fmt.Fprintf(stderr, "whodis: unsupported completion shell %q\n", args[0])
		return 2
	}
	return 0
}

func powershellCompletionValues(values []string) string {
	quoted := make([]string, len(values))
	for index, value := range values {
		quoted[index] = "'" + strings.ReplaceAll(value, "'", "''") + "'"
	}
	return strings.Join(quoted, ",")
}

func printTaskUsage(writer io.Writer, task cliTask) {
	switch task {
	case taskScan:
		fmt.Fprint(writer, `Usage: whodis [rdap|whois|rwhois] inspect <domain> [<domain> ...] [options]

Looks up registration data and public DNS records (A, AAAA, CNAME, MX, NS, TXT, CAA, and more).
Only domain targets are accepted. Use --resolver <host[:port]> to choose the DNS resolver.

Example: whodis inspect example.com --tree
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
	case taskDNSQuery, taskDNSCompare, taskDNSTrace, taskDNSTransfer:
		printDNSUsage(writer)
	case taskDiagnose:
		printDiagnoseUsage(writer)
	case taskInvestigate:
		printInvestigateUsage(writer)
	default:
		printUsage(writer)
	}
}

func printDNSUsage(writer io.Writer) {
	fmt.Fprint(writer, `Usage:
  whodis dns query <name> [TYPE...] [options]
  whodis dns inventory <name> [<name> ...] [options]
  whodis dns compare <name> [TYPE...] [options]
  whodis dns trace <name> [TYPE] [options]
  whodis dns transfer <zone> [options]

Record types and classes may be mnemonics or numbers (for example HTTPS, TYPE65, IN, CLASS1).
Resolver values may be system, a host/IP, udp://, tcp://, tls://, https://, h3://, doq://,
or a DNSCrypt sdns:// stamp.
Repeat --resolver and choose --strategy first|all|fastest|random|consensus.

Transfer options: --ixfr --serial <number> --tls --tsig-name <name>
                  --tsig-secret-env <name>|--tsig-secret-file <path> --tsig-algorithm <name>

Examples:
  whodis dns query example.com A AAAA MX
  whodis dns compare example.com A --resolver 1.1.1.1 --resolver 8.8.8.8 --strategy consensus
  whodis dns trace example.com A
  whodis dns transfer example.com --json
`)
}

func printDiagnoseUsage(writer io.Writer) {
	fmt.Fprint(writer, `Usage: whodis diagnose <domain> [<domain> ...] [options]

Runs bounded checks derived from the domain's published configuration: registration, delegation and
DNS records, representative IPv4/IPv6 HTTPS reachability, HTTP redirects/status, TLS identity and ALPN,
MX SMTP/EHLO/STARTTLS, mail policies, and advertised SRV services. This is not a generic port scanner.

--trace enables optional path work. --remote opts in to configured remote probes; neither is run by default.

Example: whodis diagnose example.com --dashboard
`)
}

func printInvestigateUsage(writer io.Writer) {
	fmt.Fprint(writer, `Usage: whodis investigate <domain> [<domain> ...] [options]

Builds an evidence-backed technology and infrastructure profile from bounded public DNS, HTTP, TLS,
mail, PTR, and IP-registration observations. Network ownership is reported separately from inferred
hosting. Whodis does not run a generic port scan or execute page JavaScript.

Third-party passive DNS is off by default. Use --enrich otx to request AlienVault OTX observations;
WHODIS_OTX_API_KEY is read from the environment when present. Related domains are live-checked and
labelled current, stale, or unknown.

Options:
  --enrich otx                       opt in to OTX passive-DNS enrichment
  --related-limit <1-100>            maximum related observations (default: 25)
  --research-links <selection>       core, all, off, or comma-separated provider IDs
  --investigation-link <template>    optional custom HTTPS pivot containing {type} and {value}, or off
  --otx-endpoint <url>               override the OTX API base URL
  --timeout <duration>               complete investigation budget (default: 30s)

Example: whodis investigate example.com --dashboard
         whodis investigate example.com --research-links all
         whodis investigate example.com --enrich otx --json
`)
	fmt.Fprintln(writer, "\nResearch link providers:")
	for _, provider := range whodis.AvailableInvestigationLinkProviders() {
		fmt.Fprintf(writer, "  %-13s %-4s %s (%s)\n", provider.ID, provider.Tier, provider.Purpose, strings.Join(provider.Targets, ", "))
	}
}

func printProtocolsUsage(writer io.Writer) {
	fmt.Fprint(writer, `Usage: whodis [rdap|whois|rwhois] [command] [target ...] [options]

Routing defaults to automatic selection. Put a protocol before the command to force it:
  whodis rdap example.com
  whodis whois inspect example.com --strict
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
  --csv        CSV with one row per target
  --ndjson     newline-delimited JSON with one report per line
  --markdown   Markdown
  --raw        unmodified source response; one ordinary lookup only

Use -f/--format or exactly one shortcut. Without one, Whodis infers a format from --output, WHODIS_FORMAT,
saved preferences, and whether output is a terminal.
`)
}

func printAdvancedUsage(writer io.Writer) {
	fmt.Fprint(writer, `Advanced options:
  -i, --input <file|->      add newline-delimited targets; - reads standard input
  -o, --output <file|->     write to a file; refuses to overwrite unless --force is used
  -f, --format <name>       dashboard, tree, geekboys, plain, json, yaml, csv, ndjson, markdown, or raw
  -j, --jobs <count>        batch concurrency, from 1 through 32
      --timeout <duration>  per-lookup timeout
      --color <mode>        auto, always, or never
      --details             expand notices in dashboard, tree, and geekboys views
      --summary             summarize notices in those views
      --resolver <URI>      repeatable DNS resolver selection
      --strategy <name>     first, all, fastest, random, or consensus
      --class <CLASS>       DNS query class
      --dnssec              request DNSSEC records through EDNS
      --no-dnssec           disable DNSSEC requests despite a saved default
      --bufsize <bytes>     EDNS UDP payload size
      --nsid                request EDNS NSID
      --ecs <prefix>        explicit EDNS Client Subnet (never automatic)
      --cookie <hex>        explicit EDNS cookie
      --padding <bytes>     EDNS padding
      --no-recursion        clear recursion desired
      --checking-disabled   set the DNSSEC checking-disabled bit
      --globalping          opt in to remote DNS probes (may consume Globalping quota)
      --from <location>     repeatable Globalping location
      --limit <count>       Globalping probe limit, 1-10
      --enrich otx         opt in to passive-DNS enrichment for investigate
      --related-limit <n>  retain 1-100 related observations
      --research-links <selection>
                           core, all, off, or comma-separated provider IDs
      --investigation-link <template|off>
                           optional custom HTTPS pivot containing {type} and {value}
      --otx-endpoint <url> override the OTX API base URL
      --server <endpoint>   explicit server, with rdap/whois/rwhois
      --strict              do not fall back to another registration protocol
      --try-both            fall back after any protocol error
      --refresh             refresh IANA RDAP service data
      --allow-private       allow automatic protocol referrals to private network addresses
      --allow-insecure-http allow automatic RDAP endpoints that use HTTP
      --save                save this passive result as a secret-free snapshot
      --label <name>        assign a unique label to a saved snapshot
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
	case "inspect":
		printTaskUsage(stdout, taskScan)
	case string(taskScan), string(taskAXFR), string(taskExpires), string(taskGet):
		printTaskUsage(stdout, cliTask(args[0]))
	case "dns":
		printDNSUsage(stdout)
	case "diagnose":
		printDiagnoseUsage(stdout)
	case "investigate":
		printInvestigateUsage(stdout)
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
