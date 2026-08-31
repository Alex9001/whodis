package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Alex9001/whodis/v2"
)

type cliArgParser struct {
	args    []string
	index   int
	options cliOptions
}

func parseCLIArgs(args []string) (cliOptions, error) {
	parser := cliArgParser{
		options: cliOptions{
			task: taskLookup, protocol: whodis.ProtocolAuto, fallback: whodis.FallbackUnavailable,
			timeout: 15 * time.Second, color: "auto", jobs: 4,
		},
	}
	remaining, err := parseCommandPrefix(args, &parser.options, parser.appendField)
	if err != nil {
		return parser.options, err
	}
	parser.args = remaining
	if err := parser.parseRemaining(); err != nil {
		return parser.options, err
	}
	parser.finalize()
	if err := validateCLIOptions(parser.options); err != nil {
		return parser.options, err
	}
	return parser.options, nil
}

func (parser *cliArgParser) appendTarget(target string) {
	parser.options.targets = append(parser.options.targets, target)
	parser.options.inputSources = append(parser.options.inputSources, cliInputSource{target: target})
}

func (parser *cliArgParser) appendField(field whodis.ProjectionField) {
	for _, existing := range parser.options.fields {
		if existing == field {
			return
		}
	}
	parser.options.fields = append(parser.options.fields, field)
}

func (parser *cliArgParser) finalize() {
	if len(parser.options.targets) > 0 {
		parser.options.target = parser.options.targets[0]
	}
	if parser.options.task == taskInvestigate && !parser.options.timeoutSet {
		parser.options.timeout = 30 * time.Second
	}
}

func (parser *cliArgParser) parseRemaining() error {
	for parser.index = 0; parser.index < len(parser.args); parser.index++ {
		arg := parser.args[parser.index]
		if arg == "--" {
			for _, target := range parser.args[parser.index+1:] {
				parser.appendTarget(target)
			}
			return nil
		}
		name, inline, hasInline := strings.Cut(arg, "=")
		handled, err := parser.parseOption(name, inline, hasInline)
		if err != nil {
			return err
		}
		if handled {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			return fmt.Errorf("unknown option %s", arg)
		}
		if isSingleDNSOperation(parser.options.task) && parser.options.task != taskDNSTransfer && len(parser.options.targets) > 0 {
			parser.options.recordTypes = append(parser.options.recordTypes, arg)
		} else {
			parser.appendTarget(arg)
		}
	}
	return nil
}

func (parser *cliArgParser) parseOption(name, inline string, hasInline bool) (bool, error) {
	if handled, err := parser.parseGeneralOption(name, inline, hasInline); handled || err != nil {
		return handled, err
	}
	if handled, err := parser.parseFormatOption(name, inline, hasInline); handled || err != nil {
		return handled, err
	}
	if handled, err := parser.parseDNSOption(name, inline, hasInline); handled || err != nil {
		return handled, err
	}
	if handled, err := parser.parseTransferOption(name, inline, hasInline); handled || err != nil {
		return handled, err
	}
	return parser.parseInvestigationOption(name, inline, hasInline)
}

func (parser *cliArgParser) value(name, inline string, hasInline bool) (string, error) {
	if hasInline {
		return inline, nil
	}
	if parser.index+1 >= len(parser.args) {
		return "", fmt.Errorf("%s requires a value", name)
	}
	parser.index++
	return parser.args[parser.index], nil
}

func (parser *cliArgParser) parseGeneralOption(name, inline string, hasInline bool) (bool, error) {
	value := func() (string, error) { return parser.value(name, inline, hasInline) }
	switch name {
	case "-h", "--help":
		parser.options.help = true
	case "--version":
		parser.options.showVersion = true
	case "-o", "--output":
		v, err := value()
		if err != nil {
			return true, err
		}
		parser.options.output = v
	case "-i", "--input":
		v, err := value()
		if err != nil {
			return true, err
		}
		if strings.TrimSpace(v) == "" {
			return true, fmt.Errorf("%s requires a non-empty path", name)
		}
		parser.options.inputSources = append(parser.options.inputSources, cliInputSource{path: v})
	case "-j", "--jobs":
		v, err := value()
		if err != nil {
			return true, err
		}
		jobs, err := strconv.Atoi(v)
		if err != nil || jobs < 1 || jobs > 32 {
			return true, fmt.Errorf("--jobs must be a whole number between 1 and 32")
		}
		parser.options.jobs = jobs
	case "--server":
		v, err := value()
		if err != nil {
			return true, err
		}
		parser.options.server = v
	case "--timeout":
		v, err := value()
		if err != nil {
			return true, err
		}
		duration, err := time.ParseDuration(v)
		if err != nil || duration <= 0 {
			return true, fmt.Errorf("--timeout must be a positive duration")
		}
		parser.options.timeout = duration
		parser.options.timeoutSet = true
	case "--color":
		v, err := value()
		if err != nil {
			return true, err
		}
		parser.options.color, parser.options.colorSet = v, true
	case "--refresh":
		parser.options.refreshBootstrap = true
	case "--allow-private":
		parser.options.allowPrivate = true
	case "--allow-insecure-http":
		parser.options.allowInsecureHTTP = true
	case "--details":
		if parser.options.detailsSet && !parser.options.details {
			return true, fmt.Errorf("--details conflicts with --summary")
		}
		parser.options.details, parser.options.detailsSet = true, true
	case "--summary":
		if parser.options.detailsSet && parser.options.details {
			return true, fmt.Errorf("--summary conflicts with --details")
		}
		parser.options.details, parser.options.detailsSet = false, true
	case "--strict":
		if parser.options.fallbackSet && parser.options.fallback != whodis.FallbackNone {
			return true, fmt.Errorf("--strict conflicts with --try-both")
		}
		parser.options.fallback, parser.options.fallbackSet = whodis.FallbackNone, true
	case "--try-both":
		if parser.options.fallbackSet && parser.options.fallback != whodis.FallbackAnyError {
			return true, fmt.Errorf("--try-both conflicts with --strict")
		}
		parser.options.fallback, parser.options.fallbackSet = whodis.FallbackAnyError, true
	case "--force":
		parser.options.force = true
	case "--save":
		parser.options.saveSnapshot = true
	case "--label":
		v, err := value()
		if err != nil {
			return true, err
		}
		parser.options.snapshotLabel = strings.TrimSpace(v)
	default:
		return false, nil
	}
	return true, nil
}

func (parser *cliArgParser) parseFormatOption(name, inline string, hasInline bool) (bool, error) {
	switch name {
	case "-f", "--format":
		v, err := parser.value(name, inline, hasInline)
		if err != nil {
			return true, err
		}
		if parser.options.formatSet {
			return true, fmt.Errorf("only one output format may be selected")
		}
		if _, err := whodis.ParseFormat(v); err != nil {
			return true, err
		}
		parser.options.format, parser.options.formatSet = v, true
		return true, nil
	case "--dashboard", "--tree", "--geekboys", "--plain", "--json", "--yaml", "--csv", "--ndjson", "--markdown", "--raw":
		if hasInline {
			return true, fmt.Errorf("%s does not take a value", name)
		}
		if parser.options.formatSet {
			return true, fmt.Errorf("only one output format shortcut may be used")
		}
		parser.options.format, parser.options.formatSet = strings.TrimPrefix(name, "--"), true
		return true, nil
	default:
		return false, nil
	}
}

func (parser *cliArgParser) parseDNSOption(name, inline string, hasInline bool) (bool, error) {
	value := func() (string, error) { return parser.value(name, inline, hasInline) }
	switch name {
	case "--resolver":
		v, err := value()
		if err != nil {
			return true, err
		}
		parser.options.dnsResolvers = append(parser.options.dnsResolvers, v)
		if parser.options.dnsResolver == "" {
			parser.options.dnsResolver = v
		}
	case "--class":
		v, err := value()
		if err != nil {
			return true, err
		}
		parser.options.dnsClass = v
	case "--strategy":
		v, err := value()
		if err != nil {
			return true, err
		}
		parser.options.resolverStrategy = whodis.ResolverStrategy(strings.ToLower(v))
	case "--bufsize":
		v, err := value()
		if err != nil {
			return true, err
		}
		n, parseErr := strconv.ParseUint(v, 10, 16)
		if parseErr != nil || n < 512 {
			return true, fmt.Errorf("--bufsize must be between 512 and 65535")
		}
		parser.options.edns.BufferSize = uint16(n)
	case "--dnssec":
		parser.options.edns.DNSSEC = true
		parser.options.dnssecSet = true
	case "--no-dnssec":
		parser.options.edns.DNSSEC = false
		parser.options.dnssecSet = true
	case "--nsid":
		parser.options.edns.NSID = true
	case "--ecs":
		v, err := value()
		if err != nil {
			return true, err
		}
		parser.options.edns.ECS = v
	case "--cookie":
		v, err := value()
		if err != nil {
			return true, err
		}
		parser.options.edns.Cookie = v
	case "--padding":
		v, err := value()
		if err != nil {
			return true, err
		}
		n, parseErr := strconv.ParseUint(v, 10, 16)
		if parseErr != nil {
			return true, fmt.Errorf("--padding must be a whole number")
		}
		parser.options.edns.Padding = uint16(n)
	case "--no-recursion":
		parser.options.noRecursion = true
	case "--checking-disabled":
		parser.options.checkingDisabled = true
	case "--globalping":
		parser.options.globalping = true
	case "--from":
		v, err := value()
		if err != nil {
			return true, err
		}
		parser.options.globalpingFrom = append(parser.options.globalpingFrom, v)
	case "--limit":
		v, err := value()
		if err != nil {
			return true, err
		}
		n, parseErr := strconv.Atoi(v)
		if parseErr != nil || n < 1 || n > 10 {
			return true, fmt.Errorf("--limit must be between 1 and 10")
		}
		parser.options.globalpingLimit = n
	case "--trace":
		parser.options.trace = true
	case "--remote":
		parser.options.remote = true
	default:
		return false, nil
	}
	return true, nil
}

func (parser *cliArgParser) parseTransferOption(name, inline string, hasInline bool) (bool, error) {
	value := func() (string, error) { return parser.value(name, inline, hasInline) }
	switch name {
	case "--ixfr":
		parser.options.transfer.Type = "IXFR"
	case "--serial":
		v, err := value()
		if err != nil {
			return true, err
		}
		n, parseErr := strconv.ParseUint(v, 10, 32)
		if parseErr != nil {
			return true, fmt.Errorf("--serial must be a 32-bit unsigned integer")
		}
		parser.options.transfer.Serial = uint32(n)
	case "--tsig-name":
		v, err := value()
		if err != nil {
			return true, err
		}
		parser.options.transfer.TSIGName = v
	case "--tsig-secret":
		v, err := value()
		if err != nil {
			return true, err
		}
		parser.options.transfer.TSIGSecret = v
	case "--tsig-secret-env":
		v, err := value()
		if err != nil {
			return true, err
		}
		parser.options.tsigSecretEnv = v
	case "--tsig-secret-file":
		v, err := value()
		if err != nil {
			return true, err
		}
		parser.options.tsigSecretFile = v
	case "--tsig-algorithm":
		v, err := value()
		if err != nil {
			return true, err
		}
		parser.options.transfer.TSIGAlgo = v
	case "--tls":
		parser.options.transfer.TLS = true
	default:
		return false, nil
	}
	return true, nil
}

func (parser *cliArgParser) parseInvestigationOption(name, inline string, hasInline bool) (bool, error) {
	value := func() (string, error) { return parser.value(name, inline, hasInline) }
	switch name {
	case "--enrich":
		v, err := value()
		if err != nil {
			return true, err
		}
		parser.options.enrichments = append(parser.options.enrichments, splitCommaValues(v)...)
		if len(parser.options.enrichments) == 0 {
			return true, fmt.Errorf("--enrich requires a provider name")
		}
	case "--related-limit":
		v, err := value()
		if err != nil {
			return true, err
		}
		n, parseErr := strconv.Atoi(v)
		if parseErr != nil || n < 1 || n > 100 {
			return true, fmt.Errorf("--related-limit must be between 1 and 100")
		}
		parser.options.relatedLimit = n
	case "--investigation-link":
		v, err := value()
		if err != nil {
			return true, err
		}
		parser.options.investigationLink = strings.TrimSpace(v)
	case "--research-links":
		v, err := value()
		if err != nil {
			return true, err
		}
		parser.options.linkProviders = splitCommaValues(v)
		if len(parser.options.linkProviders) == 0 {
			return true, fmt.Errorf("--research-links requires core, all, off, or provider IDs")
		}
		parser.options.linkProvidersSet = true
	case "--otx-endpoint":
		v, err := value()
		if err != nil {
			return true, err
		}
		parser.options.otxEndpoint = strings.TrimSpace(v)
	default:
		return false, nil
	}
	return true, nil
}

func validateRegistrationCLIOptions(options cliOptions) error {
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
	return nil
}

func validateDNSCLIOptions(options cliOptions) error {
	if options.dnsResolver != "" && !supportsDNSOptions(options.task) {
		return fmt.Errorf("--resolver is only available with DNS operations, diagnose, or investigate")
	}
	hasDNSQueryOptions := options.dnsClass != "" || options.resolverStrategy != "" || options.edns != (whodis.EDNSOptions{}) ||
		options.dnssecSet || options.noRecursion || options.checkingDisabled || options.globalping
	if hasDNSQueryOptions && !supportsDNSOptions(options.task) {
		return fmt.Errorf("DNS query options require a DNS operation, diagnose, or investigate")
	}
	if (len(options.globalpingFrom) > 0 || options.globalpingLimit > 0) && !options.globalping && !options.remote {
		return fmt.Errorf("--from and --limit require --globalping or diagnose --remote")
	}
	if (options.trace || options.remote) && options.task != taskDiagnose {
		return fmt.Errorf("--trace and --remote require diagnose")
	}
	return nil
}

func validateInvestigationCLIOptions(options cliOptions) error {
	hasInvestigationOptions := len(options.enrichments) > 0 || options.relatedLimit > 0 || options.linkProvidersSet ||
		options.investigationLink != "" || options.otxEndpoint != ""
	if hasInvestigationOptions && options.task != taskInvestigate {
		return fmt.Errorf("--enrich, --related-limit, --research-links, --investigation-link, and --otx-endpoint require investigate")
	}
	for _, provider := range options.enrichments {
		if provider != "otx" {
			return fmt.Errorf("unknown enrichment provider %q; choose otx", provider)
		}
	}
	if options.task != taskInvestigate {
		return nil
	}
	return whodis.ValidateInvestigationOptions(whodis.InvestigationOptions{
		RelatedLimit: options.relatedLimit, LinkProviders: options.linkProviders,
		ExternalLinkTemplate: options.investigationLink, OTXEndpoint: options.otxEndpoint,
	})
}

func validateTransferCLIOptions(options cliOptions) error {
	if options.transfer != (whodis.TransferOptions{}) && options.task != taskDNSTransfer {
		return fmt.Errorf("--ixfr, --serial, --tls, and --tsig-* require dns transfer")
	}
	if options.globalping && options.task != taskDNSQuery && options.task != taskDNSCompare && options.task != taskDiagnose {
		return fmt.Errorf("--globalping requires dns query, dns compare, or diagnose")
	}
	if options.task == taskDNSTransfer && len(options.targets) > 1 {
		return fmt.Errorf("dns transfer accepts one zone at a time")
	}
	if options.transfer.TSIGName != "" && options.transfer.TSIGSecret == "" && options.tsigSecretEnv == "" && options.tsigSecretFile == "" {
		return fmt.Errorf("--tsig-name requires --tsig-secret-env, --tsig-secret-file, or --tsig-secret")
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
	if countTSIGSecretSources(options) > 1 {
		return fmt.Errorf("choose only one TSIG secret source")
	}
	return nil
}

func countTSIGSecretSources(options cliOptions) int {
	count := 0
	for _, value := range []string{options.transfer.TSIGSecret, options.tsigSecretEnv, options.tsigSecretFile} {
		if value != "" {
			count++
		}
	}
	return count
}

func validateSnapshotCLIOptions(options cliOptions) error {
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
