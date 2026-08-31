package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Alex9001/whodis/v2"
	"github.com/Alex9001/whodis/v2/audit"
	"gopkg.in/yaml.v3"
)

func runAuditCommand(args []string, stdout, stderr io.Writer, runtime cliRuntime) (int, bool) {
	if len(args) == 0 {
		return 0, false
	}
	switch args[0] {
	case "snapshot":
		return runSnapshotCommand(args[1:], stdout, stderr), true
	case "diff":
		return runDiffCommand(args[1:], stdout, stderr), true
	case "check":
		return runCheckCommand(args[1:], stdout, stderr, runtime), true
	default:
		return 0, false
	}
}

func printSnapshotUsage(writer io.Writer) {
	fmt.Fprint(writer, `Usage:
  whodis snapshot list [--json]
  whodis snapshot show <id|label|file>
  whodis snapshot remove <id|label>... --yes
  whodis snapshot export <id|label> -o <file>
  whodis snapshot import <file> [--label <label>]
  whodis snapshot path

Snapshots are local, sanitized observations used by diff and check. They never run in the background.
`)
}

func printDiffUsage(writer io.Writer) {
	fmt.Fprint(writer, `Usage:
  whodis diff <snapshot> <snapshot>
  whodis diff <snapshot> --live [--allow-snapshot-endpoints]

Options: --include-ttl, -f plain|json|yaml|markdown,
         --plain|--json|--yaml|--markdown, -o file, --force
Exit status 5 means material changes; 6 means the comparison was incomplete.
`)
}

func printCheckUsage(writer io.Writer) {
	fmt.Fprint(writer, `Usage: whodis check <target...> [options]

Options: --active|--passive, --against <snapshot>, --snapshot <reference>,
         --scrutiny basic|standard|strict, --policy <file>, --webhook-env <name>,
         --webhook-file <file>, -f plain|json|yaml|markdown,
         --plain|--json|--yaml|--markdown, -o file, --force, --save

Checks evaluate deterministic registration, DNS, diagnostic, change, and custom-policy rules.
`)
}

func saveBatchSnapshot(requests []whodis.Request, batch whodis.BatchReport, label string) (string, error) {
	store, err := audit.NewFileStore("")
	if err != nil {
		return "", err
	}
	snapshot, err := audit.NewSnapshot(requests, batch, audit.GeneratorInfo{Name: "whodis", Version: resolvedVersion()}, label)
	if err != nil {
		return "", err
	}
	if _, err := store.Put(snapshot); err != nil {
		return "", err
	}
	return snapshot.ID, nil
}

func runSnapshotCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printSnapshotUsage(stdout)
		return 0
	}
	store, err := audit.NewFileStore("")
	if err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 1
	}
	switch args[0] {
	case "path":
		fmt.Fprintln(stdout, store.Directory)
		return 0
	case "list":
		if containsArgument(args[1:], "--help") || containsArgument(args[1:], "-h") {
			fmt.Fprintln(stdout, "Usage: whodis snapshot list [--json]")
			return 0
		}
		for _, argument := range args[1:] {
			if argument != "--json" {
				fmt.Fprintln(stderr, "whodis: unknown snapshot list option", argument)
				return 2
			}
		}
		items, err := store.List()
		if err != nil {
			fmt.Fprintln(stderr, "whodis:", err)
			return 1
		}
		if containsArgument(args[1:], "--json") {
			return encodeCommandValue(stdout, items, "json", stderr)
		}
		if len(items) == 0 {
			fmt.Fprintln(stdout, "No snapshots saved.")
			return 0
		}
		fmt.Fprintln(stdout, "ID\tLABEL\tCREATED\tTARGETS\tOPERATIONS")
		for _, item := range items {
			operations := make([]string, len(item.Operations))
			for index, operation := range item.Operations {
				operations[index] = string(operation)
			}
			fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\n", item.ID, item.Label, item.CreatedAt.Local().Format("2006-01-02 15:04"), strings.Join(item.Targets, ","), strings.Join(operations, ","))
		}
		return 0
	case "show":
		if len(args) != 2 {
			fmt.Fprintln(stderr, "whodis: usage: whodis snapshot show <id|label|file>")
			return 2
		}
		snapshot, err := store.Get(args[1])
		if err != nil {
			fmt.Fprintln(stderr, "whodis:", err)
			return 2
		}
		return encodeCommandValue(stdout, snapshot, "json", stderr)
	case "remove":
		yes := containsArgument(args[1:], "--yes")
		refs := withoutArguments(args[1:], "--yes")
		if len(refs) == 0 || !yes {
			fmt.Fprintln(stderr, "whodis: snapshot remove requires one or more references and --yes")
			return 2
		}
		for _, reference := range refs {
			if err := store.Remove(reference); err != nil {
				fmt.Fprintln(stderr, "whodis:", err)
				return 1
			}
			fmt.Fprintln(stdout, "Removed", reference)
		}
		return 0
	case "export":
		if len(args) < 4 || (args[2] != "-o" && args[2] != "--output") {
			fmt.Fprintln(stderr, "whodis: usage: whodis snapshot export <id|label> -o <file>")
			return 2
		}
		snapshot, err := store.Get(args[1])
		if err != nil {
			fmt.Fprintln(stderr, "whodis:", err)
			return 2
		}
		if err := writeProtectedJSON(args[3], snapshot); err != nil {
			fmt.Fprintln(stderr, "whodis:", err)
			return 1
		}
		return 0
	case "import":
		if len(args) < 2 {
			fmt.Fprintln(stderr, "whodis: usage: whodis snapshot import <file> [--label <label>]")
			return 2
		}
		snapshot, err := store.Get(args[1])
		if err != nil {
			fmt.Fprintln(stderr, "whodis:", err)
			return 2
		}
		for index := 2; index < len(args); index++ {
			if args[index] == "--label" && index+1 < len(args) {
				index++
				snapshot.Label = strings.TrimSpace(args[index])
			} else {
				fmt.Fprintln(stderr, "whodis: unknown snapshot import option", args[index])
				return 2
			}
		}
		if _, err := store.Put(snapshot); err != nil {
			fmt.Fprintln(stderr, "whodis:", err)
			return 1
		}
		fmt.Fprintln(stdout, snapshot.ID)
		return 0
	default:
		fmt.Fprintln(stderr, "whodis: unknown snapshot command", args[0])
		return 2
	}
}

type diffCLIOptions struct {
	references             []string
	live                   bool
	includeTTL             bool
	allowSnapshotEndpoints bool
	format                 string
	formatSet              bool
	output                 string
	force                  bool
}

func runDiffCommand(args []string, stdout, stderr io.Writer) int {
	options := diffCLIOptions{format: "plain"}
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--live":
			options.live = true
		case "--include-ttl":
			options.includeTTL = true
		case "--allow-snapshot-endpoints":
			options.allowSnapshotEndpoints = true
		case "--json", "--yaml", "--markdown", "--plain":
			if err := setAuditFormat(&options.format, &options.formatSet, strings.TrimPrefix(args[index], "--")); err != nil {
				fmt.Fprintln(stderr, "whodis:", err)
				return 2
			}
		case "-f", "--format":
			if index+1 >= len(args) {
				fmt.Fprintln(stderr, "whodis: --format requires a value")
				return 2
			}
			index++
			if err := setAuditFormat(&options.format, &options.formatSet, args[index]); err != nil {
				fmt.Fprintln(stderr, "whodis:", err)
				return 2
			}
		case "-o", "--output":
			if index+1 >= len(args) {
				fmt.Fprintln(stderr, "whodis: --output requires a file")
				return 2
			}
			index++
			options.output = args[index]
		case "--force":
			options.force = true
		case "-h", "--help":
			printDiffUsage(stdout)
			return 0
		default:
			if strings.HasPrefix(args[index], "-") {
				fmt.Fprintln(stderr, "whodis: unknown diff option", args[index])
				return 2
			}
			options.references = append(options.references, args[index])
		}
	}
	if (!options.live && len(options.references) != 2) || (options.live && len(options.references) != 1) {
		fmt.Fprintln(stderr, "whodis: diff requires two snapshots, or one snapshot with --live")
		return 2
	}
	if options.allowSnapshotEndpoints && !options.live {
		fmt.Fprintln(stderr, "whodis: --allow-snapshot-endpoints requires --live")
		return 2
	}
	options.format = inferAuditFormat(options.format, options.formatSet, options.output)
	store, err := audit.NewFileStore("")
	if err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 1
	}
	before, err := store.Get(options.references[0])
	if err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 2
	}
	var after audit.Snapshot
	if options.live {
		requests, err := before.RequestsForReplayWithOptions(audit.ReplayOptions{AllowCustomEndpoints: options.allowSnapshotEndpoints})
		if err != nil {
			fmt.Fprintln(stderr, "whodis:", err)
			return 2
		}
		engine := whodis.NewEngine(whodis.EngineOptions{})
		defer engine.Close()
		batch, err := engine.RunBatch(context.Background(), whodis.BatchRequest{Requests: requests, Workers: 4})
		if err != nil {
			fmt.Fprintln(stderr, "whodis:", err)
			return 1
		}
		after, err = audit.NewSnapshot(requests, batch, audit.GeneratorInfo{Name: "whodis", Version: resolvedVersion()}, "")
		if err != nil {
			fmt.Fprintln(stderr, "whodis:", err)
			return 1
		}
	} else {
		after, err = store.Get(options.references[1])
		if err != nil {
			fmt.Fprintln(stderr, "whodis:", err)
			return 2
		}
	}
	changes, err := audit.Diff(before, after, audit.DiffOptions{IncludeTTL: options.includeTTL})
	if err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 2
	}
	if err := writeAuditValue(stdout, options.output, options.format, options.force, changes, renderHumanDiff(changes), renderMarkdownDiff(changes)); err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 1
	}
	if len(changes.Changes) > 0 {
		return 5
	}
	if len(changes.Warnings) > 0 {
		return 6
	}
	return 0
}

type checkCLIOptions struct {
	targets     []string
	active      bool
	activeSet   bool
	against     string
	snapshot    string
	scrutiny    audit.Scrutiny
	scrutinySet bool
	policy      string
	webhook     string
	webhookEnv  string
	webhookFile string
	format      string
	formatSet   bool
	output      string
	force       bool
	timeout     time.Duration
	jobs        int
	save        bool
	label       string
}

func runCheckCommand(args []string, stdout, stderr io.Writer, runtime cliRuntime) int {
	options, help, err := parseCheckCLIOptions(args)
	if err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 2
	}
	if help {
		printCheckUsage(stdout)
		return 0
	}

	config, configExists, err := loadOptionalUserConfig(runtime)
	if err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 1
	}
	applyCheckConfigDefaults(&options, config, configExists)
	if err := validateCheckCLIOptions(options); err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 2
	}
	options.format = inferAuditFormat(options.format, options.formatSet, options.output)

	store, err := audit.NewFileStore("")
	if err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 1
	}
	requests, batch, currentStored, code, err := loadCheckBatch(options, config, configExists, store)
	if err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return code
	}
	changes, err := loadCheckChanges(options.against, requests, batch, currentStored, store)
	if err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 2
	}
	policy, err := loadCheckPolicy(options.policy)
	if err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 2
	}
	check, err := audit.Evaluate(batch, changes, audit.EvaluateOptions{Scrutiny: options.scrutiny, Policy: policy})
	if err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 2
	}
	if code := saveCheckSnapshot(options, requests, batch, stderr); code != 0 {
		return code
	}
	if err := writeAuditValue(stdout, options.output, options.format, options.force, check, renderHumanCheck(check), renderMarkdownCheck(check)); err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 1
	}
	if code := deliverCheckWebhook(options, check, stderr, runtime); code != 0 {
		return code
	}
	return checkExitCode(check)
}

type checkArgParser struct {
	args    []string
	index   int
	options checkCLIOptions
}

func parseCheckCLIOptions(args []string) (checkCLIOptions, bool, error) {
	parser := checkArgParser{
		args: args,
		options: checkCLIOptions{
			scrutiny: audit.ScrutinyStandard, format: "plain",
			timeout: 20 * time.Second, jobs: 4,
		},
	}
	for parser.index = 0; parser.index < len(parser.args); parser.index++ {
		help, err := parser.parseCurrent()
		if err != nil || help {
			return parser.options, help, err
		}
	}
	return parser.options, false, nil
}

func (parser *checkArgParser) parseCurrent() (bool, error) {
	argument := parser.args[parser.index]
	value := func(name string) (string, error) { return parser.value(name) }
	switch argument {
	case "--active":
		if parser.options.activeSet && !parser.options.active {
			return false, fmt.Errorf("--active conflicts with --passive")
		}
		parser.options.active = true
		parser.options.activeSet = true
	case "--passive":
		if parser.options.activeSet && parser.options.active {
			return false, fmt.Errorf("--passive conflicts with --active")
		}
		parser.options.active = false
		parser.options.activeSet = true
	case "--against":
		item, err := value("--against")
		if err != nil {
			return false, err
		}
		parser.options.against = item
	case "--snapshot":
		item, err := value("--snapshot")
		if err != nil {
			return false, err
		}
		parser.options.snapshot = item
	case "--scrutiny":
		item, err := value("--scrutiny")
		if err != nil {
			return false, err
		}
		parser.options.scrutiny = audit.Scrutiny(strings.ToLower(item))
		parser.options.scrutinySet = true
	case "--policy":
		item, err := value("--policy")
		if err != nil {
			return false, err
		}
		parser.options.policy = item
	case "--webhook":
		item, err := value("--webhook")
		if err != nil {
			return false, err
		}
		parser.options.webhook = item
	case "--webhook-env":
		item, err := value("--webhook-env")
		if err != nil {
			return false, err
		}
		parser.options.webhookEnv = item
	case "--webhook-file":
		item, err := value("--webhook-file")
		if err != nil {
			return false, err
		}
		parser.options.webhookFile = item
	case "--json", "--yaml", "--markdown", "--plain":
		format := strings.TrimPrefix(argument, "--")
		if err := setAuditFormat(&parser.options.format, &parser.options.formatSet, format); err != nil {
			return false, err
		}
	case "-f", "--format":
		item, err := value("--format")
		if err != nil {
			return false, err
		}
		if err := setAuditFormat(&parser.options.format, &parser.options.formatSet, item); err != nil {
			return false, err
		}
	case "-o", "--output":
		item, err := value("--output")
		if err != nil {
			return false, err
		}
		parser.options.output = item
	case "--force":
		parser.options.force = true
	case "--timeout":
		item, err := value("--timeout")
		if err != nil {
			return false, err
		}
		duration, err := time.ParseDuration(item)
		if err != nil || duration <= 0 {
			return false, fmt.Errorf("--timeout must be a positive duration")
		}
		parser.options.timeout = duration
	case "-j", "--jobs":
		item, err := value("--jobs")
		if err != nil {
			return false, err
		}
		jobs, err := strconv.Atoi(item)
		if err != nil || jobs < 1 || jobs > 32 {
			return false, fmt.Errorf("--jobs must be between 1 and 32")
		}
		parser.options.jobs = jobs
	case "--save":
		parser.options.save = true
	case "--label":
		item, err := value("--label")
		if err != nil {
			return false, err
		}
		parser.options.label = item
	case "-h", "--help":
		return true, nil
	default:
		if strings.HasPrefix(argument, "-") {
			return false, fmt.Errorf("unknown check option %s", argument)
		}
		parser.options.targets = append(parser.options.targets, argument)
	}
	return false, nil
}

func (parser *checkArgParser) value(name string) (string, error) {
	if parser.index+1 >= len(parser.args) {
		return "", fmt.Errorf("%s requires a value", name)
	}
	parser.index++
	return parser.args[parser.index], nil
}

func applyCheckConfigDefaults(options *checkCLIOptions, config userConfig, exists bool) {
	if !exists {
		return
	}
	if !options.scrutinySet && config.Scrutiny != "" {
		options.scrutiny = audit.Scrutiny(config.Scrutiny)
	}
	if options.snapshot == "" && !options.activeSet && config.CheckActive != nil {
		options.active = *config.CheckActive
	}
}

func validateCheckCLIOptions(options checkCLIOptions) error {
	if options.label != "" && !options.save {
		return fmt.Errorf("--label requires --save")
	}
	if options.snapshot != "" && (len(options.targets) > 0 || options.active) {
		return fmt.Errorf("--snapshot is an offline input and cannot be combined with targets or --active")
	}
	if options.snapshot == "" && len(options.targets) == 0 {
		return fmt.Errorf("check requires targets or --snapshot")
	}
	return nil
}

func loadCheckBatch(options checkCLIOptions, config userConfig, configExists bool, store *audit.FileStore) ([]whodis.Request, whodis.BatchReport, *audit.Snapshot, int, error) {
	if options.snapshot != "" {
		snapshot, err := store.Get(options.snapshot)
		if err != nil {
			return nil, whodis.BatchReport{}, nil, 2, err
		}
		return nil, snapshot.Batch, &snapshot, 0, nil
	}
	if options.active {
		options.timeout = maxDuration(options.timeout, 30*time.Second)
	}
	requests := buildCheckRequests(options, config, configExists)
	engine := whodis.NewEngine(whodis.EngineOptions{Timeout: options.timeout})
	defer engine.Close()
	batch, err := engine.RunBatch(context.Background(), whodis.BatchRequest{Requests: requests, Workers: options.jobs})
	if err != nil {
		return nil, whodis.BatchReport{}, nil, exitCode(err), err
	}
	return requests, batch, nil, 0, nil
}

func buildCheckRequests(options checkCLIOptions, config userConfig, configExists bool) []whodis.Request {
	operation := whodis.OperationInspect
	if options.active {
		operation = whodis.OperationDiagnose
	}
	dnssec := true
	if configExists && config.DNSSEC != nil {
		dnssec = *config.DNSSEC
	}
	dns := whodis.DNSOptions{EDNS: whodis.EDNSOptions{DNSSEC: dnssec}}
	if configExists {
		dns.Resolvers = append([]string(nil), config.DNSResolvers...)
		dns.Strategy = whodis.ResolverStrategy(config.ResolverStrategy)
	}
	requests := make([]whodis.Request, 0, len(options.targets))
	for _, target := range options.targets {
		requests = append(requests, whodis.Request{
			Operation: operation, Target: target, Timeout: options.timeout,
			Registration: whodis.LookupOptions{
				Protocol: whodis.ProtocolAuto, Fallback: whodis.FallbackUnavailable, Timeout: options.timeout,
			},
			DNS: dns, Diagnose: whodis.DiagnoseOptions{DNS: dns, Timeout: options.timeout},
		})
	}
	return requests
}

func loadCheckChanges(against string, requests []whodis.Request, batch whodis.BatchReport, currentStored *audit.Snapshot, store *audit.FileStore) (*audit.ChangeSet, error) {
	if against == "" {
		return nil, nil
	}
	baseline, err := store.Get(against)
	if err != nil {
		return nil, err
	}
	current, err := currentCheckSnapshot(requests, batch, currentStored)
	if err != nil {
		return nil, err
	}
	changes, err := audit.Diff(baseline, current, audit.DiffOptions{})
	if err != nil {
		return nil, err
	}
	return &changes, nil
}

func currentCheckSnapshot(requests []whodis.Request, batch whodis.BatchReport, stored *audit.Snapshot) (audit.Snapshot, error) {
	if stored != nil {
		return *stored, nil
	}
	return audit.NewSnapshot(requests, batch, audit.GeneratorInfo{Name: "whodis", Version: resolvedVersion()}, "")
}

func loadCheckPolicy(path string) (*audit.Policy, error) {
	if path == "" {
		return nil, nil
	}
	policy, err := audit.LoadPolicy(path)
	if err != nil {
		return nil, err
	}
	return &policy, nil
}

func saveCheckSnapshot(options checkCLIOptions, requests []whodis.Request, batch whodis.BatchReport, stderr io.Writer) int {
	if !options.save || len(requests) == 0 {
		return 0
	}
	id, err := saveBatchSnapshot(requests, batch, options.label)
	if err != nil {
		fmt.Fprintln(stderr, "whodis: could not save snapshot:", err)
		return 1
	}
	fmt.Fprintln(stderr, "whodis: saved snapshot", id)
	return 0
}

func deliverCheckWebhook(options checkCLIOptions, check audit.CheckReport, stderr io.Writer, runtime cliRuntime) int {
	webhook, err := resolveWebhook(options, runtime)
	if err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 2
	}
	if webhook == "" || (check.Summary.Failed == 0 && check.Summary.Unknown == 0) {
		return 0
	}
	if err := postCheckWebhook(webhook, check); err != nil {
		fmt.Fprintln(stderr, "whodis: webhook delivery failed:", err)
		return 1
	}
	return 0
}

func checkExitCode(check audit.CheckReport) int {
	if check.Summary.Failed > 0 {
		return 5
	}
	if check.Summary.Unknown > 0 || len(check.Errors) > 0 {
		return 6
	}
	return 0
}
func resolveWebhook(options checkCLIOptions, runtime cliRuntime) (string, error) {
	count := 0
	for _, value := range []string{options.webhook, options.webhookEnv, options.webhookFile} {
		if value != "" {
			count++
		}
	}
	if count > 1 {
		return "", fmt.Errorf("choose only one webhook source")
	}
	if options.webhookEnv != "" {
		value := strings.TrimSpace(runtime.getenv(options.webhookEnv))
		if value == "" {
			return "", fmt.Errorf("webhook environment variable %s is empty", options.webhookEnv)
		}
		return value, nil
	}
	if options.webhookFile != "" {
		payload, err := os.ReadFile(options.webhookFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(payload)), nil
	}
	return strings.TrimSpace(options.webhook), nil
}

func postCheckWebhook(endpoint string, check audit.CheckReport) error {
	payload, err := json.Marshal(check)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "whodis/"+resolvedVersion())
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("server returned %s", response.Status)
	}
	return nil
}

func renderHumanDiff(changes audit.ChangeSet) string {
	var builder strings.Builder
	if len(changes.Changes) == 0 {
		builder.WriteString("No material changes.\n")
	}
	for _, change := range changes.Changes {
		fmt.Fprintf(&builder, "%s\t%s\n", strings.ToUpper(string(change.Kind)), change.Path)
		if len(change.Before) > 0 {
			fmt.Fprintf(&builder, "  before: %s\n", strings.Join(change.Before, "; "))
		}
		if len(change.After) > 0 {
			fmt.Fprintf(&builder, "  after:  %s\n", strings.Join(change.After, "; "))
		}
	}
	for _, warning := range changes.Warnings {
		fmt.Fprintln(&builder, "UNCERTAIN\t"+warning)
	}
	return builder.String()
}

func renderHumanCheck(check audit.CheckReport) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "WHODIS CHECK · %s\n", strings.ToUpper(string(check.Scrutiny)))
	for _, result := range audit.SortedResults(check.Results) {
		fmt.Fprintf(&builder, "%-7s %-8s %s\n", strings.ToUpper(string(result.Status)), strings.ToUpper(string(result.Severity)), result.Message)
	}
	fmt.Fprintf(&builder, "\n%d passed · %d failed · %d unknown · %d warnings\n", check.Summary.Passed, check.Summary.Failed, check.Summary.Unknown, check.Summary.Warnings)
	return builder.String()
}

func renderMarkdownDiff(changes audit.ChangeSet) string {
	var builder strings.Builder
	builder.WriteString("# Whodis semantic diff\n\n")
	if len(changes.Changes) == 0 {
		builder.WriteString("No material changes.\n")
	} else {
		builder.WriteString("| Change | Path | Before | After |\n| --- | --- | --- | --- |\n")
		for _, change := range changes.Changes {
			fmt.Fprintf(&builder, "| %s | `%s` | %s | %s |\n", change.Kind, markdownAuditCell(change.Path), markdownAuditCell(strings.Join(change.Before, "; ")), markdownAuditCell(strings.Join(change.After, "; ")))
		}
	}
	if len(changes.Warnings) > 0 {
		builder.WriteString("\n## Uncertainty\n\n")
		for _, warning := range changes.Warnings {
			fmt.Fprintf(&builder, "- %s\n", warning)
		}
	}
	return builder.String()
}

func renderMarkdownCheck(check audit.CheckReport) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "# Whodis check: %s\n\n", strings.ToUpper(string(check.Scrutiny)))
	builder.WriteString("| Subject | Status | Severity | Rule | Result |\n| --- | --- | --- | --- | --- |\n")
	for _, result := range audit.SortedResults(check.Results) {
		subject := ""
		if result.Subject != nil {
			subject = result.Subject.Canonical
		}
		fmt.Fprintf(&builder, "| %s | %s | %s | `%s` | %s |\n", markdownAuditCell(subject), result.Status, result.Severity, markdownAuditCell(result.RuleID), markdownAuditCell(result.Message))
	}
	fmt.Fprintf(&builder, "\n%d passed · %d failed · %d unknown · %d warnings\n", check.Summary.Passed, check.Summary.Failed, check.Summary.Unknown, check.Summary.Warnings)
	return builder.String()
}

func markdownAuditCell(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(value), "|", "\\|"), "\n", "<br>")
}

func setAuditFormat(format *string, formatSet *bool, value string) error {
	if *formatSet {
		return fmt.Errorf("only one output format may be selected")
	}
	parsed, err := parseAuditFormat(value)
	if err != nil {
		return err
	}
	*format = parsed
	*formatSet = true
	return nil
}

func parseAuditFormat(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "plain", "text", "txt":
		return "plain", nil
	case "json":
		return "json", nil
	case "yaml", "yml":
		return "yaml", nil
	case "markdown", "md":
		return "markdown", nil
	default:
		return "", fmt.Errorf("audit format must be plain, json, yaml, or markdown")
	}
}

func inferAuditFormat(current string, explicitlySet bool, output string) string {
	if explicitlySet || output == "" || output == "-" {
		return current
	}
	extension := strings.TrimPrefix(strings.ToLower(filepath.Ext(output)), ".")
	if format, err := parseAuditFormat(extension); err == nil {
		return format
	}
	return "plain"
}

func writeAuditValue(stdout io.Writer, output, format string, force bool, value any, human, markdown string) error {
	var payload []byte
	var err error
	switch format {
	case "json":
		payload, err = json.MarshalIndent(value, "", "  ")
		payload = append(payload, '\n')
	case "yaml":
		payload, err = yaml.Marshal(value)
	case "markdown":
		payload = []byte(markdown)
	case "plain":
		payload = []byte(human)
	default:
		return fmt.Errorf("unsupported audit format %q", format)
	}
	if err != nil {
		return err
	}
	writer, closeWriter, err := openOutput(output, force, stdout)
	if err != nil {
		return err
	}
	if _, err := writer.Write(payload); err != nil {
		abortOutput(writer)
		return err
	}
	if err := closeWriter(); err != nil {
		return fmt.Errorf("could not finalize output: %w", err)
	}
	return nil
}

func encodeCommandValue(writer io.Writer, value any, format string, stderr io.Writer) int {
	if err := writeAuditValue(writer, "", format, false, value, "", ""); err != nil {
		fmt.Fprintln(stderr, "whodis:", err)
		return 1
	}
	return 0
}

func writeProtectedJSON(path string, value any) error {
	if path == "" || path == "-" {
		return fmt.Errorf("snapshot export requires a file path")
	}
	// #nosec G703 -- snapshot export intentionally accepts a user-selected output path.
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("could not export %s: file exists", path)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("could not inspect %s: %w", path, err)
	}
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".snapshot-export-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			// #nosec G703 -- temporaryPath is captured directly from CreateTemp.
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := replaceConfigFile(temporaryPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func containsArgument(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func withoutArguments(values []string, omitted ...string) []string {
	var result []string
	for _, value := range values {
		if !containsArgument(omitted, value) {
			result = append(result, value)
		}
	}
	return result
}

func maxDuration(left, right time.Duration) time.Duration {
	if left > right {
		return left
	}
	return right
}
