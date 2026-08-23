package whodis

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Engine coordinates independent providers behind one public API.
type Engine struct {
	timeout           time.Duration
	client            *Client
	registration      RegistrationProvider
	dns               DNSProvider
	diagnose          DiagnoseProvider
	investigation     InvestigationProvider
	limits            EngineLimits
	registrationSlots chan struct{}
}

type clientRegistrationProvider struct{ client *Client }

func (provider clientRegistrationProvider) Lookup(ctx context.Context, subject Subject, options LookupOptions) (RegistrationResult, error) {
	target := subject.Canonical
	if subject.RegistrationDomain != "" {
		target = subject.RegistrationDomain
	}
	result, err := provider.client.Lookup(ctx, target, options)
	if err != nil {
		return RegistrationResult{}, err
	}
	return registrationResult(result), nil
}

// NewEngine creates a domain-workstation engine without performing network
// activity. Nil providers are replaced by Whodis's built-in implementations.
func NewEngine(options EngineOptions) *Engine {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	client := options.Client
	if client == nil {
		client = NewClient(ClientOptions{Timeout: timeout, NetworkPolicy: options.NetworkPolicy})
	}
	registration := options.Registration
	if registration == nil {
		registration = clientRegistrationProvider{client: client}
	}
	dns := options.DNS
	if dns == nil {
		dns = newNativeDNSProvider()
	}
	diagnose := options.Diagnose
	if diagnose == nil {
		diagnose = newNativeDiagnoseProvider(dns)
	}
	limits := options.Limits
	if limits.RegistrationConcurrency <= 0 {
		limits.RegistrationConcurrency = 4
	}
	if limits.MaximumBatchItems <= 0 {
		limits.MaximumBatchItems = 10000
	}
	registrationSlots := make(chan struct{}, limits.RegistrationConcurrency)
	investigation := options.Investigation
	if investigation == nil {
		investigation = newNativeInvestigationProvider(dns, registration, options.NetworkPolicy, options.Enrichments, registrationSlots)
	}
	return &Engine{
		timeout: timeout, client: client, registration: registration, dns: dns, diagnose: diagnose, investigation: investigation, limits: limits,
		registrationSlots: registrationSlots,
	}
}

// Close releases reusable transports owned by the engine.
func (engine *Engine) Close() error {
	if engine == nil {
		return nil
	}
	if closer, ok := engine.dns.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
	if engine.client != nil {
		return engine.client.Close()
	}
	return nil
}

// Run performs exactly one requested operation. A successfully returned report
// may contain scoped errors alongside partial results; an error is reserved for
// invalid requests or a canceled/deadline-exceeded operation with no result.
func (engine *Engine) Run(ctx context.Context, request Request) (Report, error) {
	if engine == nil {
		return Report{}, lookupError(ErrorInvalidInput, "engine is nil", nil)
	}
	operation := request.Operation
	if operation == "" {
		operation = OperationRegistration
	}
	subject, err := ParseSubject(request.Target, operation)
	if err != nil {
		return Report{}, err
	}
	timeout := request.Timeout
	if timeout <= 0 {
		timeout = engine.timeout
	}
	runContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	report := Report{SchemaVersion: ReportSchemaVersion, RequestID: request.ID, Operation: operation, Subject: subject, ObservedAt: time.Now().UTC()}
	emit := func(stage string) {
		if request.OnProgress != nil {
			request.OnProgress(ProgressEvent{RequestID: request.ID, Operation: operation, Target: subject.Canonical, Stage: stage})
		}
	}
	emit("started")
	switch operation {
	case OperationRegistration:
		result, lookupErr := engine.lookupRegistration(runContext, subject, request.Registration)
		if lookupErr != nil {
			return Report{}, lookupErr
		}
		report.Registration = &result
	case OperationDNSQuery:
		dnsOptions := request.DNS
		if len(dnsOptions.Types) == 0 && isReverseSubject(subject) {
			dnsOptions.Types = []string{"PTR"}
		}
		report.DNS, err = engine.dns.Query(runContext, subject.Canonical, dnsOptions)
	case OperationDNSInventory:
		report.DNS, err = engine.dns.Inventory(runContext, subject.Canonical, request.DNS)
	case OperationInspect:
		// Registration and DNS are deliberately independent. Inspect remains
		// useful when either the registry or DNS side is unavailable.
		var registration *RegistrationResult
		var dnsResult *DNSOperationResult
		var registrationErr, dnsErr error
		var group sync.WaitGroup
		group.Add(2)
		go func() {
			defer group.Done()
			value, lookupErr := engine.lookupRegistration(runContext, subject, request.Registration)
			if lookupErr != nil {
				registrationErr = lookupErr
				return
			}
			registration = &value
		}()
		go func() {
			defer group.Done()
			dnsResult, dnsErr = engine.dns.Inventory(runContext, subject.RegistrationDomain, request.DNS)
		}()
		group.Wait()
		report.Registration, report.DNS = registration, dnsResult
		report.Errors = appendOperationError(report.Errors, OperationRegistration, "registration", registrationErr)
		report.Errors = appendOperationError(report.Errors, OperationDNSInventory, "dns", dnsErr)
	case OperationDNSCompare:
		report.DNS, err = engine.dns.Compare(runContext, subject.Canonical, request.DNS)
	case OperationDNSTrace:
		report.DNS, err = engine.dns.Trace(runContext, subject.Canonical, request.DNS)
	case OperationDNSTransfer:
		report.DNS, err = engine.dns.Transfer(runContext, subject.Canonical, request.DNS)
	case OperationDiagnose:
		var registration *RegistrationResult
		var diagnosis *DiagnosisReport
		var registrationErr, diagnosisErr error
		var group sync.WaitGroup
		group.Add(2)
		go func() {
			defer group.Done()
			value, lookupErr := engine.lookupRegistration(runContext, subject, request.Registration)
			if lookupErr != nil {
				registrationErr = lookupErr
				return
			}
			registration = &value
		}()
		go func() {
			defer group.Done()
			diagnosis, diagnosisErr = engine.diagnose.Diagnose(runContext, subject.Canonical, request.Diagnose)
		}()
		group.Wait()
		report.Registration, report.Diagnosis = registration, diagnosis
		report.Errors = appendOperationError(report.Errors, OperationRegistration, "registration", registrationErr)
		report.Errors = appendOperationError(report.Errors, OperationDiagnose, "diagnose", diagnosisErr)
		if report.Diagnosis != nil {
			report.Findings = append(report.Findings, report.Diagnosis.Findings...)
			diagnosisValue := *report.Diagnosis
			diagnosisValue.Findings = nil
			report.Diagnosis = &diagnosisValue
		}
	case OperationInvestigate:
		if validationErr := ValidateInvestigationOptions(request.Investigation); validationErr != nil {
			return Report{}, lookupError(ErrorInvalidInput, validationErr.Error(), validationErr)
		}
		var registration *RegistrationResult
		var diagnosis *DiagnosisReport
		var registrationErr, diagnosisErr error
		var group sync.WaitGroup
		group.Add(2)
		go func() {
			defer group.Done()
			value, lookupErr := engine.lookupRegistration(runContext, subject, request.Registration)
			if lookupErr != nil {
				registrationErr = lookupErr
				return
			}
			registration = &value
		}()
		go func() {
			defer group.Done()
			diagnosisOptions := request.Diagnose
			diagnosisOptions.DNS = request.Investigation.DNS
			diagnosis, diagnosisErr = engine.diagnose.Diagnose(runContext, subject.Canonical, diagnosisOptions)
		}()
		group.Wait()
		report.Registration, report.Diagnosis = registration, diagnosis
		report.Errors = appendOperationError(report.Errors, OperationRegistration, "registration", registrationErr)
		report.Errors = appendOperationError(report.Errors, OperationDiagnose, "diagnose", diagnosisErr)
		if report.Diagnosis != nil {
			report.Findings = append(report.Findings, report.Diagnosis.Findings...)
			diagnosisValue := *report.Diagnosis
			diagnosisValue.Findings = nil
			report.Diagnosis = &diagnosisValue
		}
		investigation, investigationErr := engine.investigation.Investigate(runContext, subject, diagnosis, request.Investigation)
		report.Investigation = investigation
		if investigation != nil && len(investigation.ProviderErrors) > 0 {
			report.Errors = append(report.Errors, investigation.ProviderErrors...)
			investigationValue := *investigation
			investigationValue.ProviderErrors = nil
			report.Investigation = &investigationValue
		}
		report.Errors = appendOperationError(report.Errors, OperationInvestigate, "investigate", investigationErr)
	default:
		return Report{}, lookupError(ErrorInvalidInput, "unknown operation "+string(operation), nil)
	}
	if err != nil {
		if report.DNS != nil || report.Diagnosis != nil || report.Investigation != nil {
			report.Errors = appendOperationError(report.Errors, operation, providerForOperation(operation), err)
		} else {
			return Report{}, err
		}
	}
	emit("completed")
	return report, nil
}

// RunBatch performs independent requests with bounded concurrency while
// preserving input order.
func (engine *Engine) RunBatch(ctx context.Context, batch BatchRequest) (BatchReport, error) {
	if engine == nil {
		return BatchReport{}, lookupError(ErrorInvalidInput, "engine is nil", nil)
	}
	if len(batch.Requests) == 0 {
		return BatchReport{}, lookupError(ErrorInvalidInput, "at least one request is required", nil)
	}
	if len(batch.Requests) > engine.limits.MaximumBatchItems {
		return BatchReport{}, lookupError(ErrorInvalidInput, fmt.Sprintf("batch contains %d requests; maximum is %d (use streaming for larger jobs)", len(batch.Requests), engine.limits.MaximumBatchItems), nil)
	}
	workers := batch.Workers
	if workers == 0 {
		workers = defaultBatchWorkers
	}
	if workers < 1 || workers > maximumBatchWorkers {
		return BatchReport{}, lookupError(ErrorInvalidInput, fmt.Sprintf("batch workers must be between 1 and %d", maximumBatchWorkers), nil)
	}
	if workers > len(batch.Requests) {
		workers = len(batch.Requests)
	}
	result := BatchReport{SchemaVersion: ReportSchemaVersion, Reports: make([]Report, len(batch.Requests))}
	jobs := make(chan int)
	type completion struct {
		index  int
		report Report
		err    error
	}
	completed := make(chan completion, len(batch.Requests))
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range jobs {
				request := batch.Requests[index]
				request.OnProgress = nil
				report, err := engine.Run(ctx, request)
				completed <- completion{index: index, report: report, err: err}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for index := range batch.Requests {
			select {
			case jobs <- index:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { group.Wait(); close(completed) }()

	done := 0
	for item := range completed {
		if item.err != nil {
			item.report = failedBatchReport(batch.Requests[item.index], item.err)
		}
		result.Reports[item.index] = item.report
		done++
		if batch.OnProgress != nil {
			batch.OnProgress(ProgressEvent{Operation: item.report.Operation, Target: item.report.Subject.Canonical, Stage: "completed", Completed: done, Total: len(batch.Requests)})
		}
	}
	// If the parent context was canceled before every request could be queued,
	// preserve the one-report-per-request contract instead of returning zero
	// value holes that cannot be associated with their original targets.
	for index, report := range result.Reports {
		if report.SchemaVersion != 0 {
			continue
		}
		canceled := ctx.Err()
		if canceled == nil {
			canceled = context.Canceled
		}
		result.Reports[index] = failedBatchReport(batch.Requests[index], canceled)
	}
	return result, nil
}

// RunStream consumes requests incrementally and emits completed reports in
// completion order. Index preserves input attribution without materializing a
// complete BatchReport.
func (engine *Engine) RunStream(ctx context.Context, requests <-chan Request, options StreamOptions, emit func(StreamItem) error) error {
	if engine == nil {
		return lookupError(ErrorInvalidInput, "engine is nil", nil)
	}
	if requests == nil || emit == nil {
		return lookupError(ErrorInvalidInput, "stream requests and emit callback are required", nil)
	}
	workers := options.Workers
	if workers == 0 {
		workers = defaultBatchWorkers
	}
	if workers < 1 || workers > maximumBatchWorkers {
		return lookupError(ErrorInvalidInput, fmt.Sprintf("stream workers must be between 1 and %d", maximumBatchWorkers), nil)
	}
	streamContext, cancel := context.WithCancel(ctx)
	defer cancel()
	type indexedRequest struct {
		index   int
		request Request
	}
	jobs := make(chan indexedRequest)
	completed := make(chan StreamItem, workers)
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for job := range jobs {
				report, err := engine.Run(streamContext, job.request)
				if err != nil {
					report = failedBatchReport(job.request, err)
				}
				select {
				case completed <- StreamItem{Index: job.index, Report: report}:
				case <-streamContext.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		index := 0
		for {
			select {
			case request, ok := <-requests:
				if !ok {
					return
				}
				select {
				case jobs <- indexedRequest{index: index, request: request}:
					index++
				case <-streamContext.Done():
					return
				}
			case <-streamContext.Done():
				return
			}
		}
	}()
	go func() {
		group.Wait()
		close(completed)
	}()
	for item := range completed {
		if err := emit(item); err != nil {
			cancel()
			for range completed {
			}
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return contextLookupError("stream", err)
	}
	return nil
}

func (engine *Engine) lookupRegistration(ctx context.Context, subject Subject, options LookupOptions) (RegistrationResult, error) {
	select {
	case engine.registrationSlots <- struct{}{}:
		defer func() { <-engine.registrationSlots }()
		return engine.registration.Lookup(ctx, subject, options)
	case <-ctx.Done():
		return RegistrationResult{}, contextLookupError("registration lookup", ctx.Err())
	}
}

func failedBatchReport(request Request, err error) Report {
	operation := request.Operation
	if operation == "" {
		operation = OperationRegistration
	}
	subject, parseErr := ParseSubject(request.Target, operation)
	if parseErr != nil {
		subject = Subject{Original: request.Target, Canonical: strings.TrimSpace(request.Target)}
	}
	return Report{
		SchemaVersion: ReportSchemaVersion,
		RequestID:     request.ID,
		Operation:     operation,
		Subject:       subject,
		ObservedAt:    time.Now().UTC(),
		Errors:        appendOperationError(nil, operation, providerForOperation(operation), err),
	}
}

func appendOperationError(current []OperationError, operation Operation, provider string, err error) []OperationError {
	if err == nil {
		return current
	}
	kind := ErrorUnavailable
	var typed *LookupError
	if errors.As(err, &typed) {
		kind = typed.Kind
	}
	return append(current, OperationError{Operation: operation, Provider: provider, Kind: kind, Message: err.Error()})
}

func providerForOperation(operation Operation) string {
	if operation == OperationRegistration {
		return "registration"
	}
	if operation == OperationInspect {
		return "inspect"
	}
	if operation == OperationDiagnose {
		return "diagnose"
	}
	if operation == OperationInvestigate {
		return "investigate"
	}
	return "dns"
}

func isReverseSubject(subject Subject) bool {
	canonical := strings.ToLower(subject.Canonical)
	return strings.HasSuffix(canonical, ".in-addr.arpa.") || strings.HasSuffix(canonical, ".ip6.arpa.")
}
