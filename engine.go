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
	timeout      time.Duration
	registration RegistrationProvider
	dns          DNSProvider
	diagnose     DiagnoseProvider
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
		client = NewClient(ClientOptions{Timeout: timeout})
	}
	registration := options.Registration
	if registration == nil {
		registration = client
	}
	dns := options.DNS
	if dns == nil {
		dns = newNativeDNSProvider()
	}
	diagnose := options.Diagnose
	if diagnose == nil {
		diagnose = newNativeDiagnoseProvider(dns)
	}
	return &Engine{timeout: timeout, registration: registration, dns: dns, diagnose: diagnose}
}

// Run performs exactly one requested operation. A successfully returned report
// may contain scoped errors alongside partial results; an error is reserved for
// invalid requests or a canceled/deadline-exceeded operation with no result.
func (engine *Engine) Run(ctx context.Context, request Request) (Report, error) {
	if engine == nil {
		return Report{}, lookupError(ErrorInvalidInput, "engine is nil", nil)
	}
	target, err := ParseTarget(request.Target)
	if err != nil {
		return Report{}, err
	}
	operation := request.Operation
	if operation == "" {
		operation = OperationRegistration
	}
	if operation != OperationRegistration && target.Kind != KindDomain {
		return Report{}, lookupError(ErrorInvalidInput, fmt.Sprintf("%s requires a domain target", operation), nil)
	}
	timeout := request.Timeout
	if timeout <= 0 {
		timeout = engine.timeout
	}
	runContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	report := Report{SchemaVersion: ReportSchemaVersion, Operation: operation, Query: target, RetrievedAt: time.Now().UTC()}
	emit := func(stage string) {
		if request.OnProgress != nil {
			request.OnProgress(ProgressEvent{RequestID: request.ID, Operation: operation, Target: target.Canonical, Stage: stage})
		}
	}
	emit("started")
	switch operation {
	case OperationRegistration:
		result, lookupErr := engine.registration.Lookup(runContext, request.Target, request.Registration)
		if lookupErr != nil {
			return Report{}, lookupErr
		}
		report.Registration = &result
	case OperationDNSQuery:
		report.DNS, err = engine.dns.Query(runContext, target.Canonical, request.DNS)
	case OperationDNSInventory:
		// Registration and DNS are deliberately independent here. Inventory
		// remains useful when a registry service is unavailable and vice versa.
		var registration *LookupResult
		var dnsResult *DNSOperationResult
		var registrationErr, dnsErr error
		var group sync.WaitGroup
		group.Add(2)
		go func() {
			defer group.Done()
			value, lookupErr := engine.registration.Lookup(runContext, request.Target, request.Registration)
			if lookupErr != nil {
				registrationErr = lookupErr
				return
			}
			registration = &value
		}()
		go func() {
			defer group.Done()
			dnsResult, dnsErr = engine.dns.Inventory(runContext, target.Canonical, request.DNS)
		}()
		group.Wait()
		report.Registration, report.DNS = registration, dnsResult
		report.Errors = appendOperationError(report.Errors, OperationRegistration, "registration", registrationErr)
		report.Errors = appendOperationError(report.Errors, OperationDNSInventory, "dns", dnsErr)
	case OperationDNSCompare:
		report.DNS, err = engine.dns.Compare(runContext, target.Canonical, request.DNS)
	case OperationDNSTrace:
		report.DNS, err = engine.dns.Trace(runContext, target.Canonical, request.DNS)
	case OperationDNSTransfer:
		report.DNS, err = engine.dns.Transfer(runContext, target.Canonical, request.DNS)
	case OperationDiagnose:
		var registration *LookupResult
		var diagnosis *DiagnosisReport
		var registrationErr, diagnosisErr error
		var group sync.WaitGroup
		group.Add(2)
		go func() {
			defer group.Done()
			value, lookupErr := engine.registration.Lookup(runContext, request.Target, request.Registration)
			if lookupErr != nil {
				registrationErr = lookupErr
				return
			}
			registration = &value
		}()
		go func() {
			defer group.Done()
			diagnosis, diagnosisErr = engine.diagnose.Diagnose(runContext, target.Canonical, request.Diagnose)
		}()
		group.Wait()
		report.Registration, report.Diagnosis = registration, diagnosis
		report.Errors = appendOperationError(report.Errors, OperationRegistration, "registration", registrationErr)
		report.Errors = appendOperationError(report.Errors, OperationDiagnose, "diagnose", diagnosisErr)
		if report.Diagnosis != nil {
			report.Findings = append(report.Findings, report.Diagnosis.Findings...)
		}
	default:
		return Report{}, lookupError(ErrorInvalidInput, "unknown operation "+string(operation), nil)
	}
	if err != nil {
		if report.DNS != nil || report.Diagnosis != nil {
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
	if len(batch.Requests) == 0 {
		return BatchReport{}, lookupError(ErrorInvalidInput, "at least one request is required", nil)
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
			batch.OnProgress(ProgressEvent{Operation: item.report.Operation, Target: item.report.Query.Canonical, Stage: "completed", Completed: done, Total: len(batch.Requests)})
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

func failedBatchReport(request Request, err error) Report {
	target, parseErr := ParseTarget(request.Target)
	if parseErr != nil {
		target = Target{Original: request.Target, Canonical: strings.TrimSpace(request.Target)}
	}
	operation := request.Operation
	if operation == "" {
		operation = OperationRegistration
	}
	return Report{
		SchemaVersion: ReportSchemaVersion,
		Operation:     operation,
		Query:         target,
		RetrievedAt:   time.Now().UTC(),
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
	if operation == OperationDiagnose {
		return "diagnose"
	}
	return "dns"
}
