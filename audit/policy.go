package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Alex9001/whodis/v2"
	"gopkg.in/yaml.v3"
)

type EvaluateOptions struct {
	Scrutiny Scrutiny
	Policy   *Policy
}

// LoadPolicy loads a strict YAML or JSON policy. Unknown fields are rejected.
func LoadPolicy(path string) (Policy, error) {
	payload, err := os.ReadFile(path) // #nosec G304 -- the CLI intentionally loads the user-selected policy file.
	if err != nil {
		return Policy{}, err
	}
	var raw struct {
		SchemaVersion int    `yaml:"policy_schema_version"`
		Name          string `yaml:"name"`
		Rules         []struct {
			ID       string          `yaml:"id"`
			Type     string          `yaml:"type"`
			Severity whodis.Severity `yaml:"severity"`
			Config   map[string]any  `yaml:"config"`
		} `yaml:"rules"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(payload))
	decoder.KnownFields(true)
	if err := decoder.Decode(&raw); err != nil {
		return Policy{}, err
	}
	policy := Policy{SchemaVersion: raw.SchemaVersion, Name: raw.Name}
	for _, rule := range raw.Rules {
		config, err := json.Marshal(rule.Config)
		if err != nil {
			return Policy{}, err
		}
		policy.Rules = append(policy.Rules, Rule{ID: rule.ID, Type: rule.Type, Severity: rule.Severity, Config: config})
	}
	if err := ValidatePolicy(policy); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

func ValidatePolicy(policy Policy) error {
	if policy.SchemaVersion != PolicySchemaVersion {
		return fmt.Errorf("unsupported policy schema %d", policy.SchemaVersion)
	}
	seen := map[string]bool{}
	known := map[string]bool{"minimum_registration_days": true, "required_status": true, "forbidden_status": true, "required_dns_record": true, "expected_nameserver": true, "expected_mx": true, "required_dnssec": true, "minimum_tls_days": true, "maximum_finding_severity": true, "allow_diff_path": true}
	for _, rule := range policy.Rules {
		if strings.TrimSpace(rule.ID) == "" || seen[rule.ID] {
			return fmt.Errorf("policy rule IDs must be non-empty and unique")
		}
		seen[rule.ID] = true
		if !known[rule.Type] {
			return fmt.Errorf("unknown policy rule type %q", rule.Type)
		}
		if rule.Severity != whodis.SeverityInfo && rule.Severity != whodis.SeverityWarning && rule.Severity != whodis.SeverityError {
			return fmt.Errorf("rule %s has invalid severity", rule.ID)
		}
		if err := validateRuleConfig(rule); err != nil {
			return fmt.Errorf("rule %s: %w", rule.ID, err)
		}
	}
	return nil
}

func validateRuleConfig(rule Rule) error {
	var config map[string]any
	if len(rule.Config) > 0 {
		if err := json.Unmarshal(rule.Config, &config); err != nil {
			return fmt.Errorf("config must be an object: %w", err)
		}
	}
	allowed := map[string]bool{}
	requiredString := ""
	requiredNumber := ""
	switch rule.Type {
	case "minimum_registration_days", "minimum_tls_days":
		allowed["days"], requiredNumber = true, "days"
	case "required_status", "forbidden_status", "expected_nameserver", "expected_mx":
		allowed["value"], requiredString = true, "value"
	case "required_dns_record":
		allowed["type"], allowed["value"], requiredString = true, true, "type"
	case "required_dnssec":
		allowed["state"], requiredString = true, "state"
	case "maximum_finding_severity":
		allowed["severity"], requiredString = true, "severity"
	case "allow_diff_path":
		allowed["path"], requiredString = true, "path"
	}
	for key := range config {
		if !allowed[key] {
			return fmt.Errorf("unknown config field %q", key)
		}
	}
	if requiredString != "" {
		value, ok := config[requiredString].(string)
		if !ok || strings.TrimSpace(value) == "" {
			return fmt.Errorf("config.%s must be a non-empty string", requiredString)
		}
	}
	if requiredNumber != "" {
		value, ok := config[requiredNumber].(float64)
		if !ok || value < 0 || value != float64(int(value)) {
			return fmt.Errorf("config.%s must be a non-negative whole number", requiredNumber)
		}
	}
	if rule.Type == "maximum_finding_severity" {
		value := whodis.Severity(strings.ToLower(stringConfig(config, "severity")))
		if value != whodis.SeverityInfo && value != whodis.SeverityWarning && value != whodis.SeverityError {
			return fmt.Errorf("config.severity must be info, warning, or error")
		}
	}
	return nil
}

// Evaluate applies a scrutiny preset and optional custom policy.
func Evaluate(batch whodis.BatchReport, changes *ChangeSet, options EvaluateOptions) (CheckReport, error) {
	if options.Scrutiny == "" {
		options.Scrutiny = ScrutinyStandard
	}
	if options.Scrutiny != ScrutinyBasic && options.Scrutiny != ScrutinyStandard && options.Scrutiny != ScrutinyStrict {
		return CheckReport{}, fmt.Errorf("scrutiny must be basic, standard, or strict")
	}
	if options.Policy != nil {
		if err := ValidatePolicy(*options.Policy); err != nil {
			return CheckReport{}, err
		}
	}
	report := CheckReport{SchemaVersion: CheckSchemaVersion, Scrutiny: options.Scrutiny, EvaluatedAt: time.Now().UTC(), Changes: changes}
	for index, item := range batch.Reports {
		report.Subjects = append(report.Subjects, item.Subject)
		report.Errors = append(report.Errors, item.Errors...)
		report.Results = append(report.Results, attributeRuleResults(evaluateBuiltins(item, options.Scrutiny), index, item.Subject)...)
		if options.Policy != nil {
			report.Results = append(report.Results, attributeRuleResults(evaluateCustom(item, *options.Policy), index, item.Subject)...)
		}
	}
	if changes != nil {
		allowed := allowedDiffPaths(options.Policy)
		for index, change := range changes.Changes {
			if pathAllowed(change.Path, allowed) {
				continue
			}
			report.Results = append(report.Results, RuleResult{RuleID: fmt.Sprintf("change.%d", index+1), Status: CheckFail, Severity: whodis.SeverityWarning, Message: changeSummary(change), Evidence: map[string]string{"path": change.Path}})
		}
		if len(changes.Warnings) > 0 {
			report.Results = append(report.Results, RuleResult{RuleID: "change.completeness", Status: CheckUnknown, Severity: whodis.SeverityWarning, Message: strings.Join(changes.Warnings, "; ")})
		}
	}
	for _, result := range report.Results {
		switch result.Status {
		case CheckPass:
			report.Summary.Passed++
		case CheckFail:
			report.Summary.Failed++
		case CheckUnknown:
			report.Summary.Unknown++
		case CheckSkipped:
			report.Summary.Skipped++
		}
		if result.Severity == whodis.SeverityWarning {
			report.Summary.Warnings++
		}
	}
	return report, nil
}

func attributeRuleResults(results []RuleResult, reportIndex int, subject whodis.Subject) []RuleResult {
	for index := range results {
		itemIndex := reportIndex
		itemSubject := subject
		results[index].ReportIndex = &itemIndex
		results[index].Subject = &itemSubject
	}
	return results
}

func evaluateBuiltins(report whodis.Report, scrutiny Scrutiny) []RuleResult {
	prefix := report.Subject.Canonical + ": "
	var results []RuleResult
	if report.Registration == nil {
		results = append(results, RuleResult{RuleID: "registration.available", Status: CheckUnknown, Severity: whodis.SeverityError, Message: prefix + "registration data is unavailable"})
	} else {
		expiration := expirationTime(report.Registration.Object.Events)
		switch {
		case expiration.IsZero():
			results = append(results, RuleResult{RuleID: "registration.expiration", Status: CheckUnknown, Severity: whodis.SeverityWarning, Message: prefix + "registration expiration was not published"})
		case expiration.Before(time.Now()):
			results = append(results, RuleResult{RuleID: "registration.expiration", Status: CheckFail, Severity: whodis.SeverityError, Message: prefix + "registration is expired", Evidence: map[string]string{"expiration": expiration.Format(time.RFC3339)}})
		default:
			days := int(time.Until(expiration).Hours() / 24)
			severity := whodis.SeverityInfo
			status := CheckPass
			if days < 30 && scrutiny != ScrutinyBasic {
				severity = whodis.SeverityWarning
				if scrutiny == ScrutinyStrict {
					status = CheckFail
				}
			}
			results = append(results, RuleResult{RuleID: "registration.expiration", Status: status, Severity: severity, Message: fmt.Sprintf("%sregistration expires in %d days", prefix, days), Evidence: map[string]string{"expiration": expiration.Format(time.RFC3339)}})
		}
	}
	dns := report.DNS
	if dns == nil && report.Diagnosis != nil {
		dns = report.Diagnosis.DNS
	}
	if dns == nil || dns.Inventory == nil {
		results = append(results, RuleResult{RuleID: "dns.available", Status: CheckUnknown, Severity: whodis.SeverityError, Message: prefix + "DNS inventory is unavailable"})
	} else {
		nameservers := 0
		bogus, secure := false, false
		for _, record := range dns.Inventory.Records {
			if record.Type == "NS" {
				nameservers++
			}
		}
		for _, message := range dns.Messages {
			bogus = bogus || message.DNSSEC == "bogus"
			secure = secure || message.DNSSEC == "secure"
		}
		if nameservers == 0 {
			results = append(results, RuleResult{RuleID: "dns.nameservers", Status: CheckFail, Severity: whodis.SeverityError, Message: prefix + "no authoritative nameserver records were discovered"})
		} else {
			results = append(results, RuleResult{RuleID: "dns.nameservers", Status: CheckPass, Severity: whodis.SeverityInfo, Message: fmt.Sprintf("%s%d authoritative nameserver records discovered", prefix, nameservers)})
		}
		if bogus {
			results = append(results, RuleResult{RuleID: "dns.dnssec", Status: CheckFail, Severity: whodis.SeverityError, Message: prefix + "DNSSEC validation is bogus"})
		} else if secure {
			results = append(results, RuleResult{RuleID: "dns.dnssec", Status: CheckPass, Severity: whodis.SeverityInfo, Message: prefix + "DNSSEC validation succeeded"})
		} else if scrutiny != ScrutinyBasic {
			status := CheckPass
			severity := whodis.SeverityWarning
			if scrutiny == ScrutinyStrict {
				status = CheckFail
			}
			results = append(results, RuleResult{RuleID: "dns.dnssec", Status: status, Severity: severity, Message: prefix + "no secure DNSSEC validation was observed"})
		}
	}
	for _, finding := range reportFindings(report) {
		status := CheckPass
		if finding.Severity == whodis.SeverityError || (scrutiny == ScrutinyStrict && finding.Severity == whodis.SeverityWarning) {
			status = CheckFail
		}
		results = append(results, RuleResult{RuleID: "diagnose." + finding.ID, Status: status, Severity: finding.Severity, Message: prefix + finding.Summary, Evidence: finding.Evidence})
	}
	if report.Diagnosis != nil {
		for _, tlsProbe := range report.Diagnosis.TLS {
			if !tlsProbe.NotAfter.IsZero() && tlsProbe.NotAfter.Before(time.Now()) {
				results = append(results, RuleResult{RuleID: "tls.expiration." + tlsProbe.ServerName, Status: CheckFail, Severity: whodis.SeverityError, Message: prefix + "TLS certificate is expired"})
			}
		}
	}
	return results
}

func evaluateCustom(report whodis.Report, policy Policy) []RuleResult {
	var results []RuleResult
	for _, rule := range policy.Rules {
		if rule.Type == "allow_diff_path" {
			continue
		}
		result := RuleResult{RuleID: rule.ID, Status: CheckUnknown, Severity: rule.Severity, Message: "rule could not be evaluated"}
		var config map[string]any
		_ = json.Unmarshal(rule.Config, &config)
		switch rule.Type {
		case "minimum_registration_days":
			if report.Registration != nil {
				expires := expirationTime(report.Registration.Object.Events)
				minimum := int(numberConfig(config, "days"))
				if !expires.IsZero() {
					days := int(time.Until(expires).Hours() / 24)
					result.Status = CheckPass
					result.Message = fmt.Sprintf("registration lifetime is %d days", days)
					if days < minimum {
						result.Status = CheckFail
					}
				}
			}
		case "required_status", "forbidden_status":
			if report.Registration != nil {
				wanted := stringConfig(config, "value")
				present := containsFold(report.Registration.Object.Status, wanted)
				result.Status = CheckPass
				if (rule.Type == "required_status" && !present) || (rule.Type == "forbidden_status" && present) {
					result.Status = CheckFail
				}
				result.Message = fmt.Sprintf("registration status %q present=%t", wanted, present)
			}
		case "required_dnssec":
			state := strings.ToLower(stringConfig(config, "state"))
			actual := ""
			if report.Registration != nil {
				actual = strings.ToLower(report.Registration.Object.DNSSEC)
			}
			if actual != "" {
				result.Status = CheckPass
				if actual != state {
					result.Status = CheckFail
				}
				result.Message = fmt.Sprintf("DNSSEC state is %s; expected %s", actual, state)
			}
		case "expected_nameserver", "expected_mx", "required_dns_record":
			records := reportRecords(report)
			wantedType := strings.ToUpper(stringConfig(config, "type"))
			if rule.Type == "expected_nameserver" {
				wantedType = "NS"
			}
			if rule.Type == "expected_mx" {
				wantedType = "MX"
			}
			wantedValue := strings.ToLower(stringConfig(config, "value"))
			found := false
			for _, record := range records {
				if record.Type == wantedType && (wantedValue == "" || strings.Contains(strings.ToLower(record.Value), wantedValue)) {
					found = true
				}
			}
			if len(records) > 0 {
				result.Status = CheckPass
				if !found {
					result.Status = CheckFail
				}
				result.Message = fmt.Sprintf("required %s record found=%t", wantedType, found)
			}
		case "minimum_tls_days":
			minimum := int(numberConfig(config, "days"))
			if report.Diagnosis != nil && len(report.Diagnosis.TLS) > 0 {
				result.Status = CheckPass
				result.Message = "TLS certificates satisfy minimum lifetime"
				for _, probe := range report.Diagnosis.TLS {
					if probe.NotAfter.IsZero() || int(time.Until(probe.NotAfter).Hours()/24) < minimum {
						result.Status = CheckFail
						result.Message = "a TLS certificate is below the minimum remaining lifetime"
					}
				}
			}
		case "maximum_finding_severity":
			maximum := severityRank(whodis.Severity(stringConfig(config, "severity")))
			if report.Diagnosis != nil || len(report.Findings) > 0 {
				result.Status = CheckPass
				result.Message = "diagnostic findings are within the severity limit"
				for _, finding := range reportFindings(report) {
					if severityRank(finding.Severity) > maximum {
						result.Status = CheckFail
						result.Message = "a diagnostic finding exceeds the severity limit"
					}
				}
			}
		}
		results = append(results, result)
	}
	return results
}

func reportFindings(report whodis.Report) []whodis.Finding {
	findings := append([]whodis.Finding(nil), report.Findings...)
	if report.Diagnosis != nil {
		findings = append(findings, report.Diagnosis.Findings...)
	}
	seen := make(map[string]bool, len(findings))
	unique := make([]whodis.Finding, 0, len(findings))
	for _, finding := range findings {
		key := finding.ID + "\x00" + string(finding.Severity) + "\x00" + finding.Title + "\x00" + finding.Summary
		if !seen[key] {
			seen[key] = true
			unique = append(unique, finding)
		}
	}
	return unique
}

func expirationTime(events []whodis.Event) time.Time {
	var latest time.Time
	for _, event := range events {
		if !strings.Contains(strings.ToLower(event.Action), "expir") && !strings.Contains(strings.ToLower(event.Action), "expiry") {
			continue
		}
		if value, err := time.Parse(time.RFC3339Nano, event.Date); err == nil && value.After(latest) {
			latest = value
		}
	}
	return latest
}

func reportRecords(report whodis.Report) []whodis.DNSRecord {
	dns := report.DNS
	if dns == nil && report.Diagnosis != nil {
		dns = report.Diagnosis.DNS
	}
	if dns == nil || dns.Inventory == nil {
		return nil
	}
	return dns.Inventory.Records
}

func stringConfig(config map[string]any, key string) string {
	value, _ := config[key].(string)
	return strings.TrimSpace(value)
}

func numberConfig(config map[string]any, key string) float64 {
	value, _ := config[key].(float64)
	return value
}

func containsFold(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(wanted)) {
			return true
		}
	}
	return false
}

func severityRank(severity whodis.Severity) int {
	switch severity {
	case whodis.SeverityError:
		return 3
	case whodis.SeverityWarning:
		return 2
	case whodis.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func allowedDiffPaths(policy *Policy) []string {
	if policy == nil {
		return nil
	}
	var paths []string
	for _, rule := range policy.Rules {
		if rule.Type != "allow_diff_path" {
			continue
		}
		var config map[string]any
		_ = json.Unmarshal(rule.Config, &config)
		if path := stringConfig(config, "path"); path != "" {
			paths = append(paths, path)
		}
	}
	return paths
}

func pathAllowed(path string, patterns []string) bool {
	for _, pattern := range patterns {
		if path == pattern || (strings.HasSuffix(pattern, "*") && strings.HasPrefix(path, strings.TrimSuffix(pattern, "*"))) {
			return true
		}
	}
	return false
}

func SortedResults(results []RuleResult) []RuleResult {
	copyOfResults := append([]RuleResult(nil), results...)
	sort.Slice(copyOfResults, func(left, right int) bool { return copyOfResults[left].RuleID < copyOfResults[right].RuleID })
	return copyOfResults
}
