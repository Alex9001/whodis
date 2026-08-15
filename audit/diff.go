package audit

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Alex9001/whodis/v2"
)

// Diff compares two snapshots without performing network activity.
func Diff(before, after Snapshot, options DiffOptions) (ChangeSet, error) {
	if err := validateSnapshot(before); err != nil {
		return ChangeSet{}, err
	}
	if err := validateSnapshot(after); err != nil {
		return ChangeSet{}, err
	}
	result := ChangeSet{
		SchemaVersion: DiffSchemaVersion,
		Before:        SnapshotRef{ID: before.ID, Label: before.Label, CreatedAt: before.CreatedAt},
		After:         SnapshotRef{ID: after.ID, Label: after.Label, CreatedAt: after.CreatedAt},
	}
	same, err := sameScope(before, after)
	if err != nil {
		return ChangeSet{}, err
	}
	if !same {
		result.Warnings = append(result.Warnings, "snapshot request scope or target set differs")
		return result, nil
	}
	left, leftWarnings, leftUncertain := flattenBatch(before, options)
	right, rightWarnings, rightUncertain := flattenBatch(after, options)
	result.Warnings = append(result.Warnings, leftWarnings...)
	result.Warnings = append(result.Warnings, rightWarnings...)
	paths := make(map[string]struct{}, len(left)+len(right))
	for path := range left {
		paths[path] = struct{}{}
	}
	for path := range right {
		paths[path] = struct{}{}
	}
	ordered := make([]string, 0, len(paths))
	for path := range paths {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)
	for _, path := range ordered {
		if pathIsUncertain(path, leftUncertain) || pathIsUncertain(path, rightUncertain) {
			continue
		}
		beforeValues, afterValues := left[path], right[path]
		if equalStrings(beforeValues, afterValues) {
			continue
		}
		kind := ChangeChanged
		if len(beforeValues) == 0 {
			kind = ChangeAdded
		} else if len(afterValues) == 0 {
			kind = ChangeRemoved
		}
		result.Changes = append(result.Changes, Change{Path: path, Kind: kind, Before: beforeValues, After: afterValues})
	}
	result.Warnings = uniqueSorted(result.Warnings)
	return result, nil
}

func sameScope(left, right Snapshot) (bool, error) {
	if len(left.Requests) != len(right.Requests) {
		return false, nil
	}
	for index := range left.Requests {
		leftScope, err := canonicalRequestScope(left.Requests[index])
		if err != nil {
			return false, err
		}
		rightScope, err := canonicalRequestScope(right.Requests[index])
		if err != nil {
			return false, err
		}
		if leftScope != rightScope {
			return false, nil
		}
	}
	return true, nil
}

func canonicalRequestScope(request ReplayRequest) (string, error) {
	subject, err := whodis.ParseSubject(request.Target, request.Operation)
	if err != nil {
		return "", err
	}
	request.Target = subject.Canonical
	request.Timeout = strings.TrimSpace(request.Timeout)
	request.Registration.Server = strings.TrimSpace(request.Registration.Server)
	request.DNS.Types = normalizedUpperValues(request.DNS.Types)
	request.DNS.GlobalpingLocations = uniqueSorted(request.DNS.GlobalpingLocations)
	request.DNS.Resolvers = append([]string(nil), request.DNS.Resolvers...)
	for index := range request.DNS.Resolvers {
		request.DNS.Resolvers[index] = strings.TrimSpace(request.DNS.Resolvers[index])
	}
	if request.DNS.Strategy != whodis.ResolverFirst {
		sort.Strings(request.DNS.Resolvers)
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func normalizedUpperValues(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.ToUpper(strings.TrimSpace(value)); value != "" {
			normalized = append(normalized, value)
		}
	}
	return uniqueSorted(normalized)
}

func flattenBatch(snapshot Snapshot, options DiffOptions) (map[string][]string, []string, map[string]bool) {
	values := make(map[string][]string)
	var warnings []string
	uncertain := make(map[string]bool)
	for _, report := range snapshot.Batch.Reports {
		key := escapePath(report.Subject.Canonical) + "/" + escapePath(string(report.Operation))
		blocked := map[string]bool{}
		for _, operationError := range report.Errors {
			warnings = append(warnings, fmt.Sprintf("%s %s was incomplete: %s", report.Subject.Canonical, operationError.Provider, operationError.Message))
			switch operationError.Provider {
			case "registration":
				blocked["registration"] = true
			case "dns":
				blocked["dns"] = true
			case "diagnose":
				blocked["diagnosis"] = true
				blocked["findings"] = true
			}
		}
		encoded, _ := json.Marshal(report)
		var document map[string]any
		_ = json.Unmarshal(encoded, &document)
		delete(document, "schema_version")
		delete(document, "request_id")
		delete(document, "observed_at")
		delete(document, "errors")
		delete(document, "subject")
		delete(document, "operation")
		for section := range blocked {
			delete(document, section)
			uncertain["/reports/"+key+"/"+escapePath(section)] = true
		}
		flattenValue(values, "/reports/"+key, document, options)
	}
	for path := range values {
		values[path] = uniqueSorted(values[path])
	}
	return values, warnings, uncertain
}

func pathIsUncertain(path string, prefixes map[string]bool) bool {
	for prefix := range prefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

func flattenValue(destination map[string][]string, path string, value any, options DiffOptions) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			if ignoredDiffKey(key, options) {
				continue
			}
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			flattenValue(destination, path+"/"+escapePath(key), typed[key], options)
		}
	case []any:
		for _, item := range typed {
			encoded, _ := json.Marshal(normalizeJSON(item, options))
			destination[path] = append(destination[path], string(encoded))
		}
	case nil:
	default:
		destination[path] = append(destination[path], fmt.Sprint(typed))
	}
}

func normalizeJSON(value any, options DiffOptions) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any)
		for key, item := range typed {
			if !ignoredDiffKey(key, options) {
				result[key] = normalizeJSON(item, options)
			}
		}
		return result
	case []any:
		items := make([]any, len(typed))
		for index, item := range typed {
			items[index] = normalizeJSON(item, options)
		}
		sort.Slice(items, func(left, right int) bool {
			leftJSON, _ := json.Marshal(items[left])
			rightJSON, _ := json.Marshal(items[right])
			return string(leftJSON) < string(rightJSON)
		})
		return items
	default:
		return value
	}
}

func ignoredDiffKey(key string, options DiffOptions) bool {
	switch key {
	case "duration_ns", "id", "raw", "request_id", "observed_at", "retrieved_at":
		return true
	case "ttl":
		return !options.IncludeTTL
	default:
		return false
	}
}

func escapePath(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func changeSummary(change Change) string {
	return string(change.Kind) + " " + change.Path + " (" + strconv.Itoa(len(change.Before)) + " → " + strconv.Itoa(len(change.After)) + ")"
}
