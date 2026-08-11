package guiapi

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"

	"github.com/Alex9001/whodis"
)

var defaultBatchFields = []whodis.ProjectionField{
	whodis.FieldExpiration,
	whodis.FieldRegistrar,
	whodis.FieldProtocol,
}

func renderExport(batch whodis.BatchResult, params exportParams) (exportResult, error) {
	format := strings.ToLower(strings.TrimSpace(params.Format))
	fields, err := exportFields(params.Fields)
	if err != nil {
		return exportResult{}, err
	}
	var output bytes.Buffer
	switch format {
	case "json":
		err = whodis.RenderBatch(&output, batch, whodis.FormatJSON, whodis.BatchRenderOptions{})
		return exportResult{Content: output.String(), MIME: "application/json", Extension: "json"}, err
	case "plain", "txt":
		err = whodis.RenderBatch(&output, batch, whodis.FormatPlain, whodis.BatchRenderOptions{})
		return exportResult{Content: output.String(), MIME: "text/plain", Extension: "txt"}, err
	case "tsv":
		err = whodis.RenderBatch(&output, batch, whodis.FormatPlain, whodis.BatchRenderOptions{Fields: fields})
		return exportResult{Content: output.String(), MIME: "text/tab-separated-values", Extension: "tsv"}, err
	case "csv":
		err = renderCSV(&output, batch, fields)
		return exportResult{Content: output.String(), MIME: "text/csv", Extension: "csv"}, err
	case "raw":
		err = whodis.RenderBatch(&output, batch, whodis.FormatRaw, whodis.BatchRenderOptions{})
		return exportResult{Content: output.String(), MIME: "text/plain", Extension: "txt"}, err
	default:
		return exportResult{}, fmt.Errorf("unsupported export format %q", params.Format)
	}
}

func renderReportExport(batch whodis.BatchReport, params exportParams) (exportResult, error) {
	format := strings.ToLower(strings.TrimSpace(params.Format))
	var output bytes.Buffer
	var renderFormat whodis.Format
	mime, extension := "text/plain", "txt"
	switch format {
	case "json":
		renderFormat, mime, extension = whodis.FormatJSON, "application/json", "json"
	case "yaml", "yml":
		renderFormat, mime, extension = whodis.FormatYAML, "application/yaml", "yaml"
	case "markdown", "md":
		renderFormat, mime, extension = whodis.FormatMarkdown, "text/markdown", "md"
	case "plain", "txt":
		renderFormat = whodis.FormatPlain
	case "raw":
		renderFormat = whodis.FormatRaw
	case "csv":
		err := renderReportCSV(&output, batch, ',')
		return exportResult{Content: output.String(), MIME: "text/csv", Extension: "csv"}, err
	case "tsv":
		err := renderReportCSV(&output, batch, '\t')
		return exportResult{Content: output.String(), MIME: "text/tab-separated-values", Extension: "tsv"}, err
	default:
		return exportResult{}, fmt.Errorf("unsupported report export format %q", params.Format)
	}
	err := whodis.RenderBatchReport(&output, batch, renderFormat, whodis.RenderOptions{})
	return exportResult{Content: output.String(), MIME: mime, Extension: extension}, err
}

func renderReportCSV(output *bytes.Buffer, batch whodis.BatchReport, comma rune) error {
	writer := csv.NewWriter(output)
	writer.Comma = comma
	if err := writer.Write([]string{"TARGET", "OPERATION", "EXPIRATION", "REGISTRAR", "DNS_RECORDS", "FINDINGS", "ERROR"}); err != nil {
		return err
	}
	for _, report := range batch.Reports {
		expiration, registrar, dnsRecords, findings := "", "", 0, 0
		if report.Registration != nil {
			expiration = strings.Join(eventValues(report.Registration.Object.Events, "expiration", "expiry", "expires"), "; ")
			registrar = report.Registration.Object.Registrar
		}
		if report.DNS != nil {
			dnsRecords = reportDNSRecordCount(report.DNS)
		}
		if report.Diagnosis != nil {
			findings = len(report.Diagnosis.Findings)
			if report.Diagnosis.DNS != nil {
				dnsRecords = reportDNSRecordCount(report.Diagnosis.DNS)
			}
		}
		errorValues := make([]string, 0, len(report.Errors))
		for _, operationError := range report.Errors {
			errorValues = append(errorValues, string(operationError.Kind)+": "+operationError.Message)
		}
		if err := writer.Write([]string{report.Query.Canonical, string(report.Operation), expiration, registrar, fmt.Sprint(dnsRecords), fmt.Sprint(findings), strings.Join(errorValues, "; ")}); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func reportDNSRecordCount(result *whodis.DNSOperationResult) int {
	if result == nil {
		return 0
	}
	seen := make(map[string]bool)
	add := func(records []whodis.DNSRecord) {
		for _, record := range records {
			seen[record.Name+"\x00"+record.Type+"\x00"+record.Value] = true
		}
	}
	if result.Inventory != nil {
		add(result.Inventory.Records)
	}
	if result.Transfer != nil {
		add(result.Transfer.Records)
	}
	for _, message := range result.Messages {
		add(message.Answer)
		add(message.Authority)
		add(message.Additional)
	}
	for _, remote := range result.Remote {
		add(remote.Answers)
	}
	return len(seen)
}

func exportFields(values []string) ([]whodis.ProjectionField, error) {
	if len(values) == 0 {
		return append([]whodis.ProjectionField(nil), defaultBatchFields...), nil
	}
	fields := make([]whodis.ProjectionField, 0, len(values))
	for _, value := range values {
		field, err := whodis.ParseProjectionField(value)
		if err != nil {
			return nil, err
		}
		fields = append(fields, field)
	}
	return fields, nil
}

func renderCSV(output *bytes.Buffer, batch whodis.BatchResult, fields []whodis.ProjectionField) error {
	writer := csv.NewWriter(output)
	headers := []string{"TARGET"}
	for _, field := range fields {
		headers = append(headers, strings.ToUpper(string(field)))
	}
	headers = append(headers, "ERROR")
	if err := writer.Write(headers); err != nil {
		return err
	}
	for _, batchItem := range batch.Items {
		row := []string{batchItem.Input}
		for _, field := range fields {
			values := []string(nil)
			if batchItem.Result != nil {
				values = projectionValues(*batchItem.Result, field)
			}
			row = append(row, strings.Join(values, "; "))
		}
		errorText := ""
		if batchItem.Error != nil {
			errorText = string(batchItem.Error.Kind) + ": " + batchItem.Error.Message
		}
		row = append(row, errorText)
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func projectionValues(result whodis.LookupResult, field whodis.ProjectionField) []string {
	switch field {
	case whodis.FieldExpiration:
		return eventValues(result.Object.Events, "expiration", "expiry", "expires")
	case whodis.FieldRegistration:
		return eventValues(result.Object.Events, "registration", "registered", "creation", "created")
	case whodis.FieldUpdated:
		return eventValues(result.Object.Events, "last changed", "last update", "updated", "changed")
	case whodis.FieldRegistrar:
		return nonEmpty(result.Object.Registrar)
	case whodis.FieldRegistry:
		return nonEmpty(result.Object.Registry)
	case whodis.FieldStatus:
		return result.Object.Status
	case whodis.FieldNameservers:
		return result.Object.Nameservers
	case whodis.FieldDNSSEC:
		return nonEmpty(result.Object.DNSSEC)
	case whodis.FieldProtocol:
		return nonEmpty(string(result.Route.Protocol))
	default:
		return nil
	}
}

func eventValues(events []whodis.Event, actions ...string) []string {
	var values []string
	for _, event := range events {
		for _, action := range actions {
			if strings.EqualFold(strings.TrimSpace(event.Action), action) && strings.TrimSpace(event.Date) != "" {
				values = append(values, strings.TrimSpace(event.Date))
				break
			}
		}
	}
	return values
}

func nonEmpty(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return []string{strings.TrimSpace(value)}
}
