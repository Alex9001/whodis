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
