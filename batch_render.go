package whodis

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/mattn/go-runewidth"
	"gopkg.in/yaml.v3"
)

// ParseProjectionField validates a CLI- or UI-facing field name.
func ParseProjectionField(value string) (ProjectionField, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "expiration", "expires", "expiry":
		return FieldExpiration, nil
	case "registration", "registered", "created", "creation":
		return FieldRegistration, nil
	case "updated", "last-changed", "last_changed", "changed":
		return FieldUpdated, nil
	case "registrar":
		return FieldRegistrar, nil
	case "registry":
		return FieldRegistry, nil
	case "status":
		return FieldStatus, nil
	case "nameservers", "name-servers", "name_servers":
		return FieldNameservers, nil
	case "dnssec":
		return FieldDNSSEC, nil
	case "protocol":
		return FieldProtocol, nil
	default:
		return "", fmt.Errorf("unknown field %q", value)
	}
}

// RenderBatch writes a completed batch. Empty Fields preserves complete
// registration results; non-empty Fields activates the compact projection.
func RenderBatch(writer io.Writer, batch BatchResult, format Format, options BatchRenderOptions) error {
	if format == FormatRaw && (len(batch.Items) != 1 || len(options.Fields) > 0) {
		return fmt.Errorf("raw output requires exactly one target without --fields")
	}
	if len(options.Fields) > 0 {
		return renderProjectedBatch(writer, batch, format, options)
	}
	if len(batch.Items) == 1 && batch.Items[0].Result != nil {
		return Render(writer, *batch.Items[0].Result, format, options.RenderOptions)
	}
	return renderCompleteBatch(writer, batch, format, options.RenderOptions)
}

func renderCompleteBatch(writer io.Writer, batch BatchResult, format Format, options RenderOptions) error {
	switch format {
	case FormatJSON:
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(batch)
	case FormatYAML:
		payload, err := yaml.Marshal(batch)
		if err != nil {
			return err
		}
		_, err = writer.Write(payload)
		return err
	case FormatRaw:
		return fmt.Errorf("raw output requires exactly one target")
	}

	for index, item := range batch.Items {
		if index > 0 {
			if _, err := io.WriteString(writer, "\n"); err != nil {
				return err
			}
		}
		if !(format == FormatTree && item.Result != nil) {
			if _, err := io.WriteString(writer, batchSectionHeading(item.Input, format)); err != nil {
				return err
			}
		}
		if item.Error != nil {
			if _, err := io.WriteString(writer, renderBatchError(item.Error, format)); err != nil {
				return err
			}
			continue
		}
		if item.Result == nil {
			if _, err := io.WriteString(writer, "Error: lookup returned no result\n"); err != nil {
				return err
			}
			continue
		}
		if err := Render(writer, *item.Result, format, options); err != nil {
			return err
		}
	}
	return nil
}

func batchSectionHeading(input string, format Format) string {
	input = safeText(input)
	switch format {
	case FormatMarkdown:
		return "## " + input + "\n\n"
	case FormatTree:
		return input + "\n"
	case FormatGeekBoys:
		return "--- " + input + " " + strings.Repeat("-", max(1, 34-runewidth.StringWidth(input))) + "\n"
	case FormatPretty:
		return "┄─ " + input + " " + strings.Repeat("─", max(1, 34-runewidth.StringWidth(input))) + "\n"
	default:
		return "=== " + input + " ===\n"
	}
}

func renderBatchError(err *BatchError, format Format) string {
	if err == nil {
		return ""
	}
	message := safeText(err.Message)
	switch format {
	case FormatMarkdown:
		return "**Error:** `" + markdownCell(string(err.Kind)) + "` — " + markdownCell(message) + "\n"
	case FormatTree:
		return "└── Error [" + string(err.Kind) + "]: " + message + "\n"
	case FormatGeekBoys:
		return "Error [" + string(err.Kind) + "]: " + message + "\n"
	case FormatPretty:
		return "Error [" + string(err.Kind) + "]: " + message + "\n"
	default:
		return "Error [" + string(err.Kind) + "]: " + message + "\n"
	}
}

type projectedBatch struct {
	SchemaVersion int               `json:"schema_version" yaml:"schema_version"`
	Fields        []ProjectionField `json:"fields" yaml:"fields"`
	Items         []projectedItem   `json:"items" yaml:"items"`
}

type projectedItem struct {
	Target string                       `json:"target" yaml:"target"`
	Values map[ProjectionField][]string `json:"values" yaml:"values"`
	Error  *BatchError                  `json:"error,omitempty" yaml:"error,omitempty"`
}

func makeProjectedBatch(batch BatchResult, fields []ProjectionField) projectedBatch {
	projected := projectedBatch{SchemaVersion: 1, Fields: append([]ProjectionField(nil), fields...), Items: make([]projectedItem, len(batch.Items))}
	for index, item := range batch.Items {
		values := make(map[ProjectionField][]string, len(fields))
		for _, field := range fields {
			values[field] = nil
		}
		if item.Result != nil {
			for _, field := range fields {
				values[field] = projectField(*item.Result, field)
			}
		}
		projected.Items[index] = projectedItem{Target: item.Input, Values: values, Error: item.Error}
	}
	return projected
}

func renderProjectedBatch(writer io.Writer, batch BatchResult, format Format, options BatchRenderOptions) error {
	projected := makeProjectedBatch(batch, options.Fields)
	switch format {
	case FormatJSON:
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(projected)
	case FormatYAML:
		payload, err := yaml.Marshal(projected)
		if err != nil {
			return err
		}
		_, err = writer.Write(payload)
		return err
	case FormatMarkdown:
		_, err := io.WriteString(writer, renderProjectedMarkdown(projected))
		return err
	case FormatPlain:
		_, err := io.WriteString(writer, renderProjectedTSV(projected))
		return err
	case FormatTree:
		_, err := io.WriteString(writer, renderProjectedTree(projected))
		return err
	case FormatGeekBoys:
		_, err := io.WriteString(writer, renderProjectedGeekBoys(projected))
		return err
	case FormatPretty:
		_, err := io.WriteString(writer, renderProjectedGrid(projected, options.Width))
		return err
	case FormatRaw:
		return fmt.Errorf("raw output cannot be combined with --fields")
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func projectField(result LookupResult, field ProjectionField) []string {
	object := result.Object
	switch field {
	case FieldExpiration:
		return eventValues(object.Events, "expiration", "expiry", "expires")
	case FieldRegistration:
		return eventValues(object.Events, "registration", "registered", "creation", "created")
	case FieldUpdated:
		return eventValues(object.Events, "last changed", "last update", "updated", "changed")
	case FieldRegistrar:
		return nonEmpty(object.Registrar)
	case FieldRegistry:
		return nonEmpty(object.Registry)
	case FieldStatus:
		return uniqueText(object.Status)
	case FieldNameservers:
		return uniqueText(object.Nameservers)
	case FieldDNSSEC:
		return nonEmpty(object.DNSSEC)
	case FieldProtocol:
		return nonEmpty(string(result.Route.Protocol))
	default:
		return nil
	}
}

func eventValues(events []Event, wanted ...string) []string {
	var values []string
	for _, event := range events {
		for _, action := range wanted {
			if strings.EqualFold(strings.TrimSpace(event.Action), action) && strings.TrimSpace(event.Date) != "" {
				values = appendUnique(values, strings.TrimSpace(event.Date))
				break
			}
		}
	}
	return values
}

func uniqueText(values []string) []string {
	var output []string
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			output = appendUnique(output, value)
		}
	}
	return output
}

func renderProjectedTSV(batch projectedBatch) string {
	var builder strings.Builder
	columns := projectionHeaders(batch.Fields)
	builder.WriteString(strings.Join(columns, "\t"))
	builder.WriteByte('\n')
	for _, item := range batch.Items {
		cells := projectedCells(item, batch.Fields)
		for index, cell := range cells {
			cells[index] = safeText(cell)
		}
		builder.WriteString(strings.Join(cells, "\t"))
		builder.WriteByte('\n')
	}
	return builder.String()
}

func renderProjectedMarkdown(batch projectedBatch) string {
	var builder strings.Builder
	headers := projectionHeaders(batch.Fields)
	builder.WriteString("| " + strings.Join(headers, " | ") + " |\n")
	separator := make([]string, len(headers))
	for index := range separator {
		separator[index] = "---"
	}
	builder.WriteString("| " + strings.Join(separator, " | ") + " |\n")
	for _, item := range batch.Items {
		cells := projectedCells(item, batch.Fields)
		for index, cell := range cells {
			cells[index] = markdownCell(cell)
		}
		builder.WriteString("| " + strings.Join(cells, " | ") + " |\n")
	}
	return builder.String()
}

func renderProjectedTree(batch projectedBatch) string {
	var builder strings.Builder
	for _, item := range batch.Items {
		builder.WriteString(safeText(item.Target) + "\n")
		cells := projectedCells(item, batch.Fields)
		for index, field := range batch.Fields {
			branch := "├──"
			if index == len(batch.Fields)-1 && item.Error == nil {
				branch = "└──"
			}
			fmt.Fprintf(&builder, "%s %s: %s\n", branch, strings.ToUpper(string(field)), safeText(cells[index+1]))
		}
		if item.Error != nil {
			fmt.Fprintf(&builder, "└── ERROR: %s\n", safeText(cells[len(cells)-1]))
		}
	}
	return builder.String()
}

func renderProjectedGeekBoys(batch projectedBatch) string {
	var builder strings.Builder
	for _, item := range batch.Items {
		fmt.Fprintf(&builder, ".--- %s %s+\n", safeText(item.Target), strings.Repeat("-", max(1, 34-runewidth.StringWidth(safeText(item.Target)))))
		cells := projectedCells(item, batch.Fields)
		for index, field := range batch.Fields {
			fmt.Fprintf(&builder, "| %-11s: %s\n", strings.ToUpper(string(field)), safeText(cells[index+1]))
		}
		if item.Error != nil {
			fmt.Fprintf(&builder, "| ERROR      : %s\n", safeText(cells[len(cells)-1]))
		}
		builder.WriteString("+--------------------------------------'\n")
	}
	return builder.String()
}

func renderProjectedGrid(batch projectedBatch, preferredWidth int) string {
	headers := projectionHeaders(batch.Fields)
	rows := make([][]string, len(batch.Items))
	for index, item := range batch.Items {
		rows[index] = projectedCells(item, batch.Fields)
	}
	widths := make([]int, len(headers))
	for index, header := range headers {
		widths[index] = runewidth.StringWidth(header)
	}
	for _, row := range rows {
		for index, cell := range row {
			widths[index] = max(widths[index], runewidth.StringWidth(safeText(cell)))
		}
	}
	limit := preferredWidth
	if limit <= 0 {
		limit = 120
	}
	shrinkGridWidths(widths, limit)

	border := func(left, middle, right, fill string) string {
		parts := make([]string, len(widths))
		for index, width := range widths {
			parts[index] = strings.Repeat(fill, width+2)
		}
		return left + strings.Join(parts, middle) + right + "\n"
	}
	row := func(cells []string) string {
		parts := make([]string, len(cells))
		for index, cell := range cells {
			parts[index] = " " + padGridCell(safeText(cell), widths[index]) + " "
		}
		return "│" + strings.Join(parts, "│") + "│\n"
	}
	var builder strings.Builder
	builder.WriteString(border("╭", "┬", "╮", "─"))
	builder.WriteString(row(headers))
	builder.WriteString(border("├", "┼", "┤", "─"))
	for _, values := range rows {
		builder.WriteString(row(values))
	}
	builder.WriteString(border("╰", "┴", "╯", "─"))
	return builder.String()
}

func projectionHeaders(fields []ProjectionField) []string {
	headers := []string{"TARGET"}
	for _, field := range fields {
		headers = append(headers, strings.ToUpper(string(field)))
	}
	return append(headers, "ERROR")
}

func projectedCells(item projectedItem, fields []ProjectionField) []string {
	cells := []string{item.Target}
	for _, field := range fields {
		cells = append(cells, strings.Join(item.Values[field], "; "))
	}
	if item.Error != nil {
		cells = append(cells, string(item.Error.Kind)+": "+item.Error.Message)
	} else {
		cells = append(cells, "")
	}
	return cells
}

func shrinkGridWidths(widths []int, limit int) {
	for gridWidth(widths) > limit {
		changed := false
		for index := range widths {
			minimum := 8
			if index == 0 {
				minimum = 12
			}
			if widths[index] > minimum && gridWidth(widths) > limit {
				widths[index]--
				changed = true
			}
		}
		if !changed {
			return
		}
	}
}

func gridWidth(widths []int) int {
	width := len(widths) + 1
	for _, column := range widths {
		width += column + 2
	}
	return width
}

func padGridCell(value string, width int) string {
	if runewidth.StringWidth(value) > width {
		if width <= 1 {
			return "…"
		}
		value = runewidth.Truncate(value, width-1, "") + "…"
	}
	return value + strings.Repeat(" ", max(0, width-runewidth.StringWidth(value)))
}
