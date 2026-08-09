package whodis

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// Format is an output representation for a LookupResult.
type Format string

const (
	FormatPretty   Format = "pretty"
	FormatPlain    Format = "plain"
	FormatJSON     Format = "json"
	FormatYAML     Format = "yaml"
	FormatMarkdown Format = "markdown"
	FormatRaw      Format = "raw"
)

// RenderOptions changes presentation only; it never changes lookup behavior.
type RenderOptions struct {
	Color string
	Width int
}

// ParseFormat validates a CLI-facing output format. text and txt are friendly
// aliases for plain.
func ParseFormat(value string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "pretty", "":
		return FormatPretty, nil
	case "plain", "text", "txt":
		return FormatPlain, nil
	case "json":
		return FormatJSON, nil
	case "yaml", "yml":
		return FormatYAML, nil
	case "markdown", "md":
		return FormatMarkdown, nil
	case "raw":
		return FormatRaw, nil
	default:
		return "", fmt.Errorf("unknown format %q", value)
	}
}

// Render writes one successful result in the requested format.
func Render(writer io.Writer, result LookupResult, format Format, options RenderOptions) error {
	switch format {
	case FormatJSON:
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	case FormatYAML:
		payload, err := yaml.Marshal(result)
		if err != nil {
			return err
		}
		_, err = writer.Write(payload)
		return err
	case FormatMarkdown:
		_, err := io.WriteString(writer, renderMarkdown(result))
		return err
	case FormatRaw:
		if len(result.Sources) == 0 {
			return fmt.Errorf("lookup contains no raw source")
		}
		_, err := io.WriteString(writer, result.Sources[len(result.Sources)-1].Raw)
		return err
	case FormatPlain:
		_, err := io.WriteString(writer, renderPlain(result))
		return err
	case FormatPretty:
		_, err := io.WriteString(writer, renderPretty(result, options))
		return err
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func renderPlain(result LookupResult) string {
	var builder strings.Builder
	line := func(label, value string) {
		if value != "" {
			fmt.Fprintf(&builder, "%s: %s\n", label, safeText(value))
		}
	}
	line("Query", result.Query.Canonical)
	line("Kind", string(result.Query.Kind))
	line("Protocol", string(result.Route.Protocol))
	line("Authority", result.Route.Endpoint)
	line("Discovery", result.Route.DiscoverySource)
	if result.FallbackFrom != nil {
		line("Fallback from", string(result.FallbackFrom.Protocol)+" at "+result.FallbackFrom.Endpoint)
	}
	line("Retrieved", result.RetrievedAt.Format("2006-01-02T15:04:05Z"))

	object := result.Object
	line("Name", object.Name)
	line("Unicode name", object.UnicodeName)
	line("Handle", object.Handle)
	line("Registrar", object.Registrar)
	line("Registry", object.Registry)
	line("DNSSEC", object.DNSSEC)
	line("Network", object.NetworkType)
	line("Range start", object.StartAddress)
	line("Range end", object.EndAddress)
	line("CIDR", strings.Join(object.CIDR, ", "))
	line("Country", object.Country)
	line("ASN", object.ASN)
	line("ASN name", object.ASNName)
	line("ASN type", object.ASNType)
	if len(object.Status) > 0 {
		line("Status", strings.Join(object.Status, ", "))
	}
	if len(object.Nameservers) > 0 {
		line("Nameservers", strings.Join(object.Nameservers, ", "))
	}
	for _, event := range object.Events {
		line("Event "+event.Action, event.Date)
	}
	for _, entity := range object.Entities {
		value := firstNonEmpty(entity.Name, entity.Organization, entity.Email, entity.Phone)
		line("Contact "+strings.Join(entity.Roles, "/"), value)
	}
	if len(object.Notices) > 0 {
		for _, notice := range object.Notices {
			line("Notice "+notice.Title, strings.Join(notice.Description, " "))
		}
	}
	if len(object.Extras) > 0 {
		keys := sortedKeys(object.Extras)
		for _, key := range keys {
			line("Extra "+key, strings.Join(object.Extras[key], "; "))
		}
	}
	return builder.String()
}

func renderMarkdown(result LookupResult) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "# Whodis lookup: `%s`\n\n", safeText(result.Query.Canonical))
	builder.WriteString("| Field | Value |\n| --- | --- |\n")
	rows := basicRows(result)
	for _, row := range rows {
		fmt.Fprintf(&builder, "| %s | %s |\n", markdownCell(row[0]), markdownCell(row[1]))
	}
	if len(result.Object.Events) > 0 {
		builder.WriteString("\n## Events\n\n| Action | Date |\n| --- | --- |\n")
		for _, event := range result.Object.Events {
			fmt.Fprintf(&builder, "| %s | %s |\n", markdownCell(event.Action), markdownCell(event.Date))
		}
	}
	if len(result.Object.Nameservers) > 0 {
		builder.WriteString("\n## Nameservers\n\n")
		for _, ns := range result.Object.Nameservers {
			fmt.Fprintf(&builder, "- `%s`\n", safeText(ns))
		}
	}
	return builder.String()
}

func renderPretty(result LookupResult, options RenderOptions) string {
	color := useColor(options.Color)
	width := options.Width
	if width <= 0 {
		width = terminalWidth()
	}
	if width < 54 {
		width = 54
	}
	if width > 120 {
		width = 120
	}
	var builder strings.Builder
	title := "WHODIS · " + strings.ToUpper(string(result.Query.Kind)) + " LOOKUP"
	if color {
		title = paint(title, "38;5;81", "", "1")
	}
	builder.WriteString(title + "\n")
	builder.WriteString(renderGrid(gridRows(result), width, color))
	return builder.String()
}

type gridRow struct{ section, field, value string }

func gridRows(result LookupResult) []gridRow {
	object := result.Object
	rows := []gridRow{
		{"Lookup", "Query", result.Query.Canonical},
		{"", "Protocol", string(result.Route.Protocol)},
		{"", "Authority", result.Route.Endpoint},
		{"", "Discovery", result.Route.DiscoverySource},
		{"", "Retrieved", result.RetrievedAt.Format("2006-01-02 15:04:05 UTC")},
	}
	if result.FallbackFrom != nil {
		rows = append(rows, gridRow{"", "Fallback", string(result.FallbackFrom.Protocol) + " → " + string(result.Route.Protocol)})
	}
	registration := [][2]string{
		{"Name", object.Name}, {"Unicode name", object.UnicodeName}, {"Handle", object.Handle}, {"Registrar", object.Registrar}, {"Registry", object.Registry},
		{"Status", strings.Join(object.Status, ", ")}, {"DNSSEC", object.DNSSEC}, {"Network", object.NetworkType}, {"Range", joinRange(object.StartAddress, object.EndAddress)},
		{"CIDR", strings.Join(object.CIDR, ", ")}, {"Country", object.Country}, {"ASN", object.ASN}, {"ASN name", object.ASNName}, {"ASN type", object.ASNType},
	}
	first := true
	for _, row := range registration {
		if row[1] == "" {
			continue
		}
		section := ""
		if first {
			section, first = "Registration", false
		}
		rows = append(rows, gridRow{section, row[0], row[1]})
	}
	for _, event := range object.Events {
		rows = append(rows, gridRow{"Events", event.Action, event.Date})
	}
	for _, name := range object.Nameservers {
		rows = append(rows, gridRow{"Nameservers", "Nameserver", name})
	}
	for _, entity := range object.Entities {
		rows = append(rows, gridRow{"Contacts", strings.Join(entity.Roles, "/"), strings.Join(nonEmpty(entity.Name, entity.Organization, entity.Email, entity.Phone), " · ")})
	}
	for _, notice := range object.Notices {
		rows = append(rows, gridRow{"Notices", notice.Title, strings.Join(notice.Description, " ")})
	}
	return rows
}

func renderGrid(rows []gridRow, width int, color bool) string {
	sectionWidth, fieldWidth := 16, 20
	if width < 74 {
		sectionWidth, fieldWidth = 12, 15
	}
	valueWidth := width - sectionWidth - fieldWidth - 10
	if valueWidth < 14 {
		valueWidth = 14
	}
	border := func(left, middle, right string) string {
		return left + strings.Repeat("─", sectionWidth+2) + middle + strings.Repeat("─", fieldWidth+2) + middle + strings.Repeat("─", valueWidth+2) + right + "\n"
	}
	cell := func(value string, cellWidth int, header bool) string {
		value = padCell(value, cellWidth)
		if header && color {
			return paint(value, "38;5;230", "48;5;24", "1")
		}
		return value
	}
	var builder strings.Builder
	builder.WriteString(border("┌", "┬", "┐"))
	fmt.Fprintf(&builder, "│ %s │ %s │ %s │\n", cell("SECTION", sectionWidth, true), cell("FIELD", fieldWidth, true), cell("VALUE", valueWidth, true))
	builder.WriteString(border("├", "┼", "┤"))
	for index, row := range rows {
		sections, fields, values := wrapText(safeText(row.section), sectionWidth), wrapText(safeText(row.field), fieldWidth), wrapText(safeText(row.value), valueWidth)
		lines := max(len(sections), max(len(fields), len(values)))
		for line := 0; line < lines; line++ {
			section, field, value := "", "", ""
			if line < len(sections) {
				section = sections[line]
			}
			if line < len(fields) {
				field = fields[line]
			}
			if line < len(values) {
				value = values[line]
			}
			fmt.Fprintf(&builder, "│ %s │ %s │ %s │\n", cell(section, sectionWidth, false), cell(field, fieldWidth, false), cell(value, valueWidth, false))
		}
		if index < len(rows)-1 {
			builder.WriteString(border("├", "┼", "┤"))
		}
	}
	builder.WriteString(border("└", "┴", "┘"))
	return builder.String()
}

func padCell(value string, width int) string {
	if len(value) > width {
		value = value[:width]
	}
	return value + strings.Repeat(" ", width-len(value))
}

func basicRows(result LookupResult) [][2]string {
	object := result.Object
	rows := [][2]string{
		{"query", result.Query.Canonical}, {"protocol", string(result.Route.Protocol)}, {"authority", result.Route.Endpoint},
		{"discovery", result.Route.DiscoverySource}, {"retrieved", result.RetrievedAt.Format("2006-01-02 15:04:05 UTC")},
	}
	if result.FallbackFrom != nil {
		rows = append(rows, [2]string{"fallback", string(result.FallbackFrom.Protocol) + " → " + string(result.Route.Protocol)})
	}
	rows = append(rows,
		[2]string{"name", object.Name}, [2]string{"unicode name", object.UnicodeName}, [2]string{"handle", object.Handle},
		[2]string{"registrar", object.Registrar}, [2]string{"registry", object.Registry}, [2]string{"status", strings.Join(object.Status, ", ")},
		[2]string{"dnssec", object.DNSSEC}, [2]string{"network", object.NetworkType}, [2]string{"range", joinRange(object.StartAddress, object.EndAddress)},
		[2]string{"cidr", strings.Join(object.CIDR, ", ")}, [2]string{"country", object.Country}, [2]string{"asn", object.ASN},
		[2]string{"asn name", object.ASNName}, [2]string{"asn type", object.ASNType},
	)
	filtered := rows[:0]
	for _, row := range rows {
		if row[1] != "" {
			filtered = append(filtered, row)
		}
	}
	return filtered
}

func prettySection(builder *strings.Builder, title string, rows [][2]string, width int, color bool) {
	if len(rows) == 0 {
		return
	}
	label := " " + strings.ToUpper(title) + " "
	if color {
		label = paint(label, "38;5;81", "", "1")
	}
	builder.WriteString("\n" + label + "\n")
	maxLabel := 0
	for _, row := range rows {
		if len(row[0]) > maxLabel {
			maxLabel = len(row[0])
		}
	}
	if maxLabel > 18 {
		maxLabel = 18
	}
	for _, row := range rows {
		label := safeText(row[0])
		if len(label) > maxLabel {
			label = label[:maxLabel-1] + "…"
		}
		value := safeText(row[1])
		available := width - maxLabel - 5
		if available < 16 {
			available = 16
		}
		chunks := wrapText(value, available)
		for index, chunk := range chunks {
			if index == 0 {
				if color {
					label = paint(label, "38;5;110", "", "1")
				}
				fmt.Fprintf(builder, "  %-*s  %s\n", maxLabel, label, chunk)
			} else {
				fmt.Fprintf(builder, "  %-*s  %s\n", maxLabel, "", chunk)
			}
		}
	}
}

func terminalWidth() int {
	if columns, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && columns > 0 {
		return columns
	}
	return 80
}

func useColor(choice string) bool {
	if choice == "always" {
		return true
	}
	if choice == "never" || os.Getenv("NO_COLOR") != "" {
		return false
	}
	info, err := os.Stdout.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func paint(text, foreground, background, attribute string) string {
	parts := nonEmpty(attribute, foreground, background)
	if len(parts) == 0 {
		return text
	}
	return "\x1b[" + strings.Join(parts, ";") + "m" + text + "\x1b[0m"
}

func safeText(value string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(value))
}

func wrapText(value string, width int) []string {
	if value == "" {
		return []string{""}
	}
	words := strings.Fields(value)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	line := ""
	for _, word := range words {
		for len(word) > width {
			if line != "" {
				lines = append(lines, line)
				line = ""
			}
			lines = append(lines, word[:width])
			word = word[width:]
		}
		if line == "" {
			line = word
			continue
		}
		if len(line)+1+len(word) <= width {
			line += " " + word
			continue
		}
		lines = append(lines, line)
		line = word
	}
	return append(lines, line)
}

func padVisible(value string, width int) string {
	plain := stripANSI(value)
	if len(plain) >= width {
		return value
	}
	return value + strings.Repeat(" ", width-len(plain))
}

func stripANSI(value string) string {
	for {
		start := strings.Index(value, "\x1b[")
		if start < 0 {
			return value
		}
		end := strings.Index(value[start:], "m")
		if end < 0 {
			return value[:start]
		}
		value = value[:start] + value[start+end+1:]
	}
}

func markdownCell(value string) string { return strings.ReplaceAll(safeText(value), "|", "\\|") }
func joinRange(start, end string) string {
	if start == "" {
		return end
	}
	if end == "" || end == start {
		return start
	}
	return start + " – " + end
}
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
func nonEmpty(values ...string) []string {
	var kept []string
	for _, value := range values {
		if value != "" {
			kept = append(kept, value)
		}
	}
	return kept
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func sortedKeys(values map[string][]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
