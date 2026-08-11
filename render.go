package whodis

import (
	"encoding/json"
	"fmt"
	"io"
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
	FormatTree     Format = "tree"
	FormatGeekBoys Format = "geekboys"
	FormatPlain    Format = "plain"
	FormatJSON     Format = "json"
	FormatYAML     Format = "yaml"
	FormatMarkdown Format = "markdown"
	FormatRaw      Format = "raw"
)

// RenderOptions changes presentation only; it never changes lookup behavior.
type RenderOptions struct {
	Color   string
	Width   int
	Details bool
}

// ParseFormat validates a CLI-facing output format. Common descriptions of
// the human-facing renderers are accepted as friendly aliases.
func ParseFormat(value string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "pretty", "dashboard", "grid", "current", "":
		return FormatPretty, nil
	case "tree":
		return FormatTree, nil
	case "geekboys", "geek-boys", "retro":
		return FormatGeekBoys, nil
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
		_, err := io.WriteString(writer, renderPretty(writer, result, options))
		return err
	case FormatTree:
		_, err := io.WriteString(writer, renderTree(writer, result, options))
		return err
	case FormatGeekBoys:
		_, err := io.WriteString(writer, renderGeekBoys(writer, result, options))
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
	if nameservers := displayNameservers(result); len(nameservers) > 0 {
		line("Nameservers", strings.Join(nameservers, ", "))
	}
	if result.DNS != nil {
		line("DNS method", result.DNS.Method)
		line("DNS complete", strconv.FormatBool(result.DNS.Complete))
		for _, warning := range result.DNS.Warnings {
			line("DNS warning", warning)
		}
		for _, record := range uniqueDNSRecords(result.DNS.Records) {
			line(fmt.Sprintf("DNS %s %s (%ds)", record.Type, record.Name, record.TTL), record.Value)
		}
	}
	for _, event := range consolidateEvents(object.Events) {
		line("Event "+event.label, event.value)
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
	if events := consolidateEvents(result.Object.Events); len(events) > 0 {
		builder.WriteString("\n## Events\n\n| Action | Date |\n| --- | --- |\n")
		for _, event := range events {
			fmt.Fprintf(&builder, "| %s | %s |\n", markdownCell(event.label), markdownCell(event.value))
		}
	}
	if nameservers := displayNameservers(result); len(nameservers) > 0 {
		builder.WriteString("\n## Nameservers\n\n")
		for _, ns := range nameservers {
			fmt.Fprintf(&builder, "- `%s`\n", safeText(ns))
		}
	}
	if result.DNS != nil {
		builder.WriteString("\n## DNS records\n\n")
		fmt.Fprintf(&builder, "Method: `%s`  \\nComplete zone transfer: `%t`\n", markdownCell(result.DNS.Method), result.DNS.Complete)
		if len(result.DNS.Warnings) > 0 {
			builder.WriteString("\nWarnings:\n")
			for _, warning := range result.DNS.Warnings {
				fmt.Fprintf(&builder, "- %s\n", markdownCell(warning))
			}
		}
		if records := uniqueDNSRecords(result.DNS.Records); len(records) > 0 {
			builder.WriteString("\n| Type | Name | TTL | Value |\n| --- | --- | ---: | --- |\n")
			for _, record := range records {
				fmt.Fprintf(&builder, "| %s | %s | %d | %s |\n", markdownCell(record.Type), markdownCell(record.Name), record.TTL, markdownCell(record.Value))
			}
		}
	}
	return builder.String()
}

func displayNameservers(result LookupResult) []string {
	if result.DNS != nil && dnsRecordsIncludeType(result.DNS.Records, "NS") {
		return nil
	}
	nameservers := append([]string(nil), result.Object.Nameservers...)
	if result.DNS != nil {
		nameservers = append(nameservers, result.DNS.Nameservers...)
	}
	return uniqueFold(nameservers)
}

func dnsRecordsIncludeType(records []DNSRecord, recordType string) bool {
	for _, record := range records {
		if strings.EqualFold(record.Type, recordType) {
			return true
		}
	}
	return false
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
