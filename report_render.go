package whodis

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/mattn/go-runewidth"
	"gopkg.in/yaml.v3"
)

// RenderReport writes one schema-v3 engine report. Registration-only reports
// retain the established Whodis layouts; workstation operations use compact,
// sectioned tables with the same output-format contract.
func RenderReport(writer io.Writer, report Report, format Format, options RenderOptions) error {
	if report.Operation == OperationRegistration && report.Registration != nil {
		return Render(writer, *report.Registration, format, options)
	}
	switch format {
	case FormatJSON:
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	case FormatYAML:
		payload, err := yaml.Marshal(report)
		if err != nil {
			return err
		}
		_, err = writer.Write(payload)
		return err
	case FormatMarkdown:
		_, err := io.WriteString(writer, renderReportMarkdown(report))
		return err
	case FormatRaw:
		return fmt.Errorf("raw output is only available for registration responses")
	case FormatPlain, FormatPretty, FormatTree, FormatGeekBoys:
		options.Width = dashboardWidth(writer, options.Width)
		_, err := io.WriteString(writer, renderReportTerminal(report, format, options))
		return err
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

// RenderBatchReport writes schema-v3 reports in request order.
func RenderBatchReport(writer io.Writer, batch BatchReport, format Format, options RenderOptions) error {
	if format == FormatJSON {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(batch)
	}
	if format == FormatYAML {
		payload, err := yaml.Marshal(batch)
		if err != nil {
			return err
		}
		_, err = writer.Write(payload)
		return err
	}
	for index, report := range batch.Reports {
		if index > 0 {
			if _, err := io.WriteString(writer, "\n"); err != nil {
				return err
			}
		}
		if err := RenderReport(writer, report, format, options); err != nil {
			return err
		}
	}
	return nil
}

func renderReportTerminal(report Report, format Format, options RenderOptions) string {
	var builder strings.Builder
	title := strings.ToUpper(string(report.Operation)) + " · " + report.Query.Canonical
	if format == FormatTree {
		fmt.Fprintln(&builder, title)
	} else {
		fmt.Fprintln(&builder, title)
		fmt.Fprintln(&builder, strings.Repeat("═", max(1, runewidth.StringWidth(title))))
	}
	if report.Registration != nil {
		fmt.Fprintln(&builder, "\nRegistration")
		builder.WriteString(renderPlain(*report.Registration))
	}
	if report.DNS != nil {
		renderDNSReport(&builder, report.DNS, options.Width)
	}
	if report.Diagnosis != nil {
		renderDiagnosisReport(&builder, report.Diagnosis, options.Width)
	}
	if len(report.Errors) > 0 {
		rows := make([][]string, 0, len(report.Errors))
		for _, operationError := range report.Errors {
			rows = append(rows, []string{string(operationError.Operation), string(operationError.Kind), operationError.Message})
		}
		writeReportTable(&builder, "Partial errors", []string{"Operation", "Kind", "Message"}, rows, options.Width)
	}
	output := builder.String()
	if format == FormatPlain || format == FormatGeekBoys {
		output = strings.NewReplacer(
			"═", "=", "─", "-", "┌", "+", "┬", "+", "┐", "+",
			"├", "+", "┼", "+", "┤", "+", "└", "+", "┴", "+", "┘", "+", "│", "|",
		).Replace(output)
	}
	return output
}

func renderDNSReport(builder *strings.Builder, result *DNSOperationResult, width int) {
	if result.Inventory != nil {
		records := uniqueDNSRecords(result.Inventory.Records)
		rows := make([][]string, 0, len(records))
		for _, record := range records {
			rows = append(rows, []string{record.Name, record.Type, strconv.FormatUint(uint64(record.TTL), 10), record.Value})
		}
		writeReportTable(builder, "DNS inventory", []string{"Name", "Type", "TTL", "Value"}, rows, width)
	}
	for _, message := range result.Messages {
		title := fmt.Sprintf("DNS %s %s via %s", message.Name, message.Type, message.Resolver)
		if message.Error != "" {
			writeReportTable(builder, title, []string{"Result", "Duration"}, [][]string{{message.Error, message.Duration.String()}}, width)
			continue
		}
		rows := [][]string{{"Header", message.Rcode + " · " + message.DNSSEC, message.Duration.String(), message.Transport}}
		for _, section := range []struct {
			name    string
			records []DNSRecord
		}{{"Answer", message.Answer}, {"Authority", message.Authority}, {"Additional", message.Additional}} {
			for _, record := range section.records {
				rows = append(rows, []string{section.name, record.Name, record.Type, record.Value})
			}
		}
		writeReportTable(builder, title, []string{"Section", "Name/status", "Type/time", "Value/transport"}, rows, width)
	}
	if len(result.Differences) == 0 && result.Mode == "compare" {
		writeReportTable(builder, "Resolver comparison", []string{"Result"}, [][]string{{"Resolvers agree after TTL and order normalization."}}, width)
	} else if len(result.Differences) > 0 {
		var rows [][]string
		for _, difference := range result.Differences {
			rows = append(rows, []string{difference.Resolver, strings.Join(difference.Missing, "; "), strings.Join(difference.Extra, "; ")})
		}
		writeReportTable(builder, "Resolver differences", []string{"Resolver", "Missing", "Extra"}, rows, width)
	}
	if len(result.Trace) > 0 {
		var rows [][]string
		for index, hop := range result.Trace {
			status := hop.Rcode
			if hop.Error != "" {
				status = hop.Error
			}
			rows = append(rows, []string{strconv.Itoa(index + 1), hop.Zone, hop.Server, status, strings.Join(hop.Nameservers, ", ")})
		}
		writeReportTable(builder, "Delegation trace", []string{"Hop", "Zone", "Server", "Result", "Nameservers"}, rows, width)
	}
	if result.Transfer != nil {
		var rows [][]string
		for _, record := range result.Transfer.Records {
			rows = append(rows, []string{record.Name, record.Type, strconv.FormatUint(uint64(record.TTL), 10), record.Value})
		}
		writeReportTable(builder, strings.ToUpper(result.Transfer.Method)+" transfer", []string{"Name", "Type", "TTL", "Value"}, rows, width)
	}
	if len(result.Warnings) > 0 {
		var rows [][]string
		for _, warning := range result.Warnings {
			rows = append(rows, []string{warning})
		}
		writeReportTable(builder, "DNS warnings", []string{"Warning"}, rows, width)
	}
	if len(result.Remote) > 0 {
		var rows [][]string
		for _, measurement := range result.Remote {
			answerValues := make([]string, 0, len(measurement.Answers))
			for _, record := range measurement.Answers {
				answerValues = append(answerValues, record.Type+" "+record.Value)
			}
			status := measurement.Status
			if measurement.Error != "" {
				status = measurement.Error
			}
			rows = append(rows, []string{measurement.Location, measurement.Resolver, status, strings.Join(answerValues, "; ")})
		}
		writeReportTable(builder, "Globalping DNS", []string{"Location", "Resolver", "Status", "Answers"}, rows, width)
	}
}

func renderDiagnosisReport(builder *strings.Builder, report *DiagnosisReport, width int) {
	if len(report.Findings) > 0 {
		var rows [][]string
		for _, finding := range report.Findings {
			rows = append(rows, []string{strings.ToUpper(string(finding.Severity)), finding.Title, finding.Summary})
		}
		writeReportTable(builder, "Findings", []string{"Result", "Check", "Summary"}, rows, width)
	}
	if report.DNS != nil {
		renderDNSReport(builder, report.DNS, width)
	}
	if report.Delegation != nil {
		renderDNSReport(builder, report.Delegation, width)
	}
	if len(report.Reachability) > 0 {
		var rows [][]string
		for _, probe := range report.Reachability {
			result := "pass"
			if !probe.Reachable {
				result = probe.Error
			}
			rows = append(rows, []string{probe.Address, probe.Network, fmt.Sprintf("%s/%d", probe.Method, probe.Port), result, probe.Duration.String()})
		}
		writeReportTable(builder, "Reachability", []string{"Address", "Network", "Probe", "Result", "Time"}, rows, width)
	}
	if len(report.HTTP) > 0 {
		var rows [][]string
		for _, probe := range report.HTTP {
			status := strconv.Itoa(probe.Status)
			if probe.Error != "" {
				status = probe.Error
			}
			rows = append(rows, []string{probe.URL, status, probe.FinalURL, probe.Duration.String()})
		}
		writeReportTable(builder, "HTTP", []string{"URL", "Status", "Final URL", "Time"}, rows, width)
	}
	if len(report.TLS) > 0 {
		var rows [][]string
		for _, probe := range report.TLS {
			verified := "yes"
			if !probe.Verified {
				verified = "no"
			}
			if probe.Error != "" {
				verified = probe.Error
			}
			rows = append(rows, []string{probe.ServerName, verified, probe.Version, probe.ALPN, formatReportTime(probe.NotAfter)})
		}
		writeReportTable(builder, "TLS", []string{"Name", "Verified", "Version", "ALPN", "Expires"}, rows, width)
	}
	if len(report.Mail) > 0 {
		var rows [][]string
		for _, probe := range report.Mail {
			result := "reachable"
			if probe.Error != "" {
				result = probe.Error
			}
			rows = append(rows, []string{strconv.Itoa(int(probe.Preference)), probe.Host, result, strconv.FormatBool(probe.STARTTLS), strings.Join(probe.Capabilities, ", ")})
		}
		writeReportTable(builder, "Mail", []string{"Pref", "MX", "SMTP", "STARTTLS", "Capabilities"}, rows, width)
	}
	if len(report.Services) > 0 {
		var rows [][]string
		for _, probe := range report.Services {
			result := "reachable"
			if probe.Error != "" {
				result = probe.Error
			}
			rows = append(rows, []string{probe.Source, probe.Name, probe.Target, strconv.Itoa(int(probe.Port)), result})
		}
		writeReportTable(builder, "Advertised services", []string{"Source", "Name", "Target", "Port", "Result"}, rows, width)
	}
	if len(report.Path) > 0 {
		var rows [][]string
		for _, hop := range report.Path {
			result := "transit"
			if hop.Reached {
				result = "destination"
			}
			if hop.Error != "" {
				result = hop.Error
			}
			rows = append(rows, []string{strconv.Itoa(hop.Hop), hop.Address, result, hop.Duration.String()})
		}
		writeReportTable(builder, "Network path", []string{"Hop", "Address", "Result", "Time"}, rows, width)
	}
}

func writeReportTable(builder *strings.Builder, title string, headers []string, rows [][]string, requestedWidth int) {
	if len(rows) == 0 {
		return
	}
	fmt.Fprintf(builder, "\n%s\n", title)
	columns := len(headers)
	widths := make([]int, columns)
	for index, header := range headers {
		widths[index] = runewidth.StringWidth(header)
	}
	for _, row := range rows {
		for index := 0; index < columns && index < len(row); index++ {
			widths[index] = min(max(widths[index], runewidth.StringWidth(safeText(row[index]))), 48)
		}
	}
	if requestedWidth > 0 {
		available := requestedWidth - (3*columns + 1)
		for totalReportWidth(widths) > available && available >= columns {
			widest := 0
			for index := 1; index < len(widths); index++ {
				if widths[index] > widths[widest] {
					widest = index
				}
			}
			if widths[widest] <= 4 {
				break
			}
			widths[widest]--
		}
	}
	writeBorder := func(left, middle, right string) {
		builder.WriteString(left)
		for index, width := range widths {
			if index > 0 {
				builder.WriteString(middle)
			}
			builder.WriteString(strings.Repeat("─", width+2))
		}
		builder.WriteString(right + "\n")
	}
	writeCells := func(values []string) {
		builder.WriteString("│")
		for index, width := range widths {
			value := ""
			if index < len(values) {
				value = truncateReportCell(safeText(values[index]), width)
			}
			fmt.Fprintf(builder, " %-*s │", width, value+strings.Repeat(" ", max(0, width-runewidth.StringWidth(value))))
		}
		builder.WriteByte('\n')
	}
	writeBorder("┌", "┬", "┐")
	writeCells(headers)
	writeBorder("├", "┼", "┤")
	for _, row := range rows {
		writeCells(row)
	}
	writeBorder("└", "┴", "┘")
}

func totalReportWidth(widths []int) int {
	total := 0
	for _, width := range widths {
		total += width
	}
	return total
}

func truncateReportCell(value string, width int) string {
	if runewidth.StringWidth(value) <= width {
		return value
	}
	if width < 2 {
		return "…"
	}
	return runewidth.Truncate(value, width-1, "") + "…"
}

func renderReportMarkdown(report Report) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "# Whodis %s: `%s`\n\n", report.Operation, markdownCell(report.Query.Canonical))
	if report.Registration != nil {
		builder.WriteString(renderMarkdown(*report.Registration))
	}
	if len(report.Findings) > 0 {
		builder.WriteString("## Findings\n\n| Result | Check | Summary |\n| --- | --- | --- |\n")
		for _, finding := range report.Findings {
			fmt.Fprintf(&builder, "| %s | %s | %s |\n", finding.Severity, markdownCell(finding.Title), markdownCell(finding.Summary))
		}
	}
	dns := report.DNS
	if dns == nil && report.Diagnosis != nil {
		dns = report.Diagnosis.DNS
	}
	if dns != nil {
		var records []DNSRecord
		if dns.Inventory != nil {
			records = dns.Inventory.Records
		}
		for _, message := range dns.Messages {
			records = append(records, message.Answer...)
		}
		if len(records) > 0 {
			builder.WriteString("\n## DNS records\n\n| Name | Type | TTL | Value |\n| --- | --- | ---: | --- |\n")
			for _, record := range uniqueDNSRecords(records) {
				fmt.Fprintf(&builder, "| %s | %s | %d | %s |\n", markdownCell(record.Name), record.Type, record.TTL, markdownCell(record.Value))
			}
		}
		if len(dns.Remote) > 0 {
			builder.WriteString("\n## Globalping DNS\n\n| Location | Resolver | Status | Answers |\n| --- | --- | --- | --- |\n")
			for _, measurement := range dns.Remote {
				answers := make([]string, 0, len(measurement.Answers))
				for _, record := range measurement.Answers {
					answers = append(answers, record.Type+" "+record.Value)
				}
				fmt.Fprintf(&builder, "| %s | %s | %s | %s |\n", markdownCell(measurement.Location), markdownCell(measurement.Resolver), markdownCell(measurement.Status), markdownCell(strings.Join(answers, "; ")))
			}
		}
	}
	return builder.String()
}

func formatReportTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format("2006-01-02")
}
