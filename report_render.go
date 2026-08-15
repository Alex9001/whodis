package whodis

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mattn/go-runewidth"
	"gopkg.in/yaml.v3"
)

// RenderReport writes one schema-v4 engine report. Registration-only reports
// retain the established Whodis layouts; workstation operations use compact,
// sectioned tables with the same output-format contract.
func RenderReport(writer io.Writer, report Report, format Format, options RenderOptions) error {
	if report.Operation == OperationRegistration && report.Registration != nil && format != FormatJSON && format != FormatYAML && format != FormatCSV && format != FormatNDJSON {
		return Render(writer, report.Registration.AsLookupResult(report.Subject, report.ObservedAt), format, options)
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
	case FormatNDJSON:
		return json.NewEncoder(writer).Encode(report)
	case FormatCSV:
		return renderReportCSV(writer, []Report{report})
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

// RenderBatchReport writes schema-v4 reports in request order.
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
	if format == FormatNDJSON {
		encoder := json.NewEncoder(writer)
		for _, report := range batch.Reports {
			if err := encoder.Encode(report); err != nil {
				return err
			}
		}
		return nil
	}
	if format == FormatCSV {
		return renderReportCSV(writer, batch.Reports)
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

func renderReportCSV(writer io.Writer, reports []Report) error {
	csvWriter := csv.NewWriter(writer)
	header := []string{"TARGET", "KIND", "REGISTRATION_DOMAIN", "OPERATION", "PROTOCOL", "AUTHORITY", "REGISTRAR", "REGISTRY", "REGISTERED", "UPDATED", "EXPIRES", "DNSSEC", "STATUS", "NAMESERVERS", "DNS_RECORDS", "FINDINGS", "ERRORS", "OBSERVED_AT"}
	if err := csvWriter.Write(header); err != nil {
		return err
	}
	for _, report := range reports {
		row := make([]string, len(header))
		row[0], row[1], row[2], row[3] = report.Subject.Canonical, string(report.Subject.Kind), report.Subject.RegistrationDomain, string(report.Operation)
		row[17] = report.ObservedAt.UTC().Format(time.RFC3339)
		if registration := report.Registration; registration != nil {
			row[4], row[5] = string(registration.Route.Protocol), registration.Route.Endpoint
			object := registration.Object
			row[6], row[7] = object.Registrar, object.Registry
			row[8] = strings.Join(eventValues(object.Events, "registration", "registered", "creation", "created"), "; ")
			row[9] = strings.Join(eventValues(object.Events, "last changed", "last update", "updated", "changed"), "; ")
			row[10] = strings.Join(eventValues(object.Events, "expiration", "expiry", "expires"), "; ")
			row[11], row[12], row[13] = object.DNSSEC, strings.Join(object.Status, "; "), strings.Join(object.Nameservers, "; ")
		}
		row[14] = strconv.Itoa(reportDNSRecordCount(report))
		findings := uniqueReportFindings(report)
		findingValues := make([]string, 0, len(findings))
		for _, finding := range findings {
			findingValues = append(findingValues, string(finding.Severity)+": "+finding.Title)
		}
		row[15] = strings.Join(findingValues, "; ")
		errorValues := make([]string, 0, len(report.Errors))
		for _, operationError := range report.Errors {
			errorValues = append(errorValues, string(operationError.Operation)+"/"+string(operationError.Kind)+": "+operationError.Message)
		}
		row[16] = strings.Join(errorValues, "; ")
		if err := csvWriter.Write(row); err != nil {
			return err
		}
	}
	csvWriter.Flush()
	return csvWriter.Error()
}

func reportDNSRecordCount(report Report) int {
	var records []DNSRecord
	collectResult := func(result *DNSOperationResult) {
		if result == nil {
			return
		}
		if result.Inventory != nil {
			records = append(records, result.Inventory.Records...)
		}
		for _, message := range result.Messages {
			records = append(records, message.Answer...)
			records = append(records, message.Authority...)
			records = append(records, message.Additional...)
		}
		if result.Transfer != nil {
			records = append(records, result.Transfer.Records...)
		}
		for _, measurement := range result.Remote {
			records = append(records, measurement.Answers...)
		}
	}
	collectResult(report.DNS)
	if report.Diagnosis != nil {
		collectResult(report.Diagnosis.DNS)
		collectResult(report.Diagnosis.Delegation)
	}
	return len(uniqueDNSRecords(records))
}

func uniqueReportFindings(report Report) []Finding {
	all := append([]Finding(nil), report.Findings...)
	if report.Diagnosis != nil {
		all = append(all, report.Diagnosis.Findings...)
	}
	seen := make(map[string]bool, len(all))
	result := make([]Finding, 0, len(all))
	for _, finding := range all {
		key := finding.ID + "\x00" + string(finding.Severity) + "\x00" + finding.Title + "\x00" + finding.Summary
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, finding)
	}
	return result
}

func renderReportTerminal(report Report, format Format, options RenderOptions) string {
	var builder strings.Builder
	title := strings.ToUpper(string(report.Operation)) + " · " + report.Subject.Canonical
	if format == FormatTree {
		fmt.Fprintln(&builder, title)
	} else {
		fmt.Fprintln(&builder, title)
		fmt.Fprintln(&builder, strings.Repeat("═", max(1, runewidth.StringWidth(title))))
	}
	if report.Registration != nil {
		fmt.Fprintln(&builder, "\nRegistration")
		builder.WriteString(renderPlain(report.Registration.AsLookupResult(report.Subject, report.ObservedAt)))
	}
	if report.DNS != nil {
		renderDNSReport(&builder, report.DNS, options.Width)
	}
	if findings := uniqueReportFindings(report); len(findings) > 0 {
		var rows [][]string
		for _, finding := range findings {
			rows = append(rows, []string{strings.ToUpper(string(finding.Severity)), finding.Title, finding.Summary})
		}
		writeReportTable(&builder, "Findings", []string{"Result", "Check", "Summary"}, rows, options.Width)
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
			query := strings.TrimSpace(difference.Name + " " + difference.Type)
			rows = append(rows, []string{query, difference.Resolver, strings.Join(difference.Missing, "; "), strings.Join(difference.Extra, "; ")})
		}
		writeReportTable(builder, "Resolver differences", []string{"Query", "Resolver", "Missing", "Extra"}, rows, width)
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
		wrapped := make([][]string, len(widths))
		height := 1
		for index, width := range widths {
			if index < len(values) {
				wrapped[index] = wrapReportCell(safeText(values[index]), width)
			} else {
				wrapped[index] = []string{""}
			}
			height = max(height, len(wrapped[index]))
		}
		for line := 0; line < height; line++ {
			builder.WriteString("│")
			for index, width := range widths {
				value := ""
				if line < len(wrapped[index]) {
					value = wrapped[index][line]
				}
				fmt.Fprintf(builder, " %s%s │", value, strings.Repeat(" ", max(0, width-runewidth.StringWidth(value))))
			}
			builder.WriteByte('\n')
		}
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

func wrapReportCell(value string, width int) []string {
	if width < 1 || value == "" {
		return []string{""}
	}
	var lines []string
	for _, paragraph := range strings.Split(value, "\n") {
		paragraph = strings.TrimSpace(paragraph)
		for runewidth.StringWidth(paragraph) > width {
			piece := runewidth.Truncate(paragraph, width, "")
			cut := strings.LastIndexAny(piece, " \t/;,|")
			if cut > 0 && runewidth.StringWidth(piece[:cut]) >= width/2 {
				piece = strings.TrimSpace(piece[:cut])
			}
			if piece == "" {
				piece = runewidth.Truncate(paragraph, width, "")
			}
			lines = append(lines, piece)
			paragraph = strings.TrimSpace(strings.TrimPrefix(paragraph, piece))
		}
		lines = append(lines, paragraph)
	}
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}

func renderReportMarkdown(report Report) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "# Whodis %s: `%s`\n\n", report.Operation, markdownCell(report.Subject.Canonical))
	if report.Registration != nil {
		registration := renderMarkdown(report.Registration.AsLookupResult(report.Subject, report.ObservedAt))
		if split := strings.Index(registration, "\n\n"); split >= 0 {
			registration = "## Registration\n\n" + registration[split+2:]
		}
		builder.WriteString(registration)
	}
	findings := append([]Finding(nil), report.Findings...)
	if report.Diagnosis != nil {
		findings = append(findings, report.Diagnosis.Findings...)
	}
	if len(findings) > 0 {
		builder.WriteString("## Findings\n\n| Result | Check | Summary |\n| --- | --- | --- |\n")
		for _, finding := range findings {
			fmt.Fprintf(&builder, "| %s | %s | %s |\n", finding.Severity, markdownCell(finding.Title), markdownCell(finding.Summary))
		}
	}
	if report.DNS != nil {
		renderDNSOperationMarkdown(&builder, "DNS", report.DNS)
	}
	if report.Diagnosis != nil {
		renderDiagnosisMarkdown(&builder, report.Diagnosis)
	}
	if len(report.Errors) > 0 {
		builder.WriteString("\n## Partial errors\n\n| Operation | Provider | Kind | Message |\n| --- | --- | --- | --- |\n")
		for _, operationError := range report.Errors {
			fmt.Fprintf(&builder, "| %s | %s | %s | %s |\n", operationError.Operation, markdownCell(operationError.Provider), operationError.Kind, markdownCell(operationError.Message))
		}
	}
	return builder.String()
}

func renderDNSOperationMarkdown(builder *strings.Builder, title string, dns *DNSOperationResult) {
	if dns == nil {
		return
	}
	fmt.Fprintf(builder, "\n## %s\n\n", title)
	if dns.Mode != "" {
		fmt.Fprintf(builder, "Mode: `%s`\n", markdownCell(dns.Mode))
	}
	if len(dns.Messages) > 0 {
		builder.WriteString("\n### Queries\n\n| Name | Type | Resolver | Transport | RCODE | DNSSEC | Error |\n| --- | --- | --- | --- | --- | --- | --- |\n")
		for _, message := range dns.Messages {
			fmt.Fprintf(builder, "| %s | %s | %s | %s | %s | %s | %s |\n", markdownCell(message.Name), markdownCell(message.Type), markdownCell(message.Resolver), markdownCell(message.Transport), markdownCell(message.Rcode), markdownCell(message.DNSSEC), markdownCell(message.Error))
		}
	}
	type sectionRecord struct {
		section string
		record  DNSRecord
	}
	var records []sectionRecord
	if dns.Inventory != nil {
		for _, record := range uniqueDNSRecords(dns.Inventory.Records) {
			records = append(records, sectionRecord{"inventory", record})
		}
	}
	if dns.Transfer != nil {
		for _, record := range uniqueDNSRecords(dns.Transfer.Records) {
			records = append(records, sectionRecord{"transfer", record})
		}
	}
	for _, message := range dns.Messages {
		for _, section := range []struct {
			name    string
			records []DNSRecord
		}{{"answer", message.Answer}, {"authority", message.Authority}, {"additional", message.Additional}} {
			for _, record := range uniqueDNSRecords(section.records) {
				records = append(records, sectionRecord{section.name, record})
			}
		}
	}
	if len(records) > 0 {
		builder.WriteString("\n### Records\n\n| Section | Name | Type | TTL | Value |\n| --- | --- | --- | ---: | --- |\n")
		for _, item := range records {
			fmt.Fprintf(builder, "| %s | %s | %s | %d | %s |\n", item.section, markdownCell(item.record.Name), item.record.Type, item.record.TTL, markdownCell(item.record.Value))
		}
	}
	if len(dns.Differences) > 0 {
		builder.WriteString("\n### Resolver differences\n\n| Query | Resolver | Missing | Extra |\n| --- | --- | --- | --- |\n")
		for _, difference := range dns.Differences {
			query := strings.TrimSpace(difference.Name + " " + difference.Type)
			fmt.Fprintf(builder, "| %s | %s | %s | %s |\n", markdownCell(query), markdownCell(difference.Resolver), markdownCell(strings.Join(difference.Missing, "; ")), markdownCell(strings.Join(difference.Extra, "; ")))
		}
	}
	if len(dns.Trace) > 0 {
		builder.WriteString("\n### Delegation trace\n\n| Hop | Zone | Server | RCODE | DNSSEC | Nameservers | Addresses | Error |\n| ---: | --- | --- | --- | --- | --- | --- | --- |\n")
		for index, hop := range dns.Trace {
			fmt.Fprintf(builder, "| %d | %s | %s | %s | %s | %s | %s | %s |\n", index+1, markdownCell(hop.Zone), markdownCell(hop.Server), markdownCell(hop.Rcode), markdownCell(hop.DNSSEC), markdownCell(strings.Join(hop.Nameservers, ", ")), markdownCell(strings.Join(hop.Addresses, ", ")), markdownCell(hop.Error))
		}
	}
	if len(dns.Remote) > 0 {
		builder.WriteString("\n### Globalping DNS\n\n| Location | Resolver | Status | RCODE | Answers | Error |\n| --- | --- | --- | --- | --- | --- |\n")
		for _, measurement := range dns.Remote {
			answers := make([]string, 0, len(measurement.Answers))
			for _, record := range measurement.Answers {
				answers = append(answers, record.Type+" "+record.Value)
			}
			fmt.Fprintf(builder, "| %s | %s | %s | %s | %s | %s |\n", markdownCell(measurement.Location), markdownCell(measurement.Resolver), markdownCell(measurement.Status), markdownCell(measurement.Rcode), markdownCell(strings.Join(answers, "; ")), markdownCell(measurement.Error))
		}
	}
	warnings := append([]string(nil), dns.Warnings...)
	if dns.Inventory != nil {
		warnings = append(warnings, dns.Inventory.Warnings...)
	}
	if dns.Transfer != nil {
		warnings = append(warnings, dns.Transfer.Warnings...)
	}
	if len(warnings) > 0 {
		builder.WriteString("\n### DNS warnings\n\n")
		for _, warning := range uniqueStrings(warnings) {
			fmt.Fprintf(builder, "- %s\n", markdownCell(warning))
		}
	}
}

func renderDiagnosisMarkdown(builder *strings.Builder, diagnosis *DiagnosisReport) {
	if diagnosis == nil {
		return
	}
	builder.WriteString("\n## Diagnosis\n")
	if diagnosis.DNS != nil {
		renderDNSOperationMarkdown(builder, "Diagnostic DNS inventory", diagnosis.DNS)
	}
	if diagnosis.Delegation != nil {
		renderDNSOperationMarkdown(builder, "Diagnostic delegation", diagnosis.Delegation)
	}
	if len(diagnosis.Reachability) > 0 {
		builder.WriteString("\n### Reachability\n\n| Address | Network | Method | Port | Reachable | Error |\n| --- | --- | --- | ---: | --- | --- |\n")
		for _, probe := range diagnosis.Reachability {
			fmt.Fprintf(builder, "| %s | %s | %s | %d | %t | %s |\n", markdownCell(probe.Address), markdownCell(probe.Network), markdownCell(probe.Method), probe.Port, probe.Reachable, markdownCell(probe.Error))
		}
	}
	if len(diagnosis.HTTP) > 0 {
		builder.WriteString("\n### HTTP\n\n| URL | Status | Final URL | Healthy | Redirects | Error |\n| --- | ---: | --- | --- | --- | --- |\n")
		for _, probe := range diagnosis.HTTP {
			fmt.Fprintf(builder, "| %s | %d | %s | %t | %s | %s |\n", markdownCell(probe.URL), probe.Status, markdownCell(probe.FinalURL), probe.Healthy, markdownCell(strings.Join(probe.Redirects, " → ")), markdownCell(probe.Error))
		}
	}
	if len(diagnosis.TLS) > 0 {
		builder.WriteString("\n### TLS\n\n| Server | Address | Version | Certificate expires | Verified | Error |\n| --- | --- | --- | --- | --- | --- |\n")
		for _, probe := range diagnosis.TLS {
			fmt.Fprintf(builder, "| %s | %s | %s | %s | %t | %s |\n", markdownCell(probe.ServerName), markdownCell(probe.Address), markdownCell(probe.Version), markdownCell(formatReportTime(probe.NotAfter)), probe.Verified, markdownCell(probe.Error))
		}
	}
	if len(diagnosis.Mail) > 0 {
		builder.WriteString("\n### Mail\n\n| MX | Preference | Address | Reachable | STARTTLS | TLS verified | Capabilities | Error |\n| --- | ---: | --- | --- | --- | --- | --- | --- |\n")
		for _, probe := range diagnosis.Mail {
			fmt.Fprintf(builder, "| %s | %d | %s | %t | %t | %t | %s | %s |\n", markdownCell(probe.Host), probe.Preference, markdownCell(probe.Address), probe.Reachable, probe.STARTTLS, probe.TLSVerified, markdownCell(strings.Join(probe.Capabilities, ", ")), markdownCell(probe.Error))
		}
	}
	if len(diagnosis.Services) > 0 {
		builder.WriteString("\n### Advertised services\n\n| Source | Name | Target | Port | Reachable | Error |\n| --- | --- | --- | ---: | --- | --- |\n")
		for _, probe := range diagnosis.Services {
			fmt.Fprintf(builder, "| %s | %s | %s | %d | %t | %s |\n", markdownCell(probe.Source), markdownCell(probe.Name), markdownCell(probe.Target), probe.Port, probe.Reachable, markdownCell(probe.Error))
		}
	}
	if len(diagnosis.Path) > 0 {
		builder.WriteString("\n### Network path\n\n| Hop | Address | Reached | Error |\n| ---: | --- | --- | --- |\n")
		for _, hop := range diagnosis.Path {
			fmt.Fprintf(builder, "| %d | %s | %t | %s |\n", hop.Hop, markdownCell(hop.Address), hop.Reached, markdownCell(hop.Error))
		}
	}
	if len(diagnosis.Policies) > 0 {
		builder.WriteString("\n### Mail policies\n\n| Policy | Values |\n| --- | --- |\n")
		keys := make([]string, 0, len(diagnosis.Policies))
		for key := range diagnosis.Policies {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Fprintf(builder, "| %s | %s |\n", markdownCell(key), markdownCell(strings.Join(diagnosis.Policies[key], "; ")))
		}
	}
	if len(diagnosis.Warnings) > 0 {
		builder.WriteString("\n### Diagnosis warnings\n\n")
		for _, warning := range uniqueStrings(diagnosis.Warnings) {
			fmt.Fprintf(builder, "- %s\n", markdownCell(warning))
		}
	}
}

func formatReportTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format("2006-01-02")
}
