package whodis

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/mattn/go-runewidth"
)

var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func sampleResult() LookupResult {
	return LookupResult{
		SchemaVersion: 1,
		Query:         Target{Original: "example.com", Canonical: "example.com", Kind: KindDomain},
		Route: RouteDecision{
			Protocol:        ProtocolRDAP,
			Endpoint:        "https://rdap.example.test/",
			DiscoverySource: "fixture",
		},
		RetrievedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Object: Object{
			Kind:        KindDomain,
			Name:        "example.com",
			UnicodeName: "例え.example",
			Handle:      "DOMAIN-123",
			Registrar:   "株式会社レジストラ 🚀",
			Registry:    "Example Registry",
			Status: []string{
				"active",
				"ACTIVE",
				"client transfer prohibited",
			},
			DNSSEC: "signedDelegation",
			Nameservers: []string{
				"NS1.EXAMPLE.TEST",
				"ns1.example.test",
				"ns2.example.test",
			},
			Events: []Event{
				{Action: "registration", Date: "2024-03-01T01:02:03Z"},
				{Action: "Registration", Date: "2024-03-01T01:02:03Z"},
				{Action: "expiration", Date: "2028-03-01T01:02:03Z"},
			},
			Entities: []Entity{
				{
					Roles:        []string{"registrant"},
					Handle:       "CONTACT-ALPHA",
					Name:         "Aleksandr Example",
					Organization: "Café Example LLC",
					Email:        "admin@example.test",
				},
				{
					Roles:        []string{"technical"},
					Handle:       "CONTACT-ALPHA",
					Name:         "Aleksandr Example",
					Organization: "Café Example LLC",
					Email:        "admin@example.test",
					Phone:        "+1.555.0100",
				},
				{
					Roles:  []string{"abuse"},
					Handle: "HANDLE-ONLY-42",
				},
			},
			Notices: []Notice{
				{
					Title:       "Terms of Service",
					Description: []string{"Legal body alpha — supplied once."},
					Links:       []string{"https://example.test/terms"},
				},
				{
					Title:       "terms of service",
					Description: []string{"Legal body alpha — supplied once."},
					Links:       []string{"https://example.test/terms"},
				},
				{
					Title:       "Service Status",
					Description: []string{"Operational message beta."},
					Links:       []string{"https://status.example.test/rdap"},
				},
			},
		},
		Sources: []Source{{
			Protocol: ProtocolRDAP,
			Endpoint: "https://rdap.example.test/domain/example.com",
			Raw:      `{"objectClassName":"domain"}`,
		}},
	}
}

func sampleIPResult() LookupResult {
	result := sampleResult()
	result.Query = Target{Original: "192.0.2.1", Canonical: "192.0.2.1", Kind: KindIP}
	result.Object = Object{
		Kind:         KindIP,
		Handle:       "NET-192-0-2-0-1",
		Name:         "TEST-NET-1",
		NetworkType:  "DIRECT ALLOCATION",
		StartAddress: "192.0.2.0",
		EndAddress:   "192.0.2.255",
		CIDR:         []string{"192.0.2.0/24"},
		Country:      "US",
		Status:       []string{"active"},
		Events:       []Event{{Action: "registration", Date: "1992-12-01T00:00:00Z"}},
		Entities:     []Entity{{Roles: []string{"registrant"}, Organization: "Example Network Operations"}},
	}
	result.Route.Endpoint = "https://rdap.example.test/ip/192.0.2.1"
	return result
}

func sampleASNResult() LookupResult {
	result := sampleResult()
	result.Query = Target{Original: "AS64496", Canonical: "AS64496", Kind: KindASN}
	result.Object = Object{
		Kind:     KindASN,
		Handle:   "AS64496",
		ASN:      "64496",
		ASNName:  "EXAMPLE-NET",
		ASNType:  "DIRECT ALLOCATION",
		Country:  "US",
		Status:   []string{"active"},
		Events:   []Event{{Action: "registration", Date: "2010-01-01T00:00:00Z"}},
		Entities: []Entity{{Roles: []string{"registrant"}, Organization: "Example Autonomous Systems"}},
	}
	result.Route.Endpoint = "https://rdap.example.test/autnum/64496"
	return result
}

func renderForTest(t *testing.T, result LookupResult, format Format, options RenderOptions) string {
	t.Helper()
	var output bytes.Buffer
	if err := Render(&output, result, format, options); err != nil {
		t.Fatalf("Render(%s): %v", format, err)
	}
	if output.Len() == 0 {
		t.Fatalf("Render(%s) returned empty output", format)
	}
	return output.String()
}

func stripANSI(value string) string {
	return ansiEscapePattern.ReplaceAllString(value, "")
}

func assertFitsDisplayWidth(t *testing.T, output string, width int) {
	t.Helper()
	for index, line := range strings.Split(strings.TrimSuffix(stripANSI(output), "\n"), "\n") {
		if got := runewidth.StringWidth(line); got > width {
			t.Errorf("line %d uses %d display cells, want at most %d:\n%q", index+1, got, width, line)
		}
	}
}

func countFold(output, value string) int {
	return strings.Count(strings.ToLower(stripANSI(output)), strings.ToLower(value))
}

func maxPanelTitlesOnLine(output string, titles ...string) int {
	maximum := 0
	for _, line := range strings.Split(stripANSI(output), "\n") {
		count := 0
		for _, title := range titles {
			if strings.Contains(line, title) {
				count++
			}
		}
		if count > maximum {
			maximum = count
		}
	}
	return maximum
}

func findDashboardPanel(t *testing.T, view dashboardView, title string) dashboardPanel {
	t.Helper()
	for _, panel := range view.panels {
		if panel.title == title {
			return panel
		}
	}
	t.Fatalf("dashboard does not contain an exact %q panel title", title)
	return dashboardPanel{}
}

func findDashboardRow(t *testing.T, panel dashboardPanel, label string) dashboardRow {
	t.Helper()
	for _, row := range panel.rows {
		if row.label == label {
			return row
		}
	}
	t.Fatalf("%q panel does not contain a %q row", panel.title, label)
	return dashboardRow{}
}

func findDashboardBadge(t *testing.T, panel dashboardPanel, text string) dashboardBadge {
	t.Helper()
	for _, badge := range panel.badges {
		if strings.EqualFold(badge.text, text) {
			return badge
		}
	}
	t.Fatalf("%q panel does not contain a %q badge", panel.title, text)
	return dashboardBadge{}
}

func TestRenderFormats(t *testing.T) {
	for _, format := range []Format{FormatPretty, FormatTree, FormatGeekBoys, FormatPlain, FormatJSON, FormatYAML, FormatMarkdown, FormatRaw} {
		t.Run(string(format), func(t *testing.T) {
			output := renderForTest(t, sampleResult(), format, RenderOptions{Color: "never", Width: 80})
			if strings.Contains(output, "\x1b[") {
				t.Fatal("color escape sequence leaked into colorless output")
			}
		})
	}
}

func TestDNSRecordsRenderInHumanAndStructuredFormats(t *testing.T) {
	result := sampleResult()
	result.SchemaVersion = 2
	result.DNS = &DNSResult{
		Method:      "scan",
		Nameservers: []string{"ns1.example.test"},
		Records: []DNSRecord{
			{Name: "example.com", Type: "MX", TTL: 300, Value: "10 mail.example.com."},
			{Name: "_dmarc.example.com", Type: "TXT", TTL: 60, Value: `"v=DMARC1; p=none"`},
		},
		Warnings: []string{"pattern scans cannot enumerate every owner name"},
	}
	for _, format := range []Format{FormatPretty, FormatTree, FormatGeekBoys, FormatPlain, FormatJSON, FormatYAML, FormatMarkdown} {
		t.Run(string(format), func(t *testing.T) {
			output := renderForTest(t, result, format, RenderOptions{Color: "never", Width: 80})
			for _, value := range []string{"MX", "mail.example.com", "_dmarc.example.com"} {
				if !strings.Contains(output, value) {
					t.Errorf("%s output does not include %q:\n%s", format, value, output)
				}
			}
		})
	}
}

func TestPrettyDashboardResponsiveWidths(t *testing.T) {
	result := sampleResult()
	panelTitles := []string{"Registration", "Timeline", "DNS", "Contacts", "Source"}
	outputs := make(map[int]string)

	for _, width := range []int{40, 80, 120, 160} {
		t.Run(strconv.Itoa(width), func(t *testing.T) {
			output := renderForTest(t, result, FormatPretty, RenderOptions{Color: "never", Width: width})
			outputs[width] = output
			if !utf8.ValidString(output) {
				t.Fatal("dashboard output is not valid UTF-8")
			}
			assertFitsDisplayWidth(t, output, width)
			for _, title := range panelTitles {
				if !strings.Contains(output, title) {
					t.Errorf("dashboard does not contain %q panel:\n%s", title, output)
				}
			}
		})
	}

	if got := maxPanelTitlesOnLine(outputs[40], panelTitles...); got > 1 {
		t.Errorf("40-column layout placed %d panels on one row, want a one-column stack", got)
	}
	if got := maxPanelTitlesOnLine(outputs[80], panelTitles...); got < 2 {
		t.Errorf("80-column layout placed at most %d panels on one row, want a two-column layout", got)
	}
	for _, width := range []int{120, 160} {
		if got := maxPanelTitlesOnLine(outputs[width], panelTitles...); got < 3 {
			t.Errorf("%d-column layout placed at most %d panels on one row, want a three-column mosaic", width, got)
		}
	}
}

func TestPrettyDashboardBalancesEqualWidthColumns(t *testing.T) {
	const width = 120
	view := buildDashboard(sampleResult(), false)
	widths := dashboardColumnWidths(width, 3)
	columns := assignDashboardPanels(view.panels, widths, false)
	heights := make([]int, len(columns))
	minimumHeight, maximumHeight := 0, 0
	for columnIndex, panels := range columns {
		for panelIndex, panel := range panels {
			if panelIndex > 0 {
				heights[columnIndex]++
			}
			heights[columnIndex] += len(renderDashboardPanel(panel, widths[columnIndex], false))
		}
		if columnIndex == 0 || heights[columnIndex] < minimumHeight {
			minimumHeight = heights[columnIndex]
		}
		if heights[columnIndex] > maximumHeight {
			maximumHeight = heights[columnIndex]
		}
	}

	if maximumHeight-minimumHeight > 6 {
		t.Errorf("120-column dashboard leaves columns visibly unbalanced: heights %v", heights)
	}
}

func TestPrettyDashboardStartsWithPrimaryPanelsInsteadOfSummary(t *testing.T) {
	tests := []struct {
		name     string
		result   LookupResult
		panel    string
		identity string
		rowLabel string
		rowValue string
	}{
		{
			name:     "domain",
			result:   sampleResult(),
			panel:    "Registration",
			identity: "example.com",
			rowLabel: "Name",
			rowValue: "example.com",
		},
		{
			name:     "ip",
			result:   sampleIPResult(),
			panel:    "Network",
			identity: "192.0.2.1",
			rowLabel: "Query",
			rowValue: "192.0.2.1",
		},
		{
			name:     "asn",
			result:   sampleASNResult(),
			panel:    "ASN",
			identity: "64496",
			rowLabel: "ASN",
			rowValue: "64496",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			view := buildDashboard(test.result, false)
			primary := findDashboardPanel(t, view, test.panel)
			if primary.title != test.panel {
				t.Fatalf("primary panel title = %q, want exactly %q", primary.title, test.panel)
			}
			if row := findDashboardRow(t, primary, test.rowLabel); row.value != test.rowValue {
				t.Errorf("%s %s row = %q, want %q", test.panel, test.rowLabel, row.value, test.rowValue)
			}

			output := renderForTest(t, test.result, FormatPretty, RenderOptions{Color: "never", Width: 120})
			firstLine := strings.Split(strings.TrimLeft(output, "\n"), "\n")[0]
			if strings.Contains(strings.ToUpper(firstLine), "WHODIS ·") {
				t.Fatalf("dashboard retained the redundant WHODIS summary header:\n%s", output)
			}
			if !strings.Contains(firstLine, test.panel) {
				t.Errorf("dashboard does not start with its %q primary panel:\n%s", test.panel, output)
			}
			if !strings.Contains(output, test.identity) {
				t.Errorf("dashboard lost primary identity %q:\n%s", test.identity, output)
			}
		})
	}
}

func TestPrettyDashboardSparsePrimaryKeepsLookupIdentity(t *testing.T) {
	tests := []struct {
		name  string
		kind  Kind
		query string
		panel string
	}{
		{name: "domain", kind: KindDomain, query: "example.com", panel: "Registration"},
		{name: "ip", kind: KindIP, query: "192.0.2.1", panel: "Network"},
		{name: "asn", kind: KindASN, query: "64496", panel: "ASN"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := LookupResult{
				Query:  Target{Canonical: test.query, Kind: test.kind},
				Object: Object{Kind: test.kind},
			}
			view := buildDashboard(result, false)
			primary := findDashboardPanel(t, view, test.panel)
			rendered := strings.Join(renderDashboardPanel(primary, 80, false), "\n")
			if !strings.Contains(rendered, test.query) {
				t.Errorf("sparse %s panel lost lookup target %q:\n%s", test.panel, test.query, rendered)
			}
		})
	}
}

func TestPrettyDashboardPlacesProtocolAndStatusesInRelevantPanels(t *testing.T) {
	tests := []struct {
		name   string
		result LookupResult
		panel  string
	}{
		{name: "domain", result: sampleResult(), panel: "Registration"},
		{name: "ip", result: sampleIPResult(), panel: "Network"},
		{name: "asn", result: sampleASNResult(), panel: "ASN"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			view := buildDashboard(test.result, false)
			primary := findDashboardPanel(t, view, test.panel)
			for _, status := range uniqueFold(test.result.Object.Status) {
				badge := findDashboardBadge(t, primary, strings.ToUpper(status))
				if badge.tone != statusBadgeTone(status) {
					t.Errorf("status %q tone = %v, want %v", status, badge.tone, statusBadgeTone(status))
				}
			}

			source := findDashboardPanel(t, view, "Source")
			if row := findDashboardRow(t, source, "Protocol"); !strings.EqualFold(row.value, string(test.result.Route.Protocol)) {
				t.Errorf("Source Protocol row = %q, want %q", row.value, test.result.Route.Protocol)
			}
		})
	}
}

func TestStatusBadgeToneDistinguishesRegistryConstraints(t *testing.T) {
	for _, status := range []string{
		"client transfer prohibited",
		"clientTransferProhibited",
		"server update prohibited",
		"serverHold",
		"client hold",
		"pendingDelete",
		"pending_delete",
		"pending-delete",
		"pending validation",
	} {
		if got := statusBadgeTone(status); got != badgeConstraint {
			t.Errorf("statusBadgeTone(%q) = %v, want constraint tone", status, got)
		}
	}
	if got := statusBadgeTone("active"); got != badgeStatus {
		t.Errorf("statusBadgeTone(active) = %v, want normal status tone", got)
	}

	constraintStyle := styleDashboardBadge("[CLIENT TRANSFER PROHIBITED]", badgeConstraint, true)
	normalStyle := styleDashboardBadge("[CLIENT TRANSFER PROHIBITED]", badgeStatus, true)
	if constraintStyle == normalStyle {
		t.Fatal("constraint and ordinary status badges use the same ANSI styling")
	}
}

func TestPrettyDashboardObjectKinds(t *testing.T) {
	tests := []struct {
		name       string
		result     LookupResult
		mainPanel  string
		mainValues []string
	}{
		{
			name:       "domain",
			result:     sampleResult(),
			mainPanel:  "Registration",
			mainValues: []string{"example.com", "株式会社レジストラ"},
		},
		{
			name:       "ip",
			result:     sampleIPResult(),
			mainPanel:  "Network",
			mainValues: []string{"192.0.2.0/24", "192.0.2.255", "DIRECT ALLOCATION"},
		},
		{
			name:       "asn",
			result:     sampleASNResult(),
			mainPanel:  "ASN",
			mainValues: []string{"64496", "EXAMPLE-NET", "DIRECT ALLOCATION"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := renderForTest(t, test.result, FormatPretty, RenderOptions{Color: "never", Width: 120})
			if !strings.Contains(output, test.mainPanel) {
				t.Fatalf("output does not contain %q panel:\n%s", test.mainPanel, output)
			}
			for _, value := range test.mainValues {
				if !strings.Contains(output, value) {
					t.Errorf("output does not contain %q:\n%s", value, output)
				}
			}
			assertFitsDisplayWidth(t, output, 120)
		})
	}
}

func TestPrettyDashboardOmitsEmptyPanels(t *testing.T) {
	result := sampleResult()
	result.Object = Object{Kind: KindDomain, Name: "example.com"}
	output := renderForTest(t, result, FormatPretty, RenderOptions{Color: "never", Width: 120})

	for _, title := range []string{"Registration", "Source"} {
		if !strings.Contains(output, title) {
			t.Errorf("minimal result does not contain %q panel:\n%s", title, output)
		}
	}
	for _, title := range []string{"Timeline", "DNS", "Contacts", "Notices"} {
		if strings.Contains(output, title) {
			t.Errorf("minimal result unexpectedly contains empty %q panel:\n%s", title, output)
		}
	}
}

func TestPrettyDashboardDeduplicatesRepeatedData(t *testing.T) {
	output := renderForTest(t, sampleResult(), FormatPretty, RenderOptions{Color: "never", Width: 160})

	for value, want := range map[string]int{
		"active":               1,
		"ns1.example.test":     1,
		"2024-03-01T01:02:03Z": 1,
	} {
		if got := countFold(output, value); got != want {
			t.Errorf("%q occurs %d times, want %d:\n%s", value, got, want, output)
		}
	}
}

func TestPrettyDashboardConsolidatesContacts(t *testing.T) {
	output := renderForTest(t, sampleResult(), FormatPretty, RenderOptions{Color: "never", Width: 160})

	for _, value := range []string{
		"Contacts",
		"registrant",
		"technical",
		"Aleksandr Example",
		"Café Example LLC",
		"admin@example.test",
		"+1.555.0100",
		"HANDLE-ONLY-42",
	} {
		if !strings.Contains(output, value) {
			t.Errorf("contact output does not contain %q:\n%s", value, output)
		}
	}

	for _, value := range []string{"Aleksandr Example", "Café Example LLC", "admin@example.test"} {
		if got := strings.Count(output, value); got != 1 {
			t.Errorf("consolidated contact value %q occurs %d times, want once:\n%s", value, got, output)
		}
	}
}

func TestPrettyDashboardNoticeDisclosure(t *testing.T) {
	result := sampleResult()
	defaultOutput := renderForTest(t, result, FormatPretty, RenderOptions{Color: "never", Width: 120})

	for _, value := range []string{"2 hidden", "use --details"} {
		if !strings.Contains(defaultOutput, value) {
			t.Errorf("default output does not contain notice summary %q:\n%s", value, defaultOutput)
		}
	}
	for _, hidden := range []string{
		"Terms of Service",
		"Legal body alpha — supplied once.",
		"https://example.test/terms",
		"Service Status",
		"Operational message beta.",
		"https://status.example.test/rdap",
	} {
		if strings.Contains(defaultOutput, hidden) {
			t.Errorf("default output unexpectedly exposes notice detail %q:\n%s", hidden, defaultOutput)
		}
	}

	detailedOutput := renderForTest(t, result, FormatPretty, RenderOptions{Color: "never", Width: 120, Details: true})
	if !strings.Contains(detailedOutput, "Notices · 2") {
		t.Errorf("detailed output does not contain deduplicated notice panel count:\n%s", detailedOutput)
	}
	for _, value := range []string{
		"Terms of Service",
		"Legal body alpha — supplied once.",
		"https://example.test/terms",
		"Service Status",
		"Operational message beta.",
		"https://status.example.test/rdap",
	} {
		if got := countFold(detailedOutput, value); got != 1 {
			t.Errorf("notice detail %q occurs %d times, want once:\n%s", value, got, detailedOutput)
		}
	}
	assertFitsDisplayWidth(t, detailedOutput, 120)
}

func TestPrettyDashboardUnicodeAndANSIWidths(t *testing.T) {
	result := sampleResult()
	result.Object.Registrar += " · Cafe\u0301"
	for _, width := range []int{40, 80, 120, 160} {
		t.Run(strconv.Itoa(width), func(t *testing.T) {
			output := renderForTest(t, result, FormatPretty, RenderOptions{Color: "always", Width: width})
			if !strings.Contains(output, "\x1b[") {
				t.Fatal("color=always output does not contain ANSI styling")
			}
			if !utf8.ValidString(output) {
				t.Fatal("styled dashboard output is not valid UTF-8")
			}
			assertFitsDisplayWidth(t, output, width)
		})
	}
}

func TestPrettyDashboardTinyWidthIsBorderless(t *testing.T) {
	const width = 24
	output := renderForTest(t, sampleResult(), FormatPretty, RenderOptions{Color: "never", Width: width})
	assertFitsDisplayWidth(t, output, width)
	if strings.ContainsAny(output, "┌┐└┘╭╮╰╯│") {
		t.Errorf("tiny fallback should be borderless:\n%s", output)
	}
}

func TestPrettyDashboardExtremeNarrowWidths(t *testing.T) {
	result := sampleResult()
	result.Object.Events = append(result.Object.Events, Event{
		Action: "last update of an exceptionally verbose registry database",
		Date:   "",
	})
	result.Object.Entities = append(result.Object.Entities, Entity{
		Roles:        []string{"administrative contact with a deliberately long role"},
		Organization: "Long Contact Organization",
		Email:        "long-contact@example.test",
	})
	result.Object.Notices = append(result.Object.Notices, Notice{
		Title:       "A registry notice title that must wrap",
		Description: []string{"A detailed notice body that remains valid at the smallest widths."},
		Links:       []string{"https://example.test/a/very/long/unbroken/registry/notice/link"},
	})

	for _, width := range []int{1, 2, 8, 24, 31} {
		t.Run(strconv.Itoa(width), func(t *testing.T) {
			output := renderForTest(t, result, FormatPretty, RenderOptions{Color: "always", Width: width, Details: true})
			if !utf8.ValidString(output) {
				t.Fatal("narrow dashboard output is not valid UTF-8")
			}
			assertFitsDisplayWidth(t, output, width)
		})
	}
}

func TestPrettyDashboardKeepsWHOISExtrasOutOfPrettyView(t *testing.T) {
	result := sampleResult()
	result.Object.Extras = map[string][]string{
		"Domain Name":       {"example.com"},
		"WHOIS legal block": {"WHOIS-ONLY-EXTRA-SENTINEL"},
	}
	output := renderForTest(t, result, FormatPretty, RenderOptions{Color: "never", Width: 120, Details: true})
	if strings.Contains(output, "WHOIS-ONLY-EXTRA-SENTINEL") || strings.Contains(output, "Additional") {
		t.Fatalf("pretty output exposed duplicate raw WHOIS extras:\n%s", output)
	}
}

func TestPrettyDashboardContactMatchingIsConservative(t *testing.T) {
	result := sampleResult()
	result.Object.Entities = []Entity{
		{Roles: []string{"registrant"}, Handle: "CONTACT-1", Organization: "Shared Privacy Service", Email: "one@example.test"},
		{Roles: []string{"technical"}, Handle: "CONTACT-2", Organization: "Shared Privacy Service", Email: "two@example.test"},
	}
	output := renderForTest(t, result, FormatPretty, RenderOptions{Color: "never", Width: 120})
	if !strings.Contains(output, "Contacts · 2") {
		t.Fatalf("unrelated contacts sharing an organization were merged:\n%s", output)
	}
	for _, value := range []string{"CONTACT-1", "CONTACT-2", "one@example.test", "two@example.test"} {
		if countFold(output, value) != 1 {
			t.Errorf("contact value %q was lost or duplicated:\n%s", value, output)
		}
	}
}

func TestPrettyDashboardRetainsPopulatedNormalizedFields(t *testing.T) {
	result := sampleResult()
	result.Object.NetworkType = "SPECIAL NETWORK TYPE"
	result.Object.StartAddress = "192.0.2.0"
	result.Object.EndAddress = "192.0.2.255"
	result.Object.CIDR = []string{"192.0.2.0/24"}
	result.Object.Country = "US"
	result.Object.ASN = "64496"
	result.Object.ASNName = "EXAMPLE-AS"
	result.Object.ASNType = "DIRECT ALLOCATION"
	output := renderForTest(t, result, FormatPretty, RenderOptions{Color: "never", Width: 160})
	for _, value := range []string{
		"SPECIAL NETWORK TYPE", "192.0.2.0", "192.0.2.255", "192.0.2.0/24",
		"US", "64496", "EXAMPLE-AS", "DIRECT ALLOCATION",
	} {
		if !strings.Contains(output, value) {
			t.Errorf("populated normalized value %q is missing:\n%s", value, output)
		}
	}
}

func TestPrettyDashboardHandlesUnknownEventDates(t *testing.T) {
	result := sampleResult()
	result.Object.Events = []Event{
		{Action: "delegation"},
		{Action: "last changed"},
		{Action: "last changed", Date: "2026-02-03T04:05:06Z"},
	}
	output := renderForTest(t, result, FormatPretty, RenderOptions{Color: "never", Width: 80})
	if countFold(output, "unknown") != 1 {
		t.Fatalf("missing-date event was not rendered exactly once:\n%s", output)
	}
	if countFold(output, "2026-02-03T04:05:06Z") != 1 {
		t.Fatalf("known event date did not replace the placeholder:\n%s", output)
	}
}

func TestDashboardWidthHasSafetyCeiling(t *testing.T) {
	if got := dashboardWidth(&bytes.Buffer{}, maximumDashboardWidth*1000); got != maximumDashboardWidth {
		t.Fatalf("dashboardWidth() = %d, want safety ceiling %d", got, maximumDashboardWidth)
	}
}

func TestPrettyDashboardOmitsEmptySource(t *testing.T) {
	result := LookupResult{Query: Target{Canonical: "example.com", Kind: KindDomain}}
	output := renderForTest(t, result, FormatPretty, RenderOptions{Color: "never", Width: 80})
	if strings.Contains(output, "Source") {
		t.Fatalf("sparse lookup rendered an empty Source panel:\n%s", output)
	}
}

func TestDetailsDoesNotChangeNonPrettyFormats(t *testing.T) {
	for _, format := range []Format{FormatPlain, FormatJSON, FormatYAML, FormatMarkdown, FormatRaw} {
		t.Run(string(format), func(t *testing.T) {
			withoutDetails := renderForTest(t, sampleResult(), format, RenderOptions{Color: "never", Width: 80})
			withDetails := renderForTest(t, sampleResult(), format, RenderOptions{Color: "never", Width: 80, Details: true})
			if withDetails != withoutDetails {
				t.Errorf("--details changed %s output\nwithout details:\n%s\nwith details:\n%s", format, withoutDetails, withDetails)
			}
		})
	}
}
