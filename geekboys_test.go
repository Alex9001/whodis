package whodis

import (
	"io"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/mattn/go-runewidth"
)

func geekBoysGoldenResult() LookupResult {
	return LookupResult{
		Query: Target{Original: "example.test", Canonical: "example.test", Kind: KindDomain},
		Route: RouteDecision{
			Protocol:        ProtocolRDAP,
			Endpoint:        "https://rdap.example/",
			DiscoverySource: "bootstrap",
		},
		Object: Object{
			Kind:        KindDomain,
			Name:        "example.test",
			Status:      []string{"active", "client transfer prohibited"},
			DNSSEC:      "signed",
			Nameservers: []string{"ns1.example.test"},
		},
	}
}

func TestGeekBoysGoldenStacked(t *testing.T) {
	got := renderGeekBoys(io.Discard, geekBoysGoldenResult(), RenderOptions{Color: "always", Width: 48})
	want := `.--- Registration -----------------------------+
| + ACTIVE +  + CLIENT TRANSFER PROHIBITED +   |
|                                              |
| Name: example.test                           |
+----------------------------------------------'

.--- DNS - 1 ----------------------------------+
| DNSSEC: signed                               |
|                                              |
| - ns1.example.test                           |
+----------------------------------------------'

.--- Source -----------------------------------+
| Protocol : RDAP                              |
| Authority: https://rdap.example/             |
| Discovery: bootstrap                         |
+----------------------------------------------'
`
	if got != want {
		t.Fatalf("retro output changed\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}

func TestGeekBoysResponsiveColorlessAndUnicodeSafe(t *testing.T) {
	result := sampleResult()
	for _, width := range []int{1, 19, 40, 79, 80, 86, 120} {
		output := renderGeekBoys(io.Discard, result, RenderOptions{Color: "always", Width: width, Details: true})
		if !utf8.ValidString(output) {
			t.Errorf("width %d produced invalid UTF-8", width)
		}
		if strings.Contains(output, "\x1b[") {
			t.Errorf("width %d emitted ANSI despite the retro format's colorless contract", width)
		}
		if strings.ContainsAny(output, "╭╮╰╯─│•↗") {
			t.Errorf("width %d emitted non-ASCII decorative geometry:\n%s", width, output)
		}
		if !strings.HasSuffix(output, "\n") || strings.HasSuffix(output, "\n\n") {
			t.Errorf("width %d does not have exactly one trailing newline", width)
		}

		limit := min(width, maximumGeekBoysWidth)
		for lineIndex, line := range strings.Split(strings.TrimSuffix(output, "\n"), "\n") {
			if got := runewidth.StringWidth(line); got > limit {
				t.Errorf("width %d line %d uses %d display cells, want at most %d: %q", width, lineIndex+1, got, limit, line)
			}
		}
	}

	wide := renderGeekBoys(io.Discard, result, RenderOptions{Color: "always", Width: 120, Details: true})
	for _, value := range []string{"例え.example", "株式会社レジストラ 🚀", "Legal body alpha — supplied once.", "https://example.test/terms"} {
		if !strings.Contains(wide, value) {
			t.Errorf("wide output lost Unicode or details value %q:\n%s", value, wide)
		}
	}
}

func TestGeekBoysLayoutStartsWithPrimaryPanel(t *testing.T) {
	tests := []struct {
		name   string
		result LookupResult
		title  string
	}{
		{name: "domain", result: sampleResult(), title: ".--- Registration "},
		{name: "IP", result: sampleIPResult(), title: ".--- Network "},
		{name: "ASN", result: sampleASNResult(), title: ".--- ASN "},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := renderGeekBoys(io.Discard, test.result, RenderOptions{Width: 86})
			firstLine := strings.SplitN(output, "\n", 2)[0]
			if !strings.HasPrefix(firstLine, test.title) {
				t.Fatalf("output starts with %q, want primary panel %q", firstLine, test.title)
			}
			if strings.Contains(firstLine, test.result.Query.Canonical) || strings.Contains(firstLine, string(test.result.Route.Protocol)) {
				t.Fatalf("target or protocol leaked above the primary panel: %q", firstLine)
			}
		})
	}
}

func TestGeekBoysSwitchesFromStackToTwoBalancedColumns(t *testing.T) {
	result := sampleResult()
	stacked := renderGeekBoys(io.Discard, result, RenderOptions{Width: 79})
	stackedFirstLine := strings.SplitN(stacked, "\n", 2)[0]
	if got := strings.Count(stackedFirstLine, ".--- "); got != 1 {
		t.Fatalf("79-column output has %d panels on its first line, want a stack:\n%s", got, stacked)
	}

	columns := renderGeekBoys(io.Discard, result, RenderOptions{Width: 80})
	columnsFirstLine := strings.SplitN(columns, "\n", 2)[0]
	if got := strings.Count(columnsFirstLine, ".--- "); got != 2 {
		t.Fatalf("80-column output has %d panels on its first line, want two columns:\n%s", got, columns)
	}

	view := buildDashboard(result, false)
	panels := append([]dashboardPanel(nil), view.panels...)
	assigned := assignGeekBoysPanels(panels, []int{39, 39})
	heights := make([]int, len(assigned))
	for columnIndex, column := range assigned {
		for panelIndex, panel := range column {
			if panelIndex > 0 {
				heights[columnIndex]++
			}
			heights[columnIndex] += len(renderGeekBoysPanel(panel, 39))
		}
	}
	if difference := heights[0] - heights[1]; difference > 12 || difference < -12 {
		t.Fatalf("masonry columns are poorly balanced: heights %v", heights)
	}
}

func TestGeekBoysOmitsNoticeDetailsUnlessRequested(t *testing.T) {
	result := sampleResult()
	result.RetrievedAt = time.Time{}
	hidden := renderGeekBoys(io.Discard, result, RenderOptions{Width: 86})
	shown := renderGeekBoys(io.Discard, result, RenderOptions{Width: 86, Details: true})
	if strings.Contains(hidden, "Legal body alpha") {
		t.Fatal("notice details appeared without Details")
	}
	if !strings.Contains(shown, "Legal body alpha") || !strings.Contains(shown, "URL: https://example.test/terms") {
		t.Fatalf("requested notice details are missing:\n%s", shown)
	}
}

func TestGeekBoysPreservesLongValuesWhenTheyFitOnTheirOwnLine(t *testing.T) {
	result := sampleResult()
	const timestamp = "2023-12-28T17:24:56-05:00"
	const endpoint = "https://rdap.registry.test/v1/"
	result.Object.Events = []Event{{Action: "last changed", Date: timestamp}}
	result.Route.Endpoint = endpoint
	output := renderGeekBoys(io.Discard, result, RenderOptions{Width: 86})
	for _, value := range []string{timestamp, endpoint} {
		if !strings.Contains(output, value) {
			t.Errorf("GeekBoys split a value that fits on its own line, missing %q:\n%s", value, output)
		}
	}
}

func TestGeekBoysLabelsContactsWithoutRoles(t *testing.T) {
	result := sampleResult()
	result.Object.Entities = []Entity{{Name: "Unassigned Person", Email: "person@example.test"}}
	output := renderGeekBoys(io.Discard, result, RenderOptions{Width: 86})
	if !strings.Contains(output, "Contact:") ||
		!strings.Contains(output, "Unassigned Person") ||
		!strings.Contains(output, "person@example.test") {
		t.Fatalf("role-less contact has no structural label:\n%s", output)
	}
	if strings.Contains(output, ": Unassigned Person") && !strings.Contains(output, "Contact: Unassigned Person") {
		t.Fatalf("role-less contact rendered with an empty label:\n%s", output)
	}
}
