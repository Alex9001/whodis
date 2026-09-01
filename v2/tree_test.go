package whodis

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func renderTreeForTest(result LookupResult, options RenderOptions) string {
	return renderTree(&bytes.Buffer{}, result, options)
}

func TestTreeUsesSemanticHierarchyAndDeduplicatedData(t *testing.T) {
	output := renderTreeForTest(sampleResult(), RenderOptions{Color: "never", Width: 80})
	lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	if lines[0] != "example.com" {
		t.Fatalf("tree root = %q, want original query", lines[0])
	}

	for _, value := range []string{
		"├── Registration",
		"├── Status",
		"ACTIVE",
		"CLIENT TRANSFER PROHIBITED",
		"├── Timeline · 2",
		"├── DNS · 2",
		"Nameservers",
		"Contacts · 2",
		"└── Source",
		"Protocol: RDAP",
		"株式会社レジストラ 🚀",
	} {
		if !strings.Contains(output, value) {
			t.Errorf("tree output does not contain %q:\n%s", value, output)
		}
	}
	if strings.Contains(output, "Name: example.com") {
		t.Fatalf("tree repeated a Name row identical to the root:\n%s", output)
	}
	for value, want := range map[string]int{
		"ACTIVE":               1,
		"NS1.EXAMPLE.TEST":     1,
		"2024-03-01T01:02:03Z": 1,
		"Aleksandr Example":    1,
		"admin@example.test":   1,
	} {
		if got := countFold(output, value); got != want {
			t.Errorf("%q occurs %d times, want %d:\n%s", value, got, want, output)
		}
	}
}

func TestTreeObjectKindsAndDuplicateRootSuppression(t *testing.T) {
	tests := []struct {
		name       string
		result     LookupResult
		root       string
		panel      string
		duplicate  string
		wantValues []string
	}{
		{
			name:       "domain",
			result:     sampleResult(),
			root:       "example.com",
			panel:      "Registration",
			duplicate:  "Name: example.com",
			wantValues: []string{"DOMAIN-123", "client transfer prohibited"},
		},
		{
			name:       "ip",
			result:     sampleIPResult(),
			root:       "192.0.2.1",
			panel:      "Network",
			duplicate:  "Query: 192.0.2.1",
			wantValues: []string{"192.0.2.0/24", "192.0.2.255", "DIRECT ALLOCATION"},
		},
		{
			name:       "asn",
			result:     sampleASNResult(),
			root:       "AS64496",
			panel:      "ASN",
			wantValues: []string{"64496", "EXAMPLE-NET", "DIRECT ALLOCATION"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := renderTreeForTest(test.result, RenderOptions{Color: "never", Width: 80})
			if first := strings.Split(output, "\n")[0]; first != test.root {
				t.Fatalf("root = %q, want %q", first, test.root)
			}
			if !strings.Contains(output, test.panel) {
				t.Errorf("tree does not contain %q panel:\n%s", test.panel, output)
			}
			if test.duplicate != "" && strings.Contains(output, test.duplicate) {
				t.Errorf("tree repeated root as %q:\n%s", test.duplicate, output)
			}
			for _, value := range test.wantValues {
				if !strings.Contains(strings.ToLower(output), strings.ToLower(value)) {
					t.Errorf("tree does not contain %q:\n%s", value, output)
				}
			}
		})
	}
}

func TestTreeNoticeDisclosure(t *testing.T) {
	result := sampleResult()
	defaultOutput := renderTreeForTest(result, RenderOptions{Color: "never", Width: 80})
	if !strings.Contains(defaultOutput, "Notices: 2 hidden · use --details") {
		t.Fatalf("default tree lost notice summary:\n%s", defaultOutput)
	}
	if strings.Contains(defaultOutput, "Terms of Service") {
		t.Fatalf("default tree exposed detailed notices:\n%s", defaultOutput)
	}

	detailedOutput := renderTreeForTest(result, RenderOptions{Color: "never", Width: 80, Details: true})
	for _, value := range []string{
		"Notices · 2",
		"Terms of Service",
		"Description: Legal body alpha — supplied once.",
		"Link: https://example.test/terms",
		"Service Status",
		"Operational message beta.",
	} {
		if countFold(detailedOutput, value) != 1 {
			t.Errorf("detailed tree should contain %q exactly once:\n%s", value, detailedOutput)
		}
	}
}

func TestTreeWidthColorAndTermination(t *testing.T) {
	result := sampleResult()
	result.Object.Events = append(result.Object.Events, Event{
		Action: "an exceptionally verbose registry event whose label must wrap",
		Date:   "2026-08-09T12:34:56Z",
	})
	result.Object.Notices = append(result.Object.Notices, Notice{
		Title:       "A deliberately long registry notice",
		Description: []string{"Detailed registry text which remains readable at narrow widths."},
		Links:       []string{"https://example.test/a/very/long/unbroken/registry/notice/link"},
	})

	for _, width := range []int{1, 20, 40, 80} {
		t.Run(strconv.Itoa(width), func(t *testing.T) {
			output := renderTreeForTest(result, RenderOptions{Color: "always", Width: width, Details: true})
			if !utf8.ValidString(output) {
				t.Fatal("tree output is not valid UTF-8")
			}
			if !strings.Contains(output, "\x1b[") {
				t.Fatal("color=always tree does not contain ANSI styling")
			}
			if !strings.HasSuffix(output, "\n") || strings.HasSuffix(output, "\n\n") {
				t.Fatalf("tree must end with exactly one newline: %q", output[len(output)-min(len(output), 8):])
			}
			assertFitsDisplayWidth(t, output, width)
		})
	}
}

func TestTreeRootFallbackAndSanitization(t *testing.T) {
	tests := []struct {
		name   string
		result LookupResult
		want   string
	}{
		{
			name: "safe original",
			result: LookupResult{
				Query:  Target{Original: "example.com\nspoofed", Canonical: "example.com"},
				Object: Object{Name: "example.com"},
			},
			want: "example.com spoofed",
		},
		{
			name: "canonical",
			result: LookupResult{
				Query: Target{Original: "\x00\x01", Canonical: "example.net"},
			},
			want: "example.net",
		},
		{
			name: "name",
			result: LookupResult{
				Object: Object{Name: "example.org"},
			},
			want: "example.org",
		},
		{
			name: "handle",
			result: LookupResult{
				Object: Object{Handle: "HANDLE-1"},
			},
			want: "HANDLE-1",
		},
		{
			name:   "empty",
			result: LookupResult{},
			want:   "Lookup",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := renderTreeForTest(test.result, RenderOptions{Color: "never", Width: 80})
			if first := strings.Split(output, "\n")[0]; first != test.want {
				t.Fatalf("tree root = %q, want %q\n%s", first, test.want, output)
			}
		})
	}
}

func TestTreeStatusColorsKeepConstraintsDistinct(t *testing.T) {
	output := renderTreeForTest(sampleResult(), RenderOptions{Color: "always", Width: 80})
	if !strings.Contains(output, "\x1b[1;38;5;42mACTIVE") {
		t.Fatalf("ordinary status did not use success styling:\n%q", output)
	}
	if !strings.Contains(output, "\x1b[1;38;5;220mCLIENT TRANSFER PROHIBITED") {
		t.Fatalf("constraint status did not use warning styling:\n%q", output)
	}
}

func TestTreeSuppressesEquivalentRootIdentifiers(t *testing.T) {
	tests := []struct {
		name       string
		result     LookupResult
		absent     []string
		stillShown string
	}{
		{
			name: "trailing dot and case",
			result: LookupResult{
				Query:  Target{Original: "google.com.", Canonical: "google.com", Kind: KindDomain},
				Object: Object{Kind: KindDomain, Name: "GOOGLE.COM"},
			},
			absent: []string{"Name: GOOGLE.COM"},
		},
		{
			name: "unicode display name",
			result: LookupResult{
				Query: Target{Original: "bücher.com", Canonical: "xn--bcher-kva.com", Kind: KindDomain},
				Object: Object{
					Kind:        KindDomain,
					Name:        "xn--bcher-kva.com",
					UnicodeName: "bücher.com",
				},
			},
			absent:     []string{"Unicode: bücher.com"},
			stillShown: "Name: xn--bcher-kva.com",
		},
		{
			name:   "ASN spelling",
			result: sampleASNResult(),
			absent: []string{"ASN: 64496", "Handle: AS64496"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := renderTreeForTest(test.result, RenderOptions{Color: "never", Width: 80})
			for _, absent := range test.absent {
				if strings.Contains(output, absent) {
					t.Errorf("tree repeated root identity as %q:\n%s", absent, output)
				}
			}
			if test.stillShown != "" && !strings.Contains(output, test.stillShown) {
				t.Errorf("tree removed useful alternate identity %q:\n%s", test.stillShown, output)
			}
		})
	}
}

func TestTreePreservesLongValuesWhenTheyFitOnTheirOwnLine(t *testing.T) {
	result := sampleResult()
	const timestamp = "2023-12-28T17:24:56-05:00"
	const endpoint = "https://rdap.registry.test/v1/"
	result.Object.Events = []Event{{Action: "last changed", Date: timestamp}}
	result.Route.Endpoint = endpoint
	output := renderTreeForTest(result, RenderOptions{Color: "never", Width: 40})
	for _, value := range []string{timestamp, endpoint} {
		if !strings.Contains(output, value) {
			t.Errorf("tree split a value that fits on its own line, missing %q:\n%s", value, output)
		}
	}
}

func TestTreeLabelsContactsWithoutRoles(t *testing.T) {
	result := sampleResult()
	result.Object.Entities = []Entity{{Name: "Unassigned Person", Email: "person@example.test"}}
	output := renderTreeForTest(result, RenderOptions{Color: "never", Width: 80})
	if !strings.Contains(output, "Contact: Unassigned Person · person@example.test") {
		t.Fatalf("role-less contact has no structural label:\n%s", output)
	}
}
