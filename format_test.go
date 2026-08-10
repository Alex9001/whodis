package whodis

import "testing"

func TestParseFormatHumanAliases(t *testing.T) {
	tests := map[string]Format{
		"":          FormatPretty,
		"pretty":    FormatPretty,
		"dashboard": FormatPretty,
		"grid":      FormatPretty,
		"current":   FormatPretty,
		"tree":      FormatTree,
		"geekboys":  FormatGeekBoys,
		"geek-boys": FormatGeekBoys,
		"retro":     FormatGeekBoys,
		"plain":     FormatPlain,
		"text":      FormatPlain,
		"txt":       FormatPlain,
	}

	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			got, err := ParseFormat(input)
			if err != nil {
				t.Fatalf("ParseFormat(%q) error = %v", input, err)
			}
			if got != want {
				t.Fatalf("ParseFormat(%q) = %q, want %q", input, got, want)
			}
		})
	}
}

func TestParseFormatRejectsUnknownValue(t *testing.T) {
	if _, err := ParseFormat("spreadsheet-ish"); err == nil {
		t.Fatal("ParseFormat accepted an unknown output format")
	}
}
