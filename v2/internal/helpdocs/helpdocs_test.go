package helpdocs

import (
	"strings"
	"testing"
)

func TestCatalogLoadsAndTerminalRenderingIsClean(t *testing.T) {
	values, err := Topics()
	if err != nil {
		t.Fatal(err)
	}
	if len(values) < 8 {
		t.Fatalf("topics = %d", len(values))
	}
	seen := map[string]bool{}
	for _, topic := range values {
		if seen[topic.ID] || topic.Title == "" || topic.Summary == "" || topic.Body == "" {
			t.Fatalf("invalid topic %#v", topic)
		}
		seen[topic.ID] = true
		rendered := Terminal(topic)
		if strings.Contains(rendered, "```") || strings.Contains(rendered, "**") || !strings.Contains(rendered, topic.Title) {
			t.Fatalf("terminal rendering for %s:\n%s", topic.ID, rendered)
		}
	}
}
