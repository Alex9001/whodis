package helpdocs

import (
	"embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

//go:embed catalog.json topics/*.md
var content embed.FS

type Topic struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Summary string `json:"summary"`
	File    string `json:"file"`
	Body    string `json:"-"`
}

var (
	loadOnce sync.Once
	topics   []Topic
	loadErr  error
)

func Topics() ([]Topic, error) {
	loadOnce.Do(load)
	if loadErr != nil {
		return nil, loadErr
	}
	result := make([]Topic, len(topics))
	copy(result, topics)
	return result, nil
}

func Find(id string) (Topic, bool) {
	values, err := Topics()
	if err != nil {
		return Topic{}, false
	}
	id = strings.ToLower(strings.TrimSpace(id))
	for _, topic := range values {
		if topic.ID == id {
			return topic, true
		}
	}
	return Topic{}, false
}

func load() {
	payload, err := content.ReadFile("catalog.json")
	if err != nil {
		loadErr = err
		return
	}
	var catalog struct {
		Topics []Topic `json:"topics"`
	}
	if err := json.Unmarshal(payload, &catalog); err != nil {
		loadErr = err
		return
	}
	seen := make(map[string]bool, len(catalog.Topics))
	for index := range catalog.Topics {
		topic := &catalog.Topics[index]
		topic.ID = strings.ToLower(strings.TrimSpace(topic.ID))
		if topic.ID == "" || topic.Title == "" || topic.File == "" || seen[topic.ID] {
			loadErr = fmt.Errorf("invalid or duplicate help topic %q", topic.ID)
			return
		}
		seen[topic.ID] = true
		body, err := content.ReadFile(topic.File)
		if err != nil {
			loadErr = fmt.Errorf("help topic %s: %w", topic.ID, err)
			return
		}
		topic.Body = strings.TrimSpace(string(body)) + "\n"
	}
	topics = catalog.Topics
}

var markdownLink = regexp.MustCompile(`\[([^]]+)\]\((https://[^)]+)\)`)

func Terminal(topic Topic) string {
	lines := strings.Split(strings.ReplaceAll(topic.Body, "\r\n", "\n"), "\n")
	result := make([]string, 0, len(lines))
	inFence := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			inFence = !inFence
			continue
		}
		if inFence && line != "" {
			line = "  " + line
		}
		if strings.HasPrefix(trimmed, "#") {
			line = strings.TrimSpace(strings.TrimLeft(trimmed, "#"))
		}
		line = strings.ReplaceAll(line, "**", "")
		line = strings.ReplaceAll(line, "`", "")
		line = markdownLink.ReplaceAllString(line, "$1 ($2)")
		result = append(result, strings.TrimRight(line, " \t"))
	}
	return strings.TrimSpace(strings.Join(result, "\n")) + "\n"
}

func IDs() []string {
	values, err := Topics()
	if err != nil {
		return nil
	}
	ids := make([]string, len(values))
	for index, topic := range values {
		ids[index] = topic.ID
	}
	sort.Strings(ids)
	return ids
}
