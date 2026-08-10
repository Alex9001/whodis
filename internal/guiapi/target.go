package guiapi

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Alex9001/whodis"
)

func normalizeTarget(input string) (string, error) {
	value := strings.TrimSpace(input)
	if value == "" {
		return "", fmt.Errorf("a domain, IP address, CIDR, ASN, or URL is required")
	}
	if !strings.Contains(value, "://") {
		return value, nil
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("URL scheme must be http or https")
	}
	host := parsed.Hostname()
	if host == "" {
		return "", fmt.Errorf("URL does not contain a hostname")
	}
	return host, nil
}

func parseTarget(input string) (parseResult, error) {
	normalized, err := normalizeTarget(input)
	if err != nil {
		return parseResult{}, err
	}
	target, err := whodis.ParseTarget(normalized)
	if err != nil {
		return parseResult{}, err
	}
	return parseResult{Input: input, Normalized: normalized, Target: target}, nil
}
