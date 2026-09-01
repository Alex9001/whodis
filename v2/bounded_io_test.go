package whodis

import (
	"strings"
	"testing"
)

func TestReadLimitedBodyRejectsOversizedProtocolResponse(t *testing.T) {
	payload, err := readLimitedBody(strings.NewReader("12345"), 5)
	if err != nil || string(payload) != "12345" {
		t.Fatalf("exact limit = %q, %v", payload, err)
	}
	if _, err := readLimitedBody(strings.NewReader("123456"), 5); err == nil {
		t.Fatal("oversized response was accepted")
	}
}
