package whodis

import "testing"

func TestProductUserAgentUsesInjectedVersion(t *testing.T) {
	previous := version
	version = "v1.0.1"
	t.Cleanup(func() { version = previous })

	const want = "whodis/1.0.1 (+https://github.com/Alex9001/whodis)"
	if got := productUserAgent(); got != want {
		t.Fatalf("productUserAgent() = %q, want %q", got, want)
	}
}
