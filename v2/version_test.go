package whodis

import (
	"runtime/debug"
	"testing"
)

func TestProductUserAgentUsesInjectedVersion(t *testing.T) {
	previous := version
	version = "v1.0.1"
	t.Cleanup(func() { version = previous })

	const want = "whodis/1.0.1 (+https://github.com/Alex9001/whodis)"
	if got := productUserAgent(); got != want {
		t.Fatalf("productUserAgent() = %q, want %q", got, want)
	}
}

func TestResolveProductVersionUsesWhodisModule(t *testing.T) {
	tests := []struct {
		name      string
		buildInfo *debug.BuildInfo
		want      string
	}{
		{
			name:      "main module",
			buildInfo: &debug.BuildInfo{Main: debug.Module{Path: modulePath, Version: "v1.0.1"}},
			want:      "1.0.1",
		},
		{
			name: "embedded dependency ignores host version",
			buildInfo: &debug.BuildInfo{
				Main: debug.Module{Path: "example.com/host", Version: "v9.9.9"},
				Deps: []*debug.Module{nil, {Path: modulePath, Version: "v1.0.1"}},
			},
			want: "1.0.1",
		},
		{
			name:      "unrelated host",
			buildInfo: &debug.BuildInfo{Main: debug.Module{Path: "example.com/host", Version: "v9.9.9"}},
			want:      "dev",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := resolveProductVersion("dev", test.buildInfo, true); got != test.want {
				t.Fatalf("resolveProductVersion() = %q, want %q", got, test.want)
			}
		})
	}
}
