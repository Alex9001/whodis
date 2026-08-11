package whodis

import (
	"runtime/debug"
	"strings"
)

// version is populated by release builds. Tagged `go install` builds fall back
// to the module version recorded by the Go toolchain.
var version = "dev"

func productVersion() string {
	value := strings.TrimPrefix(strings.TrimSpace(version), "v")
	if value != "" && value != "dev" {
		return value
	}
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		moduleVersion := strings.TrimPrefix(strings.TrimSpace(buildInfo.Main.Version), "v")
		if moduleVersion != "" && moduleVersion != "(devel)" {
			return moduleVersion
		}
	}
	return "dev"
}

func productUserAgent() string {
	return "whodis/" + productVersion() + " (+https://github.com/Alex9001/whodis)"
}
