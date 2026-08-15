package whodis

import (
	"runtime/debug"
	"strings"
)

const modulePath = "github.com/Alex9001/whodis/v2"

// version is populated by release builds. Tagged `go install` builds fall back
// to the module version recorded by the Go toolchain.
var version = "dev"

func productVersion() string {
	buildInfo, ok := debug.ReadBuildInfo()
	return resolveProductVersion(version, buildInfo, ok)
}

func resolveProductVersion(injected string, buildInfo *debug.BuildInfo, buildInfoOK bool) string {
	value := normalizedProductVersion(injected)
	if value != "" && value != "dev" {
		return value
	}
	if buildInfoOK && buildInfo != nil {
		if buildInfo.Main.Path == modulePath {
			if moduleVersion := normalizedProductVersion(buildInfo.Main.Version); moduleVersion != "" && moduleVersion != "dev" {
				return moduleVersion
			}
		}
		for _, dependency := range buildInfo.Deps {
			if dependency != nil && dependency.Path == modulePath {
				if moduleVersion := normalizedProductVersion(dependency.Version); moduleVersion != "" && moduleVersion != "dev" {
					return moduleVersion
				}
			}
		}
	}
	return "dev"
}

func normalizedProductVersion(value string) string {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	if value == "(devel)" {
		return "dev"
	}
	return value
}

func productUserAgent() string {
	return "whodis/" + productVersion() + " (+https://github.com/Alex9001/whodis)"
}
