package main

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/Alex9001/whodis"
	"github.com/Alex9001/whodis/internal/guiapi"
)

var version = "dev"

func main() {
	client := whodis.NewClient(whodis.ClientOptions{})
	server := guiapi.NewServer(resolvedVersion(), client, os.Stdin, os.Stdout, os.Stderr)
	if err := server.Serve(); err != nil {
		fmt.Fprintln(os.Stderr, "whodis-gui-engine:", err)
		os.Exit(1)
	}
}

func resolvedVersion() string {
	value := strings.TrimSpace(version)
	if value != "" && value != "dev" {
		return strings.TrimPrefix(value, "v")
	}
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		moduleVersion := strings.TrimSpace(buildInfo.Main.Version)
		if moduleVersion != "" && moduleVersion != "(devel)" {
			return strings.TrimPrefix(moduleVersion, "v")
		}
	}
	return "dev"
}
