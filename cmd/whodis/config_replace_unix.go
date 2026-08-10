//go:build !windows

package main

import "os"

func replaceConfigFile(source, destination string) error {
	return os.Rename(source, destination)
}
