//go:build !windows

package main

import "os"

func replaceConfigFile(source, destination string) error {
	// #nosec G703 -- callers pass a CreateTemp path and an explicit config/output destination.
	return os.Rename(source, destination)
}
