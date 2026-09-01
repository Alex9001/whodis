//go:build windows

package main

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var replaceFileW = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReplaceFileW")

func replaceConfigFile(source, destination string) error {
	sourcePointer, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	destinationPointer, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}

	// ReplaceFileW is the native replacement operation when the destination
	// already exists. The first save, a race with external deletion, and the two
	// documented "replacement could not be moved" recovery cases use the
	// same-volume MoveFileExW operation instead.
	replaced, _, replaceErr := replaceFileW.Call(
		uintptr(unsafe.Pointer(destinationPointer)),
		uintptr(unsafe.Pointer(sourcePointer)),
		0,
		0,
		0,
		0,
	)
	if replaced != 0 {
		return nil
	}
	if !errors.Is(replaceErr, windows.ERROR_FILE_NOT_FOUND) &&
		!errors.Is(replaceErr, windows.ERROR_PATH_NOT_FOUND) &&
		!errors.Is(replaceErr, windows.ERROR_UNABLE_TO_MOVE_REPLACEMENT) &&
		!errors.Is(replaceErr, windows.ERROR_UNABLE_TO_MOVE_REPLACEMENT_2) {
		return replaceErr
	}
	return windows.MoveFileEx(
		sourcePointer,
		destinationPointer,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH,
	)
}
