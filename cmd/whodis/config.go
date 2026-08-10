package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Alex9001/whodis"
)

const formatEnvironmentVariable = "WHODIS_FORMAT"

var errConfigDirectoryUnavailable = errors.New("user configuration directory unavailable")

type savedConfigError struct {
	err error
}

func (err *savedConfigError) Error() string { return err.err.Error() }
func (err *savedConfigError) Unwrap() error { return err.err }

type cliRuntime struct {
	getenv        func(string) string
	userConfigDir func() (string, error)
	isTerminal    func(io.Writer) bool
}

type userConfig struct {
	Format string `json:"format,omitempty"`
}

func defaultCLIRuntime() cliRuntime {
	return cliRuntime{
		getenv:        os.Getenv,
		userConfigDir: os.UserConfigDir,
		isTerminal:    writerIsTerminal,
	}
}

func configFilePath(runtime cliRuntime) (string, error) {
	base, err := runtime.userConfigDir()
	if err != nil {
		return "", fmt.Errorf("%w: %v", errConfigDirectoryUnavailable, err)
	}
	if strings.TrimSpace(base) == "" {
		return "", fmt.Errorf("%w: path is empty", errConfigDirectoryUnavailable)
	}
	return filepath.Join(base, "whodis", "config.json"), nil
}

func loadUserConfig(runtime cliRuntime) (userConfig, bool, error) {
	path, err := configFilePath(runtime)
	if err != nil {
		return userConfig{}, false, err
	}
	payload, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return userConfig{}, false, nil
	}
	if err != nil {
		return userConfig{}, false, fmt.Errorf("could not read config %s: %w", path, err)
	}

	var config *userConfig
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&config); err != nil {
		return userConfig{}, false, fmt.Errorf("could not parse config %s: %w", path, err)
	}
	if config == nil {
		return userConfig{}, false, fmt.Errorf("could not parse config %s: expected a JSON object", path)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return userConfig{}, false, fmt.Errorf("could not parse config %s: %w", path, err)
	}
	return *config, true, nil
}

func saveUserConfig(runtime cliRuntime, config userConfig) error {
	path, err := configFilePath(runtime)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("could not create config directory %s: %w", directory, err)
	}
	payload, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("could not encode config: %w", err)
	}
	payload = append(payload, '\n')

	temporary, err := os.CreateTemp(directory, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("could not create temporary config in %s: %w", directory, err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("could not secure temporary config %s: %w", temporaryPath, err)
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("could not write temporary config %s: %w", temporaryPath, err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("could not sync temporary config %s: %w", temporaryPath, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("could not close temporary config %s: %w", temporaryPath, err)
	}
	if err := replaceConfigFile(temporaryPath, path); err != nil {
		return fmt.Errorf("could not replace config %s: %w", path, err)
	}
	removeTemporary = false
	return nil
}

func removeUserConfig(runtime cliRuntime) error {
	path, err := configFilePath(runtime)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("could not remove config %s: %w", path, err)
	}
	return nil
}

func parsePersistentFormat(value string) (whodis.Format, string, error) {
	if strings.TrimSpace(value) == "" {
		return "", "", errors.New("saved format cannot be empty; choose dashboard, tree, geekboys, or plain")
	}
	format, err := whodis.ParseFormat(value)
	if err != nil {
		return "", "", fmt.Errorf("%w; choose dashboard, tree, geekboys, or plain", err)
	}
	switch format {
	case whodis.FormatPretty:
		return format, "dashboard", nil
	case whodis.FormatTree:
		return format, "tree", nil
	case whodis.FormatGeekBoys:
		return format, "geekboys", nil
	case whodis.FormatPlain:
		return format, "plain", nil
	default:
		return "", "", fmt.Errorf("format %q cannot be saved; choose dashboard, tree, geekboys, or plain", value)
	}
}

func runConfig(args []string, stdout, stderr io.Writer, runtime cliRuntime) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "whodis: config requires set, get, unset, or path")
		printConfigUsage(stderr)
		return 2
	}

	switch args[0] {
	case "-h", "--help", "help":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "whodis: config help accepts no arguments")
			return 2
		}
		printConfigUsage(stdout)
		return 0
	case "path":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "whodis: config path accepts no arguments")
			return 2
		}
		path, err := configFilePath(runtime)
		if err != nil {
			fmt.Fprintln(stderr, "whodis:", err)
			return 1
		}
		fmt.Fprintln(stdout, path)
		return 0
	case "get":
		if len(args) != 2 || args[1] != "format" {
			fmt.Fprintln(stderr, "whodis: usage: whodis config get format")
			return 2
		}
		config, exists, err := loadUserConfig(runtime)
		if err != nil {
			fmt.Fprintln(stderr, "whodis:", err)
			return 1
		}
		if !exists || strings.TrimSpace(config.Format) == "" {
			fmt.Fprintln(stdout, "auto")
			return 0
		}
		_, canonical, err := parsePersistentFormat(config.Format)
		if err != nil {
			path, pathErr := configFilePath(runtime)
			if pathErr != nil {
				fmt.Fprintln(stderr, "whodis:", pathErr)
			} else {
				fmt.Fprintf(stderr, "whodis: invalid format in config %s: %v\n", path, err)
			}
			return 1
		}
		fmt.Fprintln(stdout, canonical)
		return 0
	case "set":
		if len(args) != 3 || args[1] != "format" {
			fmt.Fprintln(stderr, "whodis: usage: whodis config set format dashboard|tree|geekboys|plain")
			return 2
		}
		_, canonical, err := parsePersistentFormat(args[2])
		if err != nil {
			fmt.Fprintln(stderr, "whodis:", err)
			return 2
		}
		if err := saveUserConfig(runtime, userConfig{Format: canonical}); err != nil {
			fmt.Fprintln(stderr, "whodis:", err)
			return 1
		}
		return 0
	case "unset":
		if len(args) != 2 || args[1] != "format" {
			fmt.Fprintln(stderr, "whodis: usage: whodis config unset format")
			return 2
		}
		if err := removeUserConfig(runtime); err != nil {
			fmt.Fprintln(stderr, "whodis:", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "whodis: unknown config command %q\n", args[0])
		printConfigUsage(stderr)
		return 2
	}
}

func printConfigUsage(writer io.Writer) {
	fmt.Fprint(writer, `Usage:
  whodis config set format dashboard|tree|geekboys|plain
  whodis config get format
  whodis config unset format
  whodis config path
`)
}
