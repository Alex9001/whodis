package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/Alex9001/whodis/v2"
)

var snapshotIDPattern = regexp.MustCompile(`^snap_[0-9]{8}T[0-9]{6}Z_[0-9a-f]{8}$`)

// FileStore keeps one transparent JSON document per immutable snapshot.
type FileStore struct {
	Directory string
}

func DefaultDirectory() (string, error) {
	var root string
	switch runtime.GOOS {
	case "windows":
		root = os.Getenv("LOCALAPPDATA")
	case "darwin":
		home, err := os.UserHomeDir()
		if err == nil {
			root = filepath.Join(home, "Library", "Application Support")
		}
	default:
		root = os.Getenv("XDG_DATA_HOME")
		if root == "" {
			home, err := os.UserHomeDir()
			if err == nil {
				root = filepath.Join(home, ".local", "share")
			}
		}
	}
	if strings.TrimSpace(root) == "" {
		return "", fmt.Errorf("user data directory is unavailable")
	}
	return filepath.Join(root, "whodis", "snapshots"), nil
}

func NewFileStore(directory string) (*FileStore, error) {
	if strings.TrimSpace(directory) == "" {
		var err error
		directory, err = DefaultDirectory()
		if err != nil {
			return nil, err
		}
	}
	return &FileStore{Directory: directory}, nil
}

func (store *FileStore) Put(snapshot Snapshot) (string, error) {
	if err := validateSnapshot(snapshot); err != nil {
		return "", err
	}
	if err := os.MkdirAll(store.Directory, 0o700); err != nil {
		return "", fmt.Errorf("could not create snapshot directory: %w", err)
	}
	if snapshot.Label != "" {
		items, err := store.List()
		if err != nil {
			return "", err
		}
		for _, item := range items {
			if strings.EqualFold(item.Label, snapshot.Label) && item.ID != snapshot.ID {
				return "", fmt.Errorf("snapshot label %q already exists", snapshot.Label)
			}
		}
	}
	path := filepath.Join(store.Directory, snapshot.ID+".whodis.json")
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("snapshot %s already exists", snapshot.ID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	payload, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return "", err
	}
	payload = append(payload, '\n')
	temporary, err := os.CreateTemp(store.Directory, ".snapshot-*.tmp")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return "", err
	}
	if _, err := temporary.Write(payload); err != nil {
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return "", err
	}
	committed = true
	return path, nil
}

func (store *FileStore) Get(reference string) (Snapshot, error) {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return Snapshot{}, fmt.Errorf("snapshot reference is required")
	}
	if info, err := os.Stat(reference); err == nil && !info.IsDir() {
		return readSnapshot(reference)
	}
	direct := filepath.Join(store.Directory, strings.TrimSuffix(reference, ".whodis.json")+".whodis.json")
	if snapshot, err := readSnapshot(direct); err == nil {
		return snapshot, nil
	}
	items, err := store.List()
	if err != nil {
		return Snapshot{}, err
	}
	for _, item := range items {
		if strings.EqualFold(item.Label, reference) {
			return readSnapshot(item.Path)
		}
	}
	return Snapshot{}, fmt.Errorf("snapshot %q was not found", reference)
}

func (store *FileStore) List() ([]Metadata, error) {
	entries, err := os.ReadDir(store.Directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var items []Metadata
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".whodis.json") {
			continue
		}
		path := filepath.Join(store.Directory, entry.Name())
		snapshot, err := readSnapshot(path)
		if err != nil {
			continue
		}
		metadata := Metadata{ID: snapshot.ID, Label: snapshot.Label, CreatedAt: snapshot.CreatedAt, Path: path}
		for _, report := range snapshot.Batch.Reports {
			metadata.Targets = appendUnique(metadata.Targets, report.Subject.Canonical)
			metadata.Operations = appendUniqueOperation(metadata.Operations, report.Operation)
		}
		items = append(items, metadata)
	}
	sort.Slice(items, func(left, right int) bool { return items[left].CreatedAt.After(items[right].CreatedAt) })
	return items, nil
}

func (store *FileStore) Remove(reference string) error {
	snapshot, err := store.Get(reference)
	if err != nil {
		return err
	}
	path := filepath.Join(store.Directory, snapshot.ID+".whodis.json")
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("could not remove snapshot %s: %w", snapshot.ID, err)
	}
	return nil
}

func readSnapshot(path string) (Snapshot, error) {
	payload, err := os.ReadFile(path) // #nosec G304 -- importing an explicitly selected snapshot file is intentional.
	if err != nil {
		return Snapshot{}, err
	}
	var snapshot Snapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("could not parse snapshot %s: %w", path, err)
	}
	if err := validateSnapshot(snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("invalid snapshot %s: %w", path, err)
	}
	return snapshot, nil
}

func validateSnapshot(snapshot Snapshot) error {
	if snapshot.SchemaVersion != SnapshotSchemaVersion {
		return fmt.Errorf("unsupported snapshot schema %d", snapshot.SchemaVersion)
	}
	if !snapshotIDPattern.MatchString(snapshot.ID) || snapshot.CreatedAt.IsZero() || len(snapshot.Requests) == 0 || len(snapshot.Requests) != len(snapshot.Batch.Reports) {
		return fmt.Errorf("snapshot is missing required identity, time, requests, or reports")
	}
	if len(snapshot.Label) > 128 || strings.ContainsAny(snapshot.Label, "\r\n\x00") {
		return fmt.Errorf("snapshot label must be at most 128 characters without control newlines")
	}
	if !supportedReportSchema(snapshot.Batch.SchemaVersion) {
		return fmt.Errorf("snapshot contains unsupported report schema %d", snapshot.Batch.SchemaVersion)
	}
	for index, request := range snapshot.Requests {
		if request.Operation == whodis.OperationDNSTransfer || request.Diagnose.Remote || request.Diagnose.Trace {
			return fmt.Errorf("snapshot request %d contains an unsafe replay operation", index)
		}
		if err := whodis.ValidateInvestigationOptions(whodis.InvestigationOptions{
			RelatedLimit: request.Investigation.RelatedLimit, ExternalLinkTemplate: request.Investigation.ExternalLinkTemplate,
		}); err != nil {
			return fmt.Errorf("snapshot request %d has invalid investigation options: %w", index, err)
		}
		subject, err := whodis.ParseSubject(request.Target, request.Operation)
		if err != nil {
			return fmt.Errorf("snapshot request %d is invalid: %w", index, err)
		}
		report := snapshot.Batch.Reports[index]
		if report.SchemaVersion != snapshot.Batch.SchemaVersion || report.Operation != request.Operation {
			return fmt.Errorf("snapshot report %d does not match its replay request", index)
		}
		if report.Subject.Canonical != subject.Canonical || report.Subject.Kind != subject.Kind || report.Subject.RegistrationDomain != subject.RegistrationDomain {
			return fmt.Errorf("snapshot report %d subject does not match its replay request", index)
		}
	}
	return nil
}

func supportedReportSchema(version int) bool {
	return version == 4 || version == whodis.ReportSchemaVersion
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendUniqueOperation(values []whodis.Operation, value whodis.Operation) []whodis.Operation {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
