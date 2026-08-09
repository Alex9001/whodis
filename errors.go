package whodis

import "fmt"

// ErrorKind allows command-line callers and future UIs to handle lookup
// failures without string matching.
type ErrorKind string

const (
	ErrorInvalidInput ErrorKind = "invalid_input"
	ErrorNotFound     ErrorKind = "not_found"
	ErrorRateLimited  ErrorKind = "rate_limited"
	ErrorDiscovery    ErrorKind = "discovery"
	ErrorUnavailable  ErrorKind = "unavailable"
	ErrorProtocol     ErrorKind = "protocol"
)

// LookupError wraps a failure with an actionable classification.
type LookupError struct {
	Kind    ErrorKind
	Message string
	Cause   error
}

func (e *LookupError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

func (e *LookupError) Unwrap() error { return e.Cause }

func lookupError(kind ErrorKind, message string, cause error) *LookupError {
	return &LookupError{Kind: kind, Message: message, Cause: cause}
}
