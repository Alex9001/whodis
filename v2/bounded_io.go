package whodis

import (
	"fmt"
	"io"
)

// readLimitedBody reads one byte beyond maximum so protocol responses cannot
// be silently accepted after truncation. Homepage inspection deliberately has
// separate truncation semantics because partial markup is a supported result.
func readLimitedBody(reader io.Reader, maximum int64) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > maximum {
		return nil, fmt.Errorf("response body exceeded %d bytes", maximum)
	}
	return payload, nil
}
