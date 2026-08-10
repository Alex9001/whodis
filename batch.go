package whodis

import (
	"context"
	"fmt"
	"sync"
)

const (
	defaultBatchWorkers = 4
	maximumBatchWorkers = 32
)

// LookupBatch resolves each input independently with bounded concurrency. It
// preserves order and duplicates, and records an error on the affected item
// rather than failing the entire operation.
func (c *Client) LookupBatch(ctx context.Context, inputs []string, options BatchLookupOptions) (BatchResult, error) {
	if len(inputs) == 0 {
		return BatchResult{}, lookupError(ErrorInvalidInput, "at least one target is required", nil)
	}
	workers := options.Workers
	if workers == 0 {
		workers = defaultBatchWorkers
	}
	if workers < 1 || workers > maximumBatchWorkers {
		return BatchResult{}, lookupError(ErrorInvalidInput, fmt.Sprintf("batch workers must be between 1 and %d", maximumBatchWorkers), nil)
	}
	if workers > len(inputs) {
		workers = len(inputs)
	}

	lookupOptions := normalizedOptions(options.LookupOptions)
	if lookupOptions.RefreshBootstrap {
		// Refreshing once per bootstrap kind avoids a batch turning one explicit
		// refresh request into a burst of identical IANA requests. A later normal
		// lookup still gets to use fallback behavior if a refresh fails.
		c.refreshBatchBootstrap(ctx, inputs, lookupOptions)
		lookupOptions.RefreshBootstrap = false
	}

	result := BatchResult{SchemaVersion: 1, Items: make([]BatchItem, len(inputs))}
	for index, input := range inputs {
		result.Items[index].Input = input
	}

	jobs := make(chan int)
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range jobs {
				result.Items[index] = c.lookupBatchItem(ctx, inputs[index], lookupOptions)
			}
		}()
	}
	for index := range inputs {
		jobs <- index
	}
	close(jobs)
	group.Wait()
	return result, nil
}

func (c *Client) lookupBatchItem(ctx context.Context, input string, options LookupOptions) BatchItem {
	item := BatchItem{Input: input}
	if err := ctx.Err(); err != nil {
		item.Error = batchError(err)
		return item
	}

	itemOptions := options
	if target, err := ParseTarget(input); err == nil && target.Kind != KindDomain && itemOptions.DNSMode != DNSAuto && itemOptions.DNSMode != DNSOff {
		// A mixed domain/IP batch should not turn an explicitly requested DNS
		// scan into a spurious registration failure for every non-domain item.
		itemOptions.DNSMode = DNSOff
		itemOptions.DNSResolver = ""
	}
	itemContext, cancel := context.WithTimeout(ctx, itemOptions.Timeout)
	defer cancel()
	lookup, err := c.Lookup(itemContext, input, itemOptions)
	if err != nil {
		item.Error = batchError(err)
		return item
	}
	item.Result = &lookup
	return item
}

func batchError(err error) *BatchError {
	if typed, ok := err.(*LookupError); ok {
		return &BatchError{Kind: typed.Kind, Message: typed.Error()}
	}
	return &BatchError{Kind: ErrorUnavailable, Message: err.Error()}
}

func (c *Client) refreshBatchBootstrap(ctx context.Context, inputs []string, options LookupOptions) {
	if options.Protocol != ProtocolAuto && options.Protocol != ProtocolRDAP {
		return
	}
	needed := map[bootstrapKind]bool{}
	for _, input := range inputs {
		target, err := ParseTarget(input)
		if err != nil {
			continue
		}
		needed[bootstrapKindForTarget(target)] = true
	}
	for kind := range needed {
		_, _ = c.cache.registry(ctx, kind, true, c.timeout)
	}
}

func bootstrapKindForTarget(target Target) bootstrapKind {
	if target.Kind == KindIP {
		if containsColon(target.Canonical) {
			return bootstrapIPv6
		}
		return bootstrapIPv4
	}
	if target.Kind == KindASN {
		return bootstrapASN
	}
	return bootstrapDNS
}

func containsColon(value string) bool {
	for _, character := range value {
		if character == ':' {
			return true
		}
	}
	return false
}
