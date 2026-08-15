package whodis

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type bootstrapKind string

const (
	bootstrapDNS  bootstrapKind = "dns"
	bootstrapIPv4 bootstrapKind = "ipv4"
	bootstrapIPv6 bootstrapKind = "ipv6"
	bootstrapASN  bootstrapKind = "asn"
)

var bootstrapURLs = map[bootstrapKind]string{
	bootstrapDNS:  "https://data.iana.org/rdap/dns.json",
	bootstrapIPv4: "https://data.iana.org/rdap/ipv4.json",
	bootstrapIPv6: "https://data.iana.org/rdap/ipv6.json",
	bootstrapASN:  "https://data.iana.org/rdap/asn.json",
}

type bootstrapRegistry struct {
	Version     string       `json:"version"`
	Publication string       `json:"publication"`
	Services    [][][]string `json:"services"`
}

type bootstrapCacheEntry struct {
	Payload json.RawMessage `json:"payload"`
	Expires time.Time       `json:"expires"`
	ETag    string          `json:"etag,omitempty"`
}

type bootstrapCache struct {
	dir        string
	mu         sync.Mutex
	locks      map[bootstrapKind]*sync.Mutex
	memory     map[bootstrapKind]bootstrapCacheEntry
	httpClient *http.Client
}

func newBootstrapCache(dir string) *bootstrapCache {
	if dir == "" {
		if root, err := os.UserCacheDir(); err == nil {
			dir = filepath.Join(root, "whodis", "bootstrap")
		}
	}
	return &bootstrapCache{
		dir: dir, locks: make(map[bootstrapKind]*sync.Mutex), memory: make(map[bootstrapKind]bootstrapCacheEntry),
		httpClient: &http.Client{},
	}
}

func (c *bootstrapCache) registry(ctx context.Context, kind bootstrapKind, refresh bool, timeout time.Duration) (bootstrapRegistry, error) {
	lock := c.kindLock(kind)
	lock.Lock()
	defer lock.Unlock()

	entry, haveEntry := c.cachedEntry(kind)
	if haveEntry && !refresh && time.Now().Before(entry.Expires) {
		registry, err := decodeBootstrap(entry.Payload)
		if err == nil {
			return registry, nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bootstrapURLs[kind], nil)
	if err != nil {
		return bootstrapRegistry{}, lookupError(ErrorUnavailable, "could not prepare IANA bootstrap request", err)
	}
	req.Header.Set("User-Agent", productUserAgent())
	if haveEntry && entry.ETag != "" {
		req.Header.Set("If-None-Match", entry.ETag)
	}
	requestContext := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		requestContext, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
		req = req.WithContext(requestContext)
	}
	response, err := c.httpClient.Do(req)
	if err != nil {
		if haveEntry {
			if registry, cachedErr := decodeBootstrap(entry.Payload); cachedErr == nil {
				return registry, nil
			}
		}
		return bootstrapRegistry{}, lookupError(ErrorUnavailable, "could not retrieve IANA RDAP bootstrap data", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusNotModified && haveEntry {
		entry.Expires = expiryFromHeaders(response.Header)
		c.write(kind, entry)
		registry, err := decodeBootstrap(entry.Payload)
		if err != nil {
			return bootstrapRegistry{}, lookupError(ErrorProtocol, "cached IANA bootstrap data is malformed", err)
		}
		return registry, nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if haveEntry {
			if registry, cachedErr := decodeBootstrap(entry.Payload); cachedErr == nil {
				return registry, nil
			}
		}
		return bootstrapRegistry{}, lookupError(ErrorUnavailable, "IANA RDAP bootstrap request returned "+response.Status, nil)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, 5<<20))
	if err != nil {
		return bootstrapRegistry{}, lookupError(ErrorUnavailable, "could not read IANA bootstrap data", err)
	}
	registry, err := decodeBootstrap(payload)
	if err != nil {
		return bootstrapRegistry{}, lookupError(ErrorProtocol, "IANA bootstrap data is malformed", err)
	}
	c.write(kind, bootstrapCacheEntry{Payload: payload, Expires: expiryFromHeaders(response.Header), ETag: response.Header.Get("ETag")})
	return registry, nil
}

func (c *bootstrapCache) kindLock(kind bootstrapKind) *sync.Mutex {
	c.mu.Lock()
	defer c.mu.Unlock()
	lock := c.locks[kind]
	if lock == nil {
		lock = &sync.Mutex{}
		c.locks[kind] = lock
	}
	return lock
}

func (c *bootstrapCache) cachedEntry(kind bootstrapKind) (bootstrapCacheEntry, bool) {
	c.mu.Lock()
	entry, ok := c.memory[kind]
	c.mu.Unlock()
	if ok {
		return entry, true
	}
	entry, ok = c.read(kind)
	if ok {
		c.mu.Lock()
		c.memory[kind] = entry
		c.mu.Unlock()
	}
	return entry, ok
}

func (c *bootstrapCache) path(kind bootstrapKind) string {
	if c.dir == "" {
		return ""
	}
	return filepath.Join(c.dir, string(kind)+".json")
}

func (c *bootstrapCache) read(kind bootstrapKind) (bootstrapCacheEntry, bool) {
	path := c.path(kind)
	if path == "" {
		return bootstrapCacheEntry{}, false
	}
	payload, err := os.ReadFile(path) // #nosec G304 -- path is a fixed bootstrap filename below the configured cache directory.
	if err != nil {
		return bootstrapCacheEntry{}, false
	}
	var entry bootstrapCacheEntry
	if json.Unmarshal(payload, &entry) != nil || len(entry.Payload) == 0 {
		return bootstrapCacheEntry{}, false
	}
	return entry, true
}

func (c *bootstrapCache) write(kind bootstrapKind, entry bootstrapCacheEntry) {
	c.mu.Lock()
	c.memory[kind] = entry
	c.mu.Unlock()
	path := c.path(kind)
	if path == "" {
		return
	}
	if os.MkdirAll(filepath.Dir(path), 0o700) != nil {
		return
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".bootstrap-*.tmp")
	if err != nil {
		return
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if temporary.Chmod(0o600) != nil || json.NewEncoder(temporary).Encode(entry) != nil || temporary.Sync() != nil || temporary.Close() != nil {
		_ = temporary.Close()
		return
	}
	if os.Rename(temporaryPath, path) == nil {
		removeTemporary = false
	}
}

func decodeBootstrap(payload []byte) (bootstrapRegistry, error) {
	var registry bootstrapRegistry
	if err := json.Unmarshal(payload, &registry); err != nil {
		return bootstrapRegistry{}, err
	}
	if registry.Version == "" || len(registry.Services) == 0 {
		return bootstrapRegistry{}, errors.New("missing version or services")
	}
	return registry, nil
}

func expiryFromHeaders(headers http.Header) time.Time {
	if cacheControl := headers.Get("Cache-Control"); cacheControl != "" {
		for _, directive := range strings.Split(cacheControl, ",") {
			parts := strings.SplitN(strings.TrimSpace(directive), "=", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], "max-age") {
				if seconds, err := strconv.ParseInt(parts[1], 10, 64); err == nil && seconds > 0 {
					return time.Now().Add(time.Duration(seconds) * time.Second)
				}
			}
		}
	}
	if expires := headers.Get("Expires"); expires != "" {
		if when, err := http.ParseTime(expires); err == nil && when.After(time.Now()) {
			return when
		}
	}
	return time.Now().Add(24 * time.Hour)
}

func (c *Client) discoverRDAP(ctx context.Context, target Target, refresh bool) (RouteDecision, error) {
	kind := bootstrapDNS
	if target.Kind == KindIP {
		if strings.Contains(target.Canonical, ":") {
			kind = bootstrapIPv6
		} else {
			kind = bootstrapIPv4
		}
	} else if target.Kind == KindASN {
		kind = bootstrapASN
	}
	registry, err := c.cache.registry(ctx, kind, refresh, c.timeout)
	if err != nil {
		return RouteDecision{}, err
	}
	endpoints := registry.match(target)
	if len(endpoints) == 0 {
		return RouteDecision{}, lookupError(ErrorDiscovery, "no authoritative RDAP service is listed for "+target.Canonical, nil)
	}
	return RouteDecision{
		Protocol: ProtocolRDAP, Endpoint: endpoints[0], Alternates: endpoints[1:], DiscoverySource: "IANA RDAP bootstrap", Reason: "authoritative RDAP service matched target scope",
	}, nil
}

func (r bootstrapRegistry) match(target Target) []string {
	bestScore := -1
	var bestEndpoints []string
	for _, service := range r.Services {
		if len(service) != 2 || len(service[0]) == 0 || len(service[1]) == 0 {
			continue
		}
		for _, entry := range service[0] {
			if entryMatches(target, entry) {
				if score := matchScore(target, entry); score > bestScore {
					bestScore = score
					bestEndpoints = preferredURLs(service[1])
				}
			}
		}
	}
	return bestEndpoints
}

func matchScore(target Target, entry string) int {
	entry = strings.TrimSpace(entry)
	switch target.Kind {
	case KindDomain:
		if entry == "" {
			return 0
		}
		return len(strings.Split(entry, "."))
	case KindIP:
		prefix, err := netip.ParsePrefix(entry)
		if err == nil {
			return prefix.Bits()
		}
	case KindASN:
		// ASN bootstrap ranges must not overlap under RFC 9224, so any match
		// is authoritative. Prefer an exact singleton should one be present.
		parts := strings.Split(entry, "-")
		if len(parts) == 2 && parts[0] == parts[1] {
			return 2
		}
		return 1
	}
	return -1
}

func entryMatches(target Target, entry string) bool {
	entry = strings.ToLower(strings.TrimSpace(entry))
	switch target.Kind {
	case KindDomain:
		if entry == "" {
			return true
		}
		return target.Canonical == entry || strings.HasSuffix(target.Canonical, "."+entry)
	case KindIP:
		address := strings.Split(target.Canonical, "/")[0]
		addr, err := netip.ParseAddr(address)
		if err != nil {
			return false
		}
		prefix, err := netip.ParsePrefix(entry)
		return err == nil && prefix.Contains(addr)
	case KindASN:
		parts := strings.Split(entry, "-")
		if len(parts) != 2 {
			return false
		}
		value, valueErr := strconv.ParseUint(target.Canonical, 10, 32)
		start, startErr := strconv.ParseUint(parts[0], 10, 32)
		end, endErr := strconv.ParseUint(parts[1], 10, 32)
		return valueErr == nil && startErr == nil && endErr == nil && start <= value && value <= end
	default:
		return false
	}
}

func preferredURLs(urls []string) []string {
	var secure, insecure []string
	for _, endpoint := range urls {
		if strings.HasPrefix(strings.ToLower(endpoint), "https://") {
			secure = appendUnique(secure, ensureTrailingSlash(endpoint))
		} else if strings.HasPrefix(strings.ToLower(endpoint), "http://") {
			insecure = appendUnique(insecure, ensureTrailingSlash(endpoint))
		}
	}
	return append(secure, insecure...)
}

func ensureTrailingSlash(value string) string {
	if !strings.HasSuffix(value, "/") {
		return value + "/"
	}
	return value
}
