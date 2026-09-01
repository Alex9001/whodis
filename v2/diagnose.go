package whodis

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultDiagnoseTimeout = 20 * time.Second
	maximumProbeAddresses  = 4
	maximumMailExchangers  = 3
)

// DiagnoseOptions controls bounded, domain-derived connectivity checks. Ports
// are obtained from established protocols and advertised DNS service records;
// this API is intentionally not a general-purpose port scanner.
type DiagnoseOptions struct {
	DNS          DNSOptions    `json:"dns,omitempty" yaml:"dns,omitempty"`
	Timeout      time.Duration `json:"-" yaml:"-"`
	Trace        bool          `json:"trace,omitempty" yaml:"trace,omitempty"`
	Remote       bool          `json:"remote,omitempty" yaml:"remote,omitempty"`
	MaxAddresses int           `json:"max_addresses,omitempty" yaml:"max_addresses,omitempty"`
}

// AddressProbe captures one bounded reachability check.
type AddressProbe struct {
	Address   string        `json:"address" yaml:"address"`
	Network   string        `json:"network" yaml:"network"`
	Method    string        `json:"method" yaml:"method"`
	Port      uint16        `json:"port,omitempty" yaml:"port,omitempty"`
	Reachable bool          `json:"reachable" yaml:"reachable"`
	Duration  time.Duration `json:"duration_ns" yaml:"duration_ns"`
	Error     string        `json:"error,omitempty" yaml:"error,omitempty"`
}

// HTTPProbe captures one HTTP endpoint and its final response.
type HTTPProbe struct {
	URL           string        `json:"url" yaml:"url"`
	Status        int           `json:"status,omitempty" yaml:"status,omitempty"`
	FinalURL      string        `json:"final_url,omitempty" yaml:"final_url,omitempty"`
	Redirects     []string      `json:"redirects,omitempty" yaml:"redirects,omitempty"`
	Duration      time.Duration `json:"duration_ns" yaml:"duration_ns"`
	Server        string        `json:"server,omitempty" yaml:"server,omitempty"`
	Healthy       bool          `json:"healthy" yaml:"healthy"`
	Error         string        `json:"error,omitempty" yaml:"error,omitempty"`
	policyBlocked bool
}

// TLSProbe captures the negotiated TLS identity and protocol.
type TLSProbe struct {
	Address       string        `json:"address" yaml:"address"`
	ServerName    string        `json:"server_name" yaml:"server_name"`
	Version       string        `json:"version,omitempty" yaml:"version,omitempty"`
	CipherSuite   string        `json:"cipher_suite,omitempty" yaml:"cipher_suite,omitempty"`
	ALPN          string        `json:"alpn,omitempty" yaml:"alpn,omitempty"`
	Subject       string        `json:"subject,omitempty" yaml:"subject,omitempty"`
	Issuer        string        `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	DNSNames      []string      `json:"dns_names,omitempty" yaml:"dns_names,omitempty"`
	NotBefore     time.Time     `json:"not_before,omitempty" yaml:"not_before,omitempty"`
	NotAfter      time.Time     `json:"not_after,omitempty" yaml:"not_after,omitempty"`
	Duration      time.Duration `json:"duration_ns" yaml:"duration_ns"`
	Verified      bool          `json:"verified" yaml:"verified"`
	Error         string        `json:"error,omitempty" yaml:"error,omitempty"`
	policyBlocked bool
}

// MailProbe captures one MX SMTP greeting and advertised capabilities.
type MailProbe struct {
	Host          string        `json:"host" yaml:"host"`
	Preference    uint16        `json:"preference" yaml:"preference"`
	Address       string        `json:"address,omitempty" yaml:"address,omitempty"`
	Reachable     bool          `json:"reachable" yaml:"reachable"`
	Greeting      string        `json:"greeting,omitempty" yaml:"greeting,omitempty"`
	Capabilities  []string      `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	STARTTLS      bool          `json:"starttls" yaml:"starttls"`
	TLSVerified   bool          `json:"tls_verified,omitempty" yaml:"tls_verified,omitempty"`
	TLSVersion    string        `json:"tls_version,omitempty" yaml:"tls_version,omitempty"`
	Duration      time.Duration `json:"duration_ns" yaml:"duration_ns"`
	Error         string        `json:"error,omitempty" yaml:"error,omitempty"`
	policyBlocked bool
}

// ServiceProbe captures a DNS-advertised SRV, SVCB, or HTTPS service.
type ServiceProbe struct {
	Source        string        `json:"source" yaml:"source"`
	Name          string        `json:"name" yaml:"name"`
	Target        string        `json:"target" yaml:"target"`
	Port          uint16        `json:"port" yaml:"port"`
	Reachable     bool          `json:"reachable" yaml:"reachable"`
	Duration      time.Duration `json:"duration_ns" yaml:"duration_ns"`
	Error         string        `json:"error,omitempty" yaml:"error,omitempty"`
	policyBlocked bool
}

// PathHop is one hop from an explicitly requested local network path trace.
type PathHop struct {
	Hop      int           `json:"hop" yaml:"hop"`
	Address  string        `json:"address,omitempty" yaml:"address,omitempty"`
	Duration time.Duration `json:"duration_ns,omitempty" yaml:"duration_ns,omitempty"`
	Reached  bool          `json:"reached" yaml:"reached"`
	Error    string        `json:"error,omitempty" yaml:"error,omitempty"`
}

// DiagnosisReport is the structured output of the bounded diagnosis engine.
type DiagnosisReport struct {
	Domain       string              `json:"domain" yaml:"domain"`
	DNS          *DNSOperationResult `json:"dns,omitempty" yaml:"dns,omitempty"`
	Delegation   *DNSOperationResult `json:"delegation,omitempty" yaml:"delegation,omitempty"`
	Reachability []AddressProbe      `json:"reachability,omitempty" yaml:"reachability,omitempty"`
	HTTP         []HTTPProbe         `json:"http,omitempty" yaml:"http,omitempty"`
	TLS          []TLSProbe          `json:"tls,omitempty" yaml:"tls,omitempty"`
	Mail         []MailProbe         `json:"mail,omitempty" yaml:"mail,omitempty"`
	Services     []ServiceProbe      `json:"services,omitempty" yaml:"services,omitempty"`
	Path         []PathHop           `json:"path,omitempty" yaml:"path,omitempty"`
	Policies     map[string][]string `json:"policies,omitempty" yaml:"policies,omitempty"`
	Findings     []Finding           `json:"findings,omitempty" yaml:"findings,omitempty"`
	Warnings     []string            `json:"warnings,omitempty" yaml:"warnings,omitempty"`
}

type nativeDiagnoseProvider struct {
	dns           DNSProvider
	networkPolicy NetworkPolicy
	probeSlots    chan struct{}
}

func newNativeDiagnoseProvider(dns DNSProvider, policy NetworkPolicy, probeSlots chan struct{}) DiagnoseProvider {
	if probeSlots == nil {
		probeSlots = make(chan struct{}, 32)
	}
	return &nativeDiagnoseProvider{dns: dns, networkPolicy: policy, probeSlots: probeSlots}
}

func (provider *nativeDiagnoseProvider) acquireProbe(ctx context.Context) (func(), bool) {
	select {
	case provider.probeSlots <- struct{}{}:
		return func() { <-provider.probeSlots }, true
	case <-ctx.Done():
		return func() {}, false
	}
}

func diagnosticAddresses(addresses []string, policy NetworkPolicy) ([]string, []string) {
	allowed := make([]string, 0, len(addresses))
	var warnings []string
	for _, value := range addresses {
		address, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("diagnostic address %q is invalid", value))
			continue
		}
		address = address.Unmap()
		if !policy.AllowPrivate && !publicNetworkAddress(address) {
			warnings = append(warnings, fmt.Sprintf("diagnostic destination %s is non-public and was blocked; use --allow-private for managed internal targets", address))
			continue
		}
		allowed = append(allowed, address.String())
	}
	return uniqueStrings(allowed), uniqueStrings(warnings)
}

func (provider *nativeDiagnoseProvider) Diagnose(ctx context.Context, domain string, options DiagnoseOptions) (*DiagnosisReport, error) {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultDiagnoseTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	maximumAddresses := options.MaxAddresses
	if maximumAddresses == 0 {
		maximumAddresses = maximumProbeAddresses
	}
	if maximumAddresses < 1 || maximumAddresses > 16 {
		return nil, lookupError(ErrorInvalidInput, "max diagnostic addresses must be between 1 and 16", nil)
	}

	report := &DiagnosisReport{Domain: normalizeDNSName(domain), Policies: make(map[string][]string)}
	inventoryOptions := options.DNS
	inventoryOptions.Types = nil
	inventoryOptions.EDNS.DNSSEC = true
	if options.Remote {
		inventoryOptions.Globalping = true
	}
	var inventory, delegation *DNSOperationResult
	var inventoryErr, delegationErr error
	var discovery sync.WaitGroup
	discovery.Add(2)
	go func() {
		defer discovery.Done()
		inventory, inventoryErr = provider.dns.Inventory(ctx, domain, inventoryOptions)
	}()
	go func() {
		defer discovery.Done()
		traceOptions := options.DNS
		traceOptions.Types = []string{"NS"}
		traceOptions.EDNS.DNSSEC = true
		delegation, delegationErr = provider.dns.Trace(ctx, domain, traceOptions)
	}()
	discovery.Wait()
	report.DNS = inventory
	report.Delegation = delegation
	if inventoryErr != nil {
		report.Warnings = append(report.Warnings, inventoryErr.Error())
	}
	if delegationErr != nil {
		report.Warnings = append(report.Warnings, delegationErr.Error())
	}
	records := []DNSRecord(nil)
	if inventory != nil && inventory.Inventory != nil {
		records = inventory.Inventory.Records
	}

	addresses, addressWarnings := diagnosticAddresses(representativeAddresses(records, domain, maximumAddresses), provider.networkPolicy)
	report.Warnings = append(report.Warnings, addressWarnings...)
	mx := mailExchangers(records, domain, maximumMailExchangers)
	services := advertisedServices(records)
	collectPolicies(report.Policies, records, domain)

	var mutex sync.Mutex
	var group sync.WaitGroup
	if len(report.Policies["mta_sts"]) > 0 {
		group.Add(1)
		go func() {
			defer group.Done()
			release, acquired := provider.acquireProbe(ctx)
			if !acquired {
				return
			}
			defer release()
			policy, policyErr := fetchMTAStsPolicy(ctx, domain, provider.networkPolicy)
			mutex.Lock()
			if policyErr != nil {
				report.Warnings = append(report.Warnings, policyErr.Error())
			} else {
				report.Policies["mta_sts_policy"] = []string{policy}
			}
			mutex.Unlock()
		}()
	}
	for _, address := range addresses {
		address := address
		group.Add(1)
		go func() {
			defer group.Done()
			release, acquired := provider.acquireProbe(ctx)
			if !acquired {
				return
			}
			defer release()
			probe := probeReachability(ctx, address)
			mutex.Lock()
			report.Reachability = append(report.Reachability, probe)
			mutex.Unlock()
		}()
	}
	for _, hostname := range uniqueStrings([]string{domain, "www." + domain}) {
		hostname := hostname
		group.Add(1)
		go func() {
			defer group.Done()
			release, acquired := provider.acquireProbe(ctx)
			if !acquired {
				return
			}
			defer release()
			httpProbes := []HTTPProbe{probeHTTP(ctx, "https://"+hostname+"/", provider.networkPolicy), probeHTTP(ctx, "http://"+hostname+"/", provider.networkPolicy)}
			tlsProbe := probeTLS(ctx, hostname, 443, provider.networkPolicy)
			mutex.Lock()
			report.HTTP = append(report.HTTP, httpProbes...)
			report.TLS = append(report.TLS, tlsProbe)
			for _, probe := range httpProbes {
				if probe.policyBlocked {
					report.Warnings = append(report.Warnings, probe.Error)
				}
			}
			if tlsProbe.policyBlocked {
				report.Warnings = append(report.Warnings, tlsProbe.Error)
			}
			mutex.Unlock()
		}()
	}
	for _, exchanger := range mx {
		exchanger := exchanger
		group.Add(1)
		go func() {
			defer group.Done()
			release, acquired := provider.acquireProbe(ctx)
			if !acquired {
				return
			}
			defer release()
			probe := probeSMTP(ctx, exchanger.host, exchanger.preference, provider.networkPolicy)
			mutex.Lock()
			report.Mail = append(report.Mail, probe)
			if probe.policyBlocked {
				report.Warnings = append(report.Warnings, probe.Error)
			}
			mutex.Unlock()
		}()
	}
	for _, advertised := range services {
		advertised := advertised
		group.Add(1)
		go func() {
			defer group.Done()
			release, acquired := provider.acquireProbe(ctx)
			if !acquired {
				return
			}
			defer release()
			probe := probeService(ctx, advertised, provider.networkPolicy)
			mutex.Lock()
			report.Services = append(report.Services, probe)
			if probe.policyBlocked {
				report.Warnings = append(report.Warnings, probe.Error)
			}
			mutex.Unlock()
		}()
	}
	group.Wait()

	if options.Trace && len(addresses) > 0 {
		if release, acquired := provider.acquireProbe(ctx); acquired {
			path, pathErr := traceNetworkPath(ctx, addresses[0], 20)
			release()
			report.Path = path
			if pathErr != nil {
				report.Warnings = append(report.Warnings, pathErr.Error())
			}
		}
	}
	report.Warnings = uniqueStrings(report.Warnings)
	sortDiagnosis(report)
	report.Findings = buildFindings(report, inventoryErr, delegationErr)
	if len(records) == 0 && ctx.Err() != nil {
		return report, ctx.Err()
	}
	return report, nil
}

func fetchMTAStsPolicy(ctx context.Context, domain string, networkPolicy NetworkPolicy) (string, error) {
	endpoint := "https://mta-sts." + normalizeDNSName(domain) + "/.well-known/mta-sts.txt"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("User-Agent", productUserAgent())
	response, err := newDiagnosticHTTPClient(networkPolicy, 6*time.Second, 5, nil).Do(request)
	if err != nil {
		return "", fmt.Errorf("MTA-STS policy fetch failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("MTA-STS policy returned HTTP %s", response.Status)
	}
	payload, err := readLimitedBody(response.Body, 64<<10)
	if err != nil {
		return "", err
	}
	policy := strings.TrimSpace(string(payload))
	if !strings.Contains(strings.ToLower(policy), "version: stsv1") {
		return "", fmt.Errorf("MTA-STS policy is missing version STSv1")
	}
	return policy, nil
}

func representativeAddresses(records []DNSRecord, domain string, maximum int) []string {
	var ipv4, ipv6 []string
	for _, record := range records {
		if normalizeDNSName(record.Name) != normalizeDNSName(domain) && normalizeDNSName(record.Name) != "www."+normalizeDNSName(domain) {
			continue
		}
		switch record.Type {
		case "A":
			ipv4 = append(ipv4, record.Value)
		case "AAAA":
			ipv6 = append(ipv6, record.Value)
		}
	}
	values := append(uniqueStrings(ipv4), uniqueStrings(ipv6)...)
	if len(values) > maximum {
		values = values[:maximum]
	}
	return values
}

type mailExchanger struct {
	host       string
	preference uint16
}

func mailExchangers(records []DNSRecord, domain string, maximum int) []mailExchanger {
	var result []mailExchanger
	for _, record := range records {
		if record.Type != "MX" || normalizeDNSName(record.Name) != normalizeDNSName(domain) {
			continue
		}
		fields := strings.Fields(record.Value)
		if len(fields) < 2 || fields[1] == "." {
			continue
		}
		preference, _ := strconv.ParseUint(fields[0], 10, 16)
		result = append(result, mailExchanger{host: normalizeDNSName(fields[1]), preference: uint16(preference)})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].preference < result[j].preference })
	if len(result) > maximum {
		result = result[:maximum]
	}
	return result
}

func collectPolicies(destination map[string][]string, records []DNSRecord, domain string) {
	for _, record := range records {
		if record.Type != "TXT" {
			continue
		}
		name := normalizeDNSName(record.Name)
		value := strings.Trim(record.Value, "\"")
		switch {
		case name == normalizeDNSName(domain) && strings.HasPrefix(strings.ToLower(value), "v=spf1"):
			destination["spf"] = append(destination["spf"], value)
		case name == "_dmarc."+normalizeDNSName(domain):
			destination["dmarc"] = append(destination["dmarc"], value)
		case name == "_mta-sts."+normalizeDNSName(domain):
			destination["mta_sts"] = append(destination["mta_sts"], value)
		case name == "_smtp._tls."+normalizeDNSName(domain):
			destination["tls_rpt"] = append(destination["tls_rpt"], value)
		}
	}
}

func probeTCP(ctx context.Context, address string, port uint16) AddressProbe {
	probe := AddressProbe{Address: address, Port: port, Method: "tcp"}
	if strings.Contains(address, ":") {
		probe.Network = "ipv6"
	} else {
		probe.Network = "ipv4"
	}
	started := time.Now()
	connection, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(address, strconv.Itoa(int(port))))
	probe.Duration = time.Since(started)
	if err != nil {
		probe.Error = err.Error()
		return probe
	}
	probe.Reachable = true
	_ = connection.Close()
	return probe
}

func probeHTTP(ctx context.Context, endpoint string, networkPolicy NetworkPolicy) HTTPProbe {
	probe := HTTPProbe{URL: endpoint}
	client := newDiagnosticHTTPClient(networkPolicy, 6*time.Second, 8, func(value string) {
		probe.Redirects = append(probe.Redirects, value)
	})
	started := time.Now()
	request := func(method string) (*http.Response, error) {
		value, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
		if err != nil {
			return nil, err
		}
		value.Header.Set("User-Agent", productUserAgent())
		return client.Do(value)
	}
	response, err := request(http.MethodHead)
	if err == nil && response.StatusCode == http.StatusMethodNotAllowed {
		_ = response.Body.Close()
		response, err = request(http.MethodGet)
	}
	probe.Duration = time.Since(started)
	if err != nil {
		probe.Error, probe.policyBlocked = diagnosticProbeError("HTTP probe", err)
		return probe
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	probe.Status, probe.FinalURL, probe.Server = response.StatusCode, response.Request.URL.String(), response.Header.Get("Server")
	probe.Healthy = response.StatusCode >= 200 && response.StatusCode < 400
	return probe
}

func probeTLS(ctx context.Context, hostname string, port uint16, networkPolicy NetworkPolicy) TLSProbe {
	probe := TLSProbe{Address: net.JoinHostPort(hostname, strconv.Itoa(int(port))), ServerName: hostname}
	started := time.Now()
	rawConnection, err := dialDiagnosticContext(ctx, "tcp", probe.Address, 4*time.Second, networkPolicy)
	if err != nil {
		probe.Duration = time.Since(started)
		probe.Error, probe.policyBlocked = diagnosticProbeError("TLS probe", err)
		return probe
	}
	connection := tls.Client(rawConnection, &tls.Config{ServerName: hostname, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}})
	handshakeDeadline := time.Now().Add(4 * time.Second)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(handshakeDeadline) {
		handshakeDeadline = deadline
	}
	_ = connection.SetDeadline(handshakeDeadline)
	err = connection.HandshakeContext(ctx)
	probe.Duration = time.Since(started)
	if err != nil {
		_ = rawConnection.Close()
		probe.Error = err.Error()
		return probe
	}
	defer connection.Close()
	state := connection.ConnectionState()
	probe.Verified = len(state.VerifiedChains) > 0
	probe.Version = tls.VersionName(state.Version)
	probe.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	probe.ALPN = state.NegotiatedProtocol
	if len(state.PeerCertificates) > 0 {
		certificate := state.PeerCertificates[0]
		probe.Subject, probe.Issuer = certificate.Subject.String(), certificate.Issuer.String()
		probe.DNSNames = append([]string(nil), certificate.DNSNames...)
		probe.NotBefore, probe.NotAfter = certificate.NotBefore, certificate.NotAfter
	}
	return probe
}

func probeSMTP(ctx context.Context, hostname string, preference uint16, networkPolicy NetworkPolicy) MailProbe {
	probe := MailProbe{Host: hostname, Preference: preference}
	started := time.Now()
	connection, err := dialDiagnosticContext(ctx, "tcp", net.JoinHostPort(hostname, "25"), 4*time.Second, networkPolicy)
	probe.Duration = time.Since(started)
	if err != nil {
		probe.Error, probe.policyBlocked = diagnosticProbeError("SMTP probe", err)
		return probe
	}
	defer connection.Close()
	probe.Reachable = true
	probe.Address = connection.RemoteAddr().String()
	_ = connection.SetDeadline(time.Now().Add(4 * time.Second))
	reader := bufio.NewReader(io.LimitReader(connection, 64<<10))
	greeting, err := readSMTPResponse(reader)
	if err != nil {
		probe.Error = err.Error()
		return probe
	}
	probe.Greeting = strings.Join(greeting, " ")
	if smtpResponseCode(greeting) != 220 {
		probe.Error = "SMTP server did not return a 220 greeting"
		return probe
	}
	_, _ = fmt.Fprintf(connection, "EHLO whodis.invalid\r\n")
	capabilities, err := readSMTPResponse(reader)
	if err == nil && smtpResponseCode(capabilities) == 250 {
		probe.Capabilities = capabilities
		for _, capability := range capabilities {
			text := strings.TrimSpace(capability)
			if len(text) > 4 {
				text = text[4:]
			}
			if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(text)), "STARTTLS") {
				probe.STARTTLS = true
			}
		}
	} else if err != nil {
		probe.Error = "EHLO: " + err.Error()
		return probe
	} else {
		probe.Error = "SMTP server did not accept EHLO"
		return probe
	}
	if probe.STARTTLS {
		_, _ = fmt.Fprintf(connection, "STARTTLS\r\n")
		response, startTLSErr := readSMTPResponse(reader)
		if startTLSErr != nil || len(response) == 0 || smtpResponseCode(response) != 220 {
			if startTLSErr != nil {
				probe.Error = "STARTTLS: " + startTLSErr.Error()
			} else {
				probe.Error = "STARTTLS: SMTP server did not return 220"
			}
		} else {
			tlsConnection := tls.Client(connection, &tls.Config{ServerName: hostname, MinVersion: tls.VersionTLS12})
			if handshakeErr := tlsConnection.HandshakeContext(ctx); handshakeErr != nil {
				probe.Error = "STARTTLS: " + handshakeErr.Error()
			} else {
				state := tlsConnection.ConnectionState()
				probe.TLSVerified = len(state.VerifiedChains) > 0
				probe.TLSVersion = tls.VersionName(state.Version)
				connection = tlsConnection
			}
		}
	}
	_, _ = fmt.Fprintf(connection, "QUIT\r\n")
	return probe
}

func readSMTPResponse(reader *bufio.Reader) ([]string, error) {
	var lines []string
	for count := 0; count < 64; count++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			return lines, err
		}
		line = strings.TrimSpace(line)
		if len(line) < 3 {
			return lines, fmt.Errorf("invalid SMTP response")
		}
		payload := line
		if len(line) > 4 {
			payload = line[4:]
		}
		lines = append(lines, line[:3]+" "+payload)
		if len(line) < 4 || line[3] != '-' {
			return lines, nil
		}
	}
	return lines, fmt.Errorf("SMTP response exceeded line limit")
}

func smtpResponseCode(lines []string) int {
	if len(lines) == 0 || len(lines[0]) < 3 {
		return 0
	}
	code, _ := strconv.Atoi(lines[0][:3])
	return code
}

func advertisedServices(records []DNSRecord) []ServiceProbe {
	var services []ServiceProbe
	for _, record := range records {
		fields := strings.Fields(record.Value)
		switch record.Type {
		case "SRV":
			if len(fields) < 4 {
				continue
			}
			port, err := strconv.ParseUint(fields[2], 10, 16)
			if err != nil || port == 0 || fields[3] == "." {
				continue
			}
			services = append(services, ServiceProbe{Source: "SRV", Name: record.Name, Target: normalizeDNSName(fields[3]), Port: uint16(port)})
		case "HTTPS", "SVCB":
			if len(fields) < 2 {
				continue
			}
			target := normalizeDNSName(fields[1])
			if target == "" {
				target = normalizeDNSName(record.Name)
			}
			port := uint64(0)
			if record.Type == "HTTPS" {
				port = 443
			}
			for _, field := range fields[2:] {
				if strings.HasPrefix(strings.ToLower(field), "port=") {
					parsed, err := strconv.ParseUint(strings.Trim(strings.TrimPrefix(field, "port="), "\""), 10, 16)
					if err == nil {
						port = parsed
					}
				}
			}
			if port > 0 && port <= uint64(^uint16(0)) {
				services = append(services, ServiceProbe{Source: record.Type, Name: record.Name, Target: target, Port: uint16(port)})
			}
		}
		if len(services) >= 12 {
			break
		}
	}
	return services
}

func probeService(ctx context.Context, service ServiceProbe, networkPolicy NetworkPolicy) ServiceProbe {
	started := time.Now()
	connection, err := dialDiagnosticContext(ctx, "tcp", net.JoinHostPort(service.Target, strconv.Itoa(int(service.Port))), 3*time.Second, networkPolicy)
	service.Duration = time.Since(started)
	if err != nil {
		service.Error, service.policyBlocked = diagnosticProbeError("service probe", err)
		return service
	}
	service.Reachable = true
	_ = connection.Close()
	return service
}

func sortDiagnosis(report *DiagnosisReport) {
	sort.Slice(report.Reachability, func(i, j int) bool { return report.Reachability[i].Address < report.Reachability[j].Address })
	sort.Slice(report.HTTP, func(i, j int) bool { return report.HTTP[i].URL < report.HTTP[j].URL })
	sort.Slice(report.TLS, func(i, j int) bool { return report.TLS[i].ServerName < report.TLS[j].ServerName })
	sort.Slice(report.Mail, func(i, j int) bool { return report.Mail[i].Preference < report.Mail[j].Preference })
	sort.Slice(report.Services, func(i, j int) bool { return report.Services[i].Name < report.Services[j].Name })
}

func buildFindings(report *DiagnosisReport, dnsErr, delegationErr error) []Finding {
	var findings []Finding
	if dnsErr != nil || report.DNS == nil || report.DNS.Inventory == nil || len(report.DNS.Inventory.Records) == 0 {
		findings = append(findings, Finding{ID: "dns.inventory", Severity: SeverityError, Title: "DNS inventory", Summary: "No public DNS records could be collected."})
	} else {
		findings = append(findings, Finding{ID: "dns.inventory", Severity: SeverityPass, Title: "DNS inventory", Summary: fmt.Sprintf("Collected %d public DNS records.", len(report.DNS.Inventory.Records))})
	}
	if delegationErr != nil || report.Delegation == nil || len(report.Delegation.Trace) == 0 {
		findings = append(findings, Finding{ID: "dns.delegation", Severity: SeverityError, Title: "DNS delegation", Summary: "The root-to-authority delegation path did not complete."})
	} else {
		severity := SeverityPass
		summary := fmt.Sprintf("Followed %d delegation hops to the authoritative DNS service.", len(report.Delegation.Trace))
		for _, hop := range report.Delegation.Trace {
			if hop.Lame || strings.HasPrefix(hop.Glue, "missing") {
				severity = SeverityWarning
			}
		}
		findings = append(findings, Finding{ID: "dns.delegation", Severity: severity, Title: "DNS delegation", Summary: summary})
	}
	secure, bogus := 0, 0
	if report.DNS != nil {
		for _, message := range report.DNS.Messages {
			if message.DNSSEC == "secure" {
				secure++
			}
			if message.DNSSEC == "bogus" {
				bogus++
			}
		}
	}
	dnssecSeverity, dnssecSummary := SeverityInfo, "No locally validated signed answers were observed."
	if bogus > 0 {
		dnssecSeverity, dnssecSummary = SeverityError, fmt.Sprintf("%d DNS responses failed local DNSSEC validation.", bogus)
	} else if secure > 0 {
		dnssecSeverity, dnssecSummary = SeverityPass, fmt.Sprintf("%d DNS responses validated locally to an IANA root trust anchor.", secure)
	}
	findings = append(findings, Finding{ID: "dns.dnssec", Severity: dnssecSeverity, Title: "DNSSEC", Summary: dnssecSummary})
	findings = append(findings, reachabilityFinding(report.Reachability))
	findings = append(findings, httpFinding(report.HTTP))
	findings = append(findings, tlsFinding(report.TLS))
	if len(report.Mail) > 0 {
		reachable, startTLS, verifiedTLS, eligible := 0, 0, 0, 0
		for _, mail := range report.Mail {
			if mail.policyBlocked {
				continue
			}
			eligible++
			if mail.Reachable {
				reachable++
			}
			if mail.STARTTLS {
				startTLS++
			}
			if mail.TLSVerified {
				verifiedTLS++
			}
		}
		severity := SeverityPass
		if eligible == 0 {
			severity = SeverityWarning
		} else if reachable == 0 {
			severity = SeverityError
		} else if startTLS == 0 || verifiedTLS == 0 {
			severity = SeverityWarning
		}
		summary := fmt.Sprintf("%d of %d eligible sampled MX hosts accepted SMTP; %d advertised STARTTLS and %d completed verified TLS.", reachable, eligible, startTLS, verifiedTLS)
		if eligible == 0 {
			summary = "No public MX hosts were eligible for an SMTP probe under the current network policy."
		}
		findings = append(findings, Finding{ID: "mail.smtp", Severity: severity, Title: "Mail delivery", Summary: summary})
	}
	for _, policy := range []string{"spf", "dmarc", "mta_sts", "tls_rpt"} {
		severity, summary := SeverityPass, "Published."
		if len(report.Policies[policy]) == 0 {
			severity, summary = SeverityInfo, "Not published in discovered records."
		}
		findings = append(findings, Finding{ID: "mail." + policy, Severity: severity, Title: strings.ToUpper(strings.ReplaceAll(policy, "_", "-")), Summary: summary})
	}
	return findings
}

func reachabilityFinding(probes []AddressProbe) Finding {
	reachable := 0
	for _, probe := range probes {
		if probe.Reachable {
			reachable++
		}
	}
	severity := SeverityPass
	summary := fmt.Sprintf("%d of %d representative addresses answered a bounded reachability probe.", reachable, len(probes))
	if len(probes) == 0 {
		severity = SeverityWarning
		summary = "No public representative addresses were eligible for a reachability probe under the current network policy."
	} else if reachable == 0 {
		severity = SeverityError
	}
	return Finding{ID: "network.reachability", Severity: severity, Title: "Address reachability", Summary: summary}
}

func httpFinding(probes []HTTPProbe) Finding {
	responded, healthy, serverFailures, eligible := 0, 0, 0, 0
	for _, probe := range probes {
		if probe.policyBlocked {
			continue
		}
		eligible++
		if probe.Status > 0 {
			responded++
		}
		if probe.Healthy {
			healthy++
		}
		if probe.Status >= 500 {
			serverFailures++
		}
	}
	severity := SeverityPass
	if eligible == 0 {
		severity = SeverityWarning
	} else if responded == 0 || (healthy == 0 && serverFailures > 0) {
		severity = SeverityError
	} else if healthy < eligible {
		severity = SeverityWarning
	}
	summary := fmt.Sprintf("%d of %d eligible HTTP or HTTPS endpoints returned a healthy 2xx/3xx response; %d responded at all.", healthy, eligible, responded)
	if eligible == 0 {
		summary = "No public HTTP endpoints were eligible under the current network policy."
	}
	return Finding{ID: "web.http", Severity: severity, Title: "Web endpoints", Summary: summary}
}

func tlsFinding(probes []TLSProbe) Finding {
	verified, eligible := 0, 0
	for _, probe := range probes {
		if probe.policyBlocked {
			continue
		}
		eligible++
		if probe.Verified {
			verified++
		}
	}
	severity := SeverityPass
	if eligible == 0 {
		severity = SeverityWarning
	} else if verified == 0 {
		severity = SeverityError
	} else if verified < eligible {
		severity = SeverityWarning
	}
	summary := fmt.Sprintf("%d of %d eligible HTTPS certificates verified for the requested name.", verified, eligible)
	if eligible == 0 {
		summary = "No public TLS endpoints were eligible under the current network policy."
	}
	return Finding{ID: "web.tls", Severity: severity, Title: "TLS identity", Summary: summary}
}
