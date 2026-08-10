//go:build !windows

package whodis

import (
	"net"

	mdns "github.com/miekg/dns"
)

func systemDNSResolvers() []string {
	config, err := mdns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || config == nil {
		return nil
	}
	resolvers := make([]string, 0, len(config.Servers))
	for _, server := range config.Servers {
		resolvers = append(resolvers, net.JoinHostPort(server, config.Port))
	}
	return resolvers
}
