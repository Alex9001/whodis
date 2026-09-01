//go:build windows

package whodis

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

func systemDNSResolvers() []string {
	var size uint32
	err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, nil, &size)
	if err != windows.ERROR_BUFFER_OVERFLOW || size == 0 {
		return nil
	}
	buffer := make([]byte, size)
	adapters := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
	if err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, adapters, &size); err != nil {
		return nil
	}
	resolvers := make([]string, 0)
	for adapter := adapters; adapter != nil; adapter = adapter.Next {
		for server := adapter.FirstDnsServerAddress; server != nil; server = server.Next {
			if address := server.Address.IP(); address != nil {
				resolvers = append(resolvers, net.JoinHostPort(address.String(), "53"))
			}
		}
	}
	return resolvers
}
