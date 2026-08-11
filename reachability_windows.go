//go:build windows

package whodis

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ipHelperDLL  = windows.NewLazySystemDLL("iphlpapi.dll")
	icmpCreate   = ipHelperDLL.NewProc("IcmpCreateFile")
	icmpClose    = ipHelperDLL.NewProc("IcmpCloseHandle")
	icmpSendEcho = ipHelperDLL.NewProc("IcmpSendEcho")
)

func probeReachability(ctx context.Context, address string) AddressProbe {
	probe := AddressProbe{Address: address, Network: "ipv4", Method: "icmp-ip-helper"}
	ip := net.ParseIP(address)
	if ip == nil {
		probe.Error = "invalid IP address"
		return probe
	}
	if ip.To4() != nil {
		handle, _, createErr := icmpCreate.Call()
		if handle != 0 && handle != uintptr(windows.InvalidHandle) {
			defer icmpClose.Call(handle)
			payload := []byte("whodis")
			reply := make([]byte, 256)
			timeout := uint32(2000)
			if deadline, ok := ctx.Deadline(); ok {
				remaining := time.Until(deadline)
				if remaining <= 0 {
					timeout = 1
				} else if remaining < 2*time.Second {
					timeout = uint32(max(1, int(remaining/time.Millisecond)))
				}
			}
			started := time.Now()
			count, _, sendErr := icmpSendEcho.Call(handle, uintptr(binary.LittleEndian.Uint32(ip.To4())), uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)), 0, uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeout))
			probe.Duration = time.Since(started)
			if count > 0 && binary.LittleEndian.Uint32(reply[4:8]) == 0 {
				probe.Reachable = true
				return probe
			}
			probe.Error = fmt.Sprintf("IP Helper ICMP failed: %v", sendErr)
		} else {
			probe.Error = fmt.Sprintf("IP Helper ICMP unavailable: %v", createErr)
		}
	} else {
		probe.Network = "ipv6"
		probe.Error = "IPv6 ICMP requires TCP fallback"
	}
	fallback := probeTCP(ctx, address, 443)
	fallback.Method = "tcp-fallback"
	if fallback.Error != "" && probe.Error != "" {
		fallback.Error = probe.Error + "; TCP: " + fallback.Error
	}
	return fallback
}
