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

const (
	ipStatusSuccess           = 0
	ipStatusTTLExpiredTransit = 11013
)

type ipOptionInformation struct {
	TTL         byte
	TOS         byte
	Flags       byte
	OptionsSize byte
	OptionsData uintptr
}

func traceNetworkPath(ctx context.Context, address string, maximum int) ([]PathHop, error) {
	ip := net.ParseIP(address)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("Windows path trace currently requires an IPv4 destination")
	}
	handle, _, createErr := icmpCreate.Call()
	if handle == 0 || handle == uintptr(windows.InvalidHandle) {
		return nil, fmt.Errorf("IP Helper path trace unavailable: %v", createErr)
	}
	defer icmpClose.Call(handle)
	payload := []byte("whodis-path")
	var hops []PathHop
	for ttl := 1; ttl <= maximum; ttl++ {
		select {
		case <-ctx.Done():
			return hops, ctx.Err()
		default:
		}
		options := ipOptionInformation{TTL: byte(ttl)}
		reply := make([]byte, 512)
		started := time.Now()
		count, _, callErr := icmpSendEcho.Call(handle, uintptr(binary.LittleEndian.Uint32(ip.To4())), uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)), uintptr(unsafe.Pointer(&options)), uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), 1500)
		hop := PathHop{Hop: ttl, Duration: time.Since(started)}
		if count == 0 {
			hop.Error = callErr.Error()
			hops = append(hops, hop)
			continue
		}
		hop.Address = net.IPv4(reply[0], reply[1], reply[2], reply[3]).String()
		status := binary.LittleEndian.Uint32(reply[4:8])
		if status == ipStatusSuccess {
			hop.Reached = true
			hops = append(hops, hop)
			return hops, nil
		}
		if status != ipStatusTTLExpiredTransit {
			hop.Error = fmt.Sprintf("IP Helper status %d", status)
		}
		hops = append(hops, hop)
	}
	return hops, fmt.Errorf("network path did not reach %s within %d hops", address, maximum)
}
