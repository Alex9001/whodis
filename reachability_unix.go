//go:build !windows

package whodis

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func probeReachability(ctx context.Context, address string) AddressProbe {
	probe := AddressProbe{Address: address, Method: "icmp"}
	ip := net.ParseIP(address)
	if ip == nil {
		probe.Error = "invalid IP address"
		return probe
	}
	network, listenAddress, protocol := "udp4", "0.0.0.0", 1
	messageType := icmp.Type(ipv4.ICMPTypeEcho)
	probe.Network = "ipv4"
	destination := net.Addr(&net.UDPAddr{IP: ip})
	if ip.To4() == nil {
		network, listenAddress, protocol = "udp6", "::", 58
		messageType = ipv6.ICMPTypeEchoRequest
		probe.Network = "ipv6"
	}
	connection, err := icmp.ListenPacket(network, listenAddress)
	if err == nil {
		defer connection.Close()
		deadline := time.Now().Add(2 * time.Second)
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		_ = connection.SetDeadline(deadline)
		message := icmp.Message{Type: messageType, Code: 0, Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: rand.IntN(65535), Data: []byte("whodis")}}
		wire, marshalErr := message.Marshal(nil)
		if marshalErr == nil {
			started := time.Now()
			if _, writeErr := connection.WriteTo(wire, destination); writeErr == nil {
				buffer := make([]byte, 1500)
				for {
					n, _, readErr := connection.ReadFrom(buffer)
					if readErr != nil {
						err = readErr
						break
					}
					reply, parseErr := icmp.ParseMessage(protocol, buffer[:n])
					if parseErr == nil && (reply.Type == ipv4.ICMPTypeEchoReply || reply.Type == ipv6.ICMPTypeEchoReply) {
						probe.Reachable, probe.Duration = true, time.Since(started)
						return probe
					}
				}
			} else {
				err = writeErr
			}
		} else {
			err = marshalErr
		}
	}
	fallback := probeTCP(ctx, address, 443)
	fallback.Method = "tcp-fallback"
	if fallback.Error != "" && err != nil {
		fallback.Error = fmt.Sprintf("ICMP: %v; TCP: %s", err, fallback.Error)
	}
	return fallback
}
