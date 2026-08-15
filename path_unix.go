//go:build !windows

package whodis

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func traceNetworkPath(ctx context.Context, address string, maximum int) ([]PathHop, error) {
	ip := net.ParseIP(address)
	if ip == nil {
		return nil, fmt.Errorf("invalid path-trace address %q", address)
	}
	network, listenAddress, protocol := "ip4:icmp", "0.0.0.0", 1
	echoType, replyType, expiredType := icmp.Type(ipv4.ICMPTypeEcho), icmp.Type(ipv4.ICMPTypeEchoReply), icmp.Type(ipv4.ICMPTypeTimeExceeded)
	destination := net.Addr(&net.IPAddr{IP: ip})
	if ip.To4() == nil {
		network, listenAddress, protocol = "ip6:ipv6-icmp", "::", 58
		echoType, replyType, expiredType = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply, ipv6.ICMPTypeTimeExceeded
	}
	connection, err := icmp.ListenPacket(network, listenAddress)
	if err != nil {
		return nil, fmt.Errorf("network path trace requires raw ICMP permission: %w", err)
	}
	defer connection.Close()
	var hops []PathHop
	for ttl := 1; ttl <= maximum; ttl++ {
		select {
		case <-ctx.Done():
			return hops, ctx.Err()
		default:
		}
		if ip.To4() != nil {
			err = ipv4.NewPacketConn(connection).SetTTL(ttl)
		} else {
			err = ipv6.NewPacketConn(connection).SetHopLimit(ttl)
		}
		if err != nil {
			return hops, err
		}
		message := icmp.Message{Type: echoType, Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: nextICMPSequence(), Data: []byte("whodis-path")}}
		wire, marshalErr := message.Marshal(nil)
		if marshalErr != nil {
			return hops, marshalErr
		}
		deadline := time.Now().Add(1500 * time.Millisecond)
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		_ = connection.SetDeadline(deadline)
		started := time.Now()
		if _, err = connection.WriteTo(wire, destination); err != nil {
			hops = append(hops, PathHop{Hop: ttl, Error: err.Error()})
			continue
		}
		buffer := make([]byte, 1500)
		n, source, readErr := connection.ReadFrom(buffer)
		hop := PathHop{Hop: ttl, Duration: time.Since(started)}
		if source != nil {
			hop.Address = source.String()
		}
		if readErr != nil {
			hop.Error = readErr.Error()
			hops = append(hops, hop)
			continue
		}
		reply, parseErr := icmp.ParseMessage(protocol, buffer[:n])
		if parseErr != nil {
			hop.Error = parseErr.Error()
			hops = append(hops, hop)
			continue
		}
		if reply.Type == replyType {
			hop.Reached = true
			hops = append(hops, hop)
			return hops, nil
		}
		if reply.Type != expiredType {
			hop.Error = fmt.Sprintf("unexpected ICMP response %v", reply.Type)
		}
		hops = append(hops, hop)
	}
	return hops, fmt.Errorf("network path did not reach %s within %d hops", address, maximum)
}
