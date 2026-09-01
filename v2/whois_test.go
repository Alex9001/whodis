package whodis

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestWHOISAdapterRejectsOversizedResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		buffer := make([]byte, 256)
		_, _ = connection.Read(buffer)
		_, _ = connection.Write(bytes.Repeat([]byte{'x'}, maximumWHOISData+1))
	}()

	adapter := whoisAdapter{client: &Client{timeout: 5 * time.Second}}
	_, err = adapter.query(context.Background(), listener.Addr().String(), "example.test", false)
	if err == nil {
		t.Fatal("oversized WHOIS response was accepted")
	}
	var lookupErr *LookupError
	if !errors.As(err, &lookupErr) || lookupErr.Kind != ErrorProtocol || !strings.Contains(err.Error(), "8 MiB") {
		t.Fatalf("oversized response error = %v", err)
	}
	<-serverDone
}
