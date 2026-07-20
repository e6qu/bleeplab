package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("at least one listen=upstream coordinate is required")
	}
	for _, mapping := range os.Args[1:] {
		listenAddress, upstreamAddress, ok := strings.Cut(mapping, "=")
		if !ok || listenAddress == "" || upstreamAddress == "" {
			log.Fatalf("invalid forwarding coordinate %q", mapping)
		}
		listener, err := net.Listen("tcp", listenAddress)
		if err != nil {
			log.Fatalf("listen on %s: %v", listenAddress, err)
		}
		go serve(listener, upstreamAddress)
	}
	select {}
}

func serve(listener net.Listener, upstreamAddress string) {
	for {
		client, err := listener.Accept()
		if err != nil {
			log.Fatalf("accept on %s: %v", listener.Addr(), err)
		}
		go forward(client, upstreamAddress)
	}
}

func forward(client net.Conn, upstreamAddress string) {
	defer func() { _ = client.Close() }()
	upstream, err := net.Dial("tcp", upstreamAddress)
	if err != nil {
		log.Printf("connect to %s: %v", upstreamAddress, err)
		return
	}
	defer func() { _ = upstream.Close() }()
	done := make(chan error, 2)
	go copyConnection(done, upstream, client)
	go copyConnection(done, client, upstream)
	if err := <-done; err != nil {
		log.Printf("forward %s: %v", upstreamAddress, err)
	}
}

func copyConnection(done chan<- error, destination net.Conn, source net.Conn) {
	_, err := io.Copy(destination, source)
	if tcp, ok := destination.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	if err != nil {
		done <- fmt.Errorf("copy stream: %w", err)
		return
	}
	done <- nil
}
