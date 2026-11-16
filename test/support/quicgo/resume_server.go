package main

// A server that takes 0-RTT, for the tests of resumption: it takes every
// connection, answers the first stream of each with "ECHO:" and what came
// on it, and prints, once each handshake is done, whether it resumed and
// took 0-RTT, with the data the stream carried.

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/quic-go/quic-go"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <port> <cert.pem> <key.pem>\n", os.Args[0])
		os.Exit(1)
	}
	port, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid port: %s\n", os.Args[1])
		os.Exit(1)
	}
	cert, err := tls.LoadX509KeyPair(os.Args[2], os.Args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Certificate error: %v\n", err)
		os.Exit(1)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"quic-echo"}}

	listener, err := quic.ListenAddrEarly(fmt.Sprintf("127.0.0.1:%d", port), tlsConfig, &quic.Config{Allow0RTT: true})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Listen error: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Printf("READY:%d\n", port)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Accept error: %v\n", err)
			os.Exit(1)
		}
		go echo(conn)
	}
}

func echo(conn *quic.Conn) {
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "AcceptStream error: %v\n", err)
		return
	}
	data, err := io.ReadAll(stream)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Read error: %v\n", err)
		return
	}
	stream.Write(append([]byte("ECHO:"), data...))
	stream.Close()
	<-conn.HandshakeComplete()
	state := conn.ConnectionState()
	fmt.Printf("CONNECTION resumed=%v early=%v data=%x\n", state.TLS.DidResume, state.Used0RTT, data)
}
