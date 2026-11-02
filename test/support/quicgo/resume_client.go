package main

// A client that resumes, for the tests of resumption: it connects twice,
// the second time with the session and the NEW_TOKEN token the first was
// given, sending what it is given on a stream at once, in 0-RTT when the
// session allows it. For each connection it prints whether it resumed
// and the server took 0-RTT, with what came back.

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <addr:port> <hex-data>\n", os.Args[0])
		os.Exit(1)
	}
	data, err := hex.DecodeString(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid hex data: %v\n", err)
		os.Exit(1)
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo"},
		ClientSessionCache: tls.NewLRUClientSessionCache(4),
	}
	quicConfig := &quic.Config{TokenStore: quic.NewLRUTokenStore(4, 4)}
	for i := 0; i < 2; i++ {
		if err := connect(os.Args[1], tlsConfig, quicConfig, data); err != nil {
			fmt.Fprintf(os.Stderr, "Connection %d: %v\n", i+1, err)
			os.Exit(1)
		}
	}
}

func connect(addr string, tlsConfig *tls.Config, quicConfig *quic.Config, data []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddrEarly(ctx, addr, tlsConfig, quicConfig)
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStream()
	if err != nil {
		return err
	}
	if _, err := stream.Write(data); err != nil {
		return err
	}
	stream.Close()
	response, err := io.ReadAll(stream)
	if err != nil {
		return err
	}
	<-conn.HandshakeComplete()
	state := conn.ConnectionState()
	fmt.Printf("CONNECTION resumed=%v early=%v data=%x\n", state.TLS.DidResume, state.Used0RTT, response)
	// The tickets and the token come after the handshake: a moment for
	// them to be kept.
	time.Sleep(200 * time.Millisecond)
	return nil
}
