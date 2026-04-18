package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <addr:port> <hex-data>\n", os.Args[0])
		os.Exit(1)
	}
	addr := os.Args[1]
	dataHex := os.Args[2]

	data, err := hex.DecodeString(dataHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid hex data: %v\n", err)
		os.Exit(1)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo"},
	}
	// Enable qlog tracing for debugging interop issues
	quicConfig := &quic.Config{
		Tracer: func(ctx context.Context, p logging.Perspective, connID quic.ConnectionID) *logging.ConnectionTracer {
			dir := "/tmp/raiha-qlog"
			os.MkdirAll(dir, 0755)
			name := fmt.Sprintf("%s/client-%s.qlog", dir, connID)
			f, err := os.Create(name)
			if err != nil {
				return nil
			}
			return qlog.NewConnectionTracer(f, p, connID)
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, addr, tlsConfig, quicConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Dial error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("HANDSHAKE_COMPLETE")

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "OpenStream error: %v\n", err)
		os.Exit(1)
	}

	_, err = stream.Write(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Write error: %v\n", err)
		os.Exit(1)
	}
	stream.Close()

	response, err := io.ReadAll(stream)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Read error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("STREAM_DATA:%x\n", response)
}
