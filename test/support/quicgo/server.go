package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"

	"github.com/quic-go/quic-go"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <port>\n", os.Args[0])
		os.Exit(1)
	}
	port, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid port: %s\n", os.Args[1])
		os.Exit(1)
	}

	tlsConfig := generateTLSConfig()
	quicConfig := &quic.Config{}

	listener, err := quic.ListenAddr(fmt.Sprintf("127.0.0.1:%d", port), tlsConfig, quicConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Listen error: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Printf("READY:%d\n", port)

	conn, err := listener.Accept(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Accept error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("HANDSHAKE_COMPLETE")

	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "AcceptStream error: %v\n", err)
		os.Exit(1)
	}

	data, err := io.ReadAll(stream)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Read error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("STREAM_DATA:%x\n", data)

	echo := append([]byte("ECHO:"), data...)
	_, err = stream.Write(echo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Write error: %v\n", err)
		os.Exit(1)
	}
	stream.Close()
	fmt.Printf("SENT_DATA:%x\n", echo)
}

func generateTLSConfig() *tls.Config {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: func() []byte {
		b, _ := x509.MarshalECPrivateKey(key)
		return b
	}()})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"quic-echo"},
	}
}
