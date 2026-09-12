package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/metacubex/mihomo/component/gateway"
	qtls "github.com/metacubex/tls"
)

type configuration struct {
	gateway.Config
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"privateKey"`
	ClientCA    string `json:"clientCA"`
}

func run() error {
	path := flag.String("config", "", "server-owned JSON configuration")
	stdio := flag.Bool("stdio", false, "stop when owning parent closes stdin")
	flag.Parse()
	if *path == "" || flag.NArg() != 0 {
		return fmt.Errorf("config_required")
	}
	file, err := os.Open(*path)
	if err != nil {
		return fmt.Errorf("config_unreadable")
	}
	defer file.Close()
	config := configuration{Config: gateway.Config{MaxClients: 16, MaxLeases: 8, MaxTCPPerLease: 32, MaxTCP: 256, MaxTTLSeconds: 120}}
	decoder := json.NewDecoder(io.LimitReader(file, gateway.MaxFrameBytes+1))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || decoder.Decode(new(any)) != io.EOF {
		return fmt.Errorf("invalid_config")
	}
	certificate, err := os.ReadFile(config.Certificate)
	if err != nil {
		return fmt.Errorf("certificate_unreadable")
	}
	privateKey, err := os.ReadFile(config.PrivateKey)
	if err != nil {
		return fmt.Errorf("private_key_unreadable")
	}
	caBytes, err := os.ReadFile(config.ClientCA)
	if err != nil {
		return fmt.Errorf("client_ca_unreadable")
	}
	ca := x509.NewCertPool()
	if !ca.AppendCertsFromPEM(caBytes) {
		return fmt.Errorf("invalid_client_ca")
	}
	pair, err := tls.X509KeyPair(certificate, privateKey)
	if err != nil {
		return fmt.Errorf("invalid_certificate")
	}
	quicPair, err := qtls.X509KeyPair(certificate, privateKey)
	if err != nil {
		return fmt.Errorf("invalid_certificate")
	}
	server, err := gateway.New(config.Config,
		&tls.Config{Certificates: []tls.Certificate{pair}, ClientCAs: ca, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13, NextProtos: []string{gateway.ALPN}},
		&qtls.Config{Certificates: []qtls.Certificate{quicPair}, ClientCAs: ca, ClientAuth: qtls.RequireAndVerifyClientCert, MinVersion: qtls.VersionTLS13, NextProtos: []string{gateway.ALPN}})
	if err != nil {
		return err
	}
	defer server.Close()
	control, datagrams := server.Addresses()
	if json.NewEncoder(os.Stdout).Encode(map[string]any{"ready": true, "control": control, "datagrams": datagrams, "protocol": gateway.Version}) != nil {
		return fmt.Errorf("parent_closed")
	}
	closed := make(chan struct{})
	if *stdio {
		go func() { io.Copy(io.Discard, os.Stdin); close(closed) }()
	}
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(interrupt)
	select {
	case <-closed:
	case <-interrupt:
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
