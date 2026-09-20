// Actual-process TLS/QUIC integration fixture; no production profile is read.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/gateway"
	quic "github.com/metacubex/quic-go"
	qtls "github.com/metacubex/tls"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func check(value bool, message string) {
	if !value {
		panic(message)
	}
}

type credentials struct{ certificate, key []byte }

func issue(ca *x509.Certificate, key *ecdsa.PrivateKey, server bool) credentials {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	must(err)
	certificate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "generated-qbutt-fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if server {
		certificate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		certificate.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, ca, &private.PublicKey, key)
	must(err)
	encodedKey, err := x509.MarshalPKCS8PrivateKey(private)
	must(err)
	return credentials{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey})}
}

type control struct {
	conn    *tls.Conn
	session string
	next    uint64
	events  []gateway.Response
}

func connect(address string, config *tls.Config) *control {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, config)
	must(err)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	must(gateway.WriteFrame(conn, gateway.Request{Version: gateway.Version, ID: 1, Method: "control"}))
	var response gateway.Response
	must(gateway.ReadFrame(conn, &response))
	check(response.Error == "" && response.Session != "", "control authentication failed")
	return &control{conn: conn, session: response.Session, next: 1}
}
func (c *control) request(request gateway.Request) gateway.Response {
	c.next++
	request.Version = gateway.Version
	request.ID = c.next
	request.Session = c.session
	c.conn.SetDeadline(time.Now().Add(5 * time.Second))
	must(gateway.WriteFrame(c.conn, request))
	for {
		var response gateway.Response
		must(gateway.ReadFrame(c.conn, &response))
		if response.ID == request.ID {
			return response
		}
		c.events = append(c.events, response)
	}
}
func (c *control) accepted() gateway.Accepted {
	for {
		if len(c.events) > 0 {
			response := c.events[0]
			c.events = c.events[1:]
			if response.Accepted != nil {
				return *response.Accepted
			}
			continue
		}
		c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		var response gateway.Response
		must(gateway.ReadFrame(c.conn, &response))
		if response.Accepted != nil {
			return *response.Accepted
		}
	}
}
func (c *control) acquire(path string, generation uint64, udp bool, ttl int) gateway.LeaseInfo {
	response := c.request(gateway.Request{Method: "acquire", Path: path, Generation: generation, TCP: true, UDP: udp, TTLSeconds: ttl})
	check(response.Error == "" && response.Lease != nil, "acquire: "+response.Error)
	return *response.Lease
}
func work(address string, config *tls.Config, accepted gateway.Accepted) (*tls.Conn, gateway.Response) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, config)
	must(err)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	must(gateway.WriteFrame(conn, gateway.Request{Version: gateway.Version, ID: 1, Method: "work", Session: accepted.Session, Lease: accepted.Lease, Generation: accepted.Generation, Connection: accepted.Connection}))
	var response gateway.Response
	must(gateway.ReadFrame(conn, &response))
	return conn, response
}
func udpChannel(address string, config *qtls.Config, session string) *quic.Conn {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, address, config, gateway.QUICConfig())
	must(err)
	stream, err := conn.OpenStreamSync(ctx)
	must(err)
	stream.SetDeadline(time.Now().Add(5 * time.Second))
	must(gateway.WriteFrame(stream, gateway.Request{Version: gateway.Version, ID: 1, Method: "datagrams", Session: session}))
	var response gateway.Response
	must(gateway.ReadFrame(stream, &response))
	check(response.Error == "" && response.Session == session, "datagram authentication failed")
	stream.Close()
	return conn
}
func receive(conn *quic.Conn) gateway.Datagram {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var reassembler gateway.Reassembler
	for {
		data, err := conn.ReceiveDatagram(ctx)
		must(err)
		fragment, err := gateway.DecodeDatagram(data)
		must(err)
		packet, status, _ := reassembler.Add(fragment, time.Now())
		if status == gateway.ReassemblyComplete {
			return packet
		}
	}
}
func send(conn *quic.Conn, packet gateway.Datagram, message uint64, reverse bool, duplicate int) {
	fragments, err := gateway.EncodeDatagram(packet, message)
	must(err)
	if reverse {
		for left, right := 0, len(fragments)-1; left < right; left, right = left+1, right-1 {
			fragments[left], fragments[right] = fragments[right], fragments[left]
		}
	}
	for index, fragment := range fragments {
		must(conn.SendDatagram(fragment))
		if index == duplicate {
			must(conn.SendDatagram(fragment))
		}
	}
}
func rejectTLS(address string, config *tls.Config, request gateway.Request) bool {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", address, config)
	if err != nil {
		return true
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if gateway.WriteFrame(conn, request) != nil {
		return true
	}
	var response gateway.Response
	return gateway.ReadFrame(conn, &response) != nil
}
func rejectQUIC(address string, config *qtls.Config) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, address, config, gateway.QUICConfig())
	if err != nil {
		return true
	}
	defer conn.CloseWithError(0, "fixture_done")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return true
	}
	stream.SetDeadline(time.Now().Add(2 * time.Second))
	if gateway.WriteFrame(stream, gateway.Request{Version: gateway.Version, ID: 1, Method: "datagrams", Session: "invalid"}) != nil {
		return true
	}
	var response gateway.Response
	return gateway.ReadFrame(stream, &response) != nil
}
func expectClosed(conn net.Conn) {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var buffer [32768]byte
	for total := 0; total <= 32*1024*1024; {
		n, err := conn.Read(buffer[:])
		total += n
		if err == nil {
			continue
		}
		if timeout, ok := err.(net.Error); ok {
			check(!timeout.Timeout(), "retired socket remained open")
		}
		return
	}
	panic("retired socket exceeded bounded buffered payload")
}
func expectNoUDP(conn *net.UDPConn) {
	conn.SetReadDeadline(time.Now().Add(180 * time.Millisecond))
	var b [2048]byte
	_, _, err := conn.ReadFromUDPAddrPort(b[:])
	timeout, ok := err.(net.Error)
	check(ok && timeout.Timeout(), "rejected UDP packet escaped")
}

type readyInfo struct {
	Ready     bool   `json:"ready"`
	Control   string `json:"control"`
	Datagrams string `json:"datagrams"`
}

type gatewayProcess struct {
	command *exec.Cmd
	stdin   io.WriteCloser
	wait    chan error
	log     *os.File
	ready   readyInfo
}

func startGateway(executable, configPath, logPath string) *gatewayProcess {
	command := exec.Command(executable, "--config", configPath, "--stdio")
	stdout, err := command.StdoutPipe()
	must(err)
	stdin, err := command.StdinPipe()
	must(err)
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	must(err)
	command.Stderr = log
	must(command.Start())
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	process := &gatewayProcess{command: command, stdin: stdin, wait: wait, log: log}
	if err := json.NewDecoder(stdout).Decode(&process.ready); err != nil || !process.ready.Ready {
		process.stop()
		panic("server not ready")
	}
	return process
}

func (process *gatewayProcess) stop() {
	if process.command == nil {
		return
	}
	process.stdin.Close()
	select {
	case err := <-process.wait:
		must(err)
	case <-time.After(8 * time.Second):
		process.command.Process.Kill()
		<-process.wait
		panic("gateway shutdown timeout")
	}
	process.log.Close()
	process.command = nil
}

func run() (evidence map[string]any) {
	check(len(os.Args) == 3, "gateway executable and fresh generated output required")
	root, err := filepath.Abs(os.Args[2])
	must(err)
	check(strings.HasPrefix(filepath.Base(root), "qbutt-gateway-"), "generated output directory required")
	must(os.Mkdir(root, 0700))
	evidence = map[string]any{"status": "running", "publicInboundProven": false}
	defer func() {
		if failure := recover(); failure != nil {
			evidence["status"] = "failed"
			evidence["error"] = fmt.Sprint(failure)
		}
		data, _ := json.MarshalIndent(evidence, "", "  ")
		os.WriteFile(filepath.Join(root, "evidence.json"), data, 0600)
	}()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "temporary-gateway-lab-CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	must(err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	serverPair := issue(ca, caKey, true)
	clientPair := issue(ca, caKey, false)
	otherPair := issue(ca, caKey, false)
	clientBlock, _ := pem.Decode(clientPair.certificate)
	check(clientBlock != nil, "client certificate encoding")
	clientFingerprint := sha256.Sum256(clientBlock.Bytes)
	for name, data := range map[string][]byte{"ca.pem": caPEM, "server.pem": serverPair.certificate, "server-key.pem": serverPair.key} {
		must(os.WriteFile(filepath.Join(root, name), data, 0600))
	}
	config := map[string]any{"controlAddress": "127.0.0.1:0", "datagramAddress": "127.0.0.1:0", "listenerIP": "127.0.0.1", "advertiseIP": "127.0.0.1", "allowedPorts": []int{0}, "maxClients": 1, "maxLeases": 2, "maxTCPPerLease": 2, "maxTCP": 4, "maxTTLSeconds": 20, "maxUDPPacketsPerSecond": 64, "maxUDPBytesPerSecond": 4 * gateway.MaxDatagramPayload, "clientCertificateSHA256": hex.EncodeToString(clientFingerprint[:]), "certificate": filepath.Join(root, "server.pem"), "privateKey": filepath.Join(root, "server-key.pem"), "clientCA": filepath.Join(root, "ca.pem")}
	encoded, _ := json.Marshal(config)
	configPath := filepath.Join(root, "config.json")
	must(os.WriteFile(configPath, encoded, 0600))
	process := startGateway(os.Args[1], configPath, filepath.Join(root, "server.log"))
	defer func() {
		if process != nil {
			process.stop()
		}
	}()
	ready := process.ready
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	clientCert, err := tls.X509KeyPair(clientPair.certificate, clientPair.key)
	must(err)
	otherCert, err := tls.X509KeyPair(otherPair.certificate, otherPair.key)
	must(err)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{gateway.ALPN}, RootCAs: pool, Certificates: []tls.Certificate{clientCert}, ServerName: "127.0.0.1"}
	quicCert, err := qtls.X509KeyPair(clientPair.certificate, clientPair.key)
	must(err)
	quicConfig := &qtls.Config{MinVersion: qtls.VersionTLS13, NextProtos: []string{gateway.ALPN}, RootCAs: pool, Certificates: []qtls.Certificate{quicCert}, ServerName: "127.0.0.1"}
	noCertificate := tlsConfig.Clone()
	noCertificate.Certificates = nil
	check(rejectTLS(ready.Control, noCertificate, gateway.Request{Version: gateway.Version, ID: 1, Method: "control"}), "anonymous TLS admitted")
	otherTLS := tlsConfig.Clone()
	otherTLS.Certificates = []tls.Certificate{otherCert}
	otherQUICCert, err := qtls.X509KeyPair(otherPair.certificate, otherPair.key)
	must(err)
	otherQUIC := quicConfig.Clone()
	otherQUIC.Certificates = []qtls.Certificate{otherQUICCert}
	check(rejectTLS(ready.Control, otherTLS, gateway.Request{Version: gateway.Version, ID: 1, Method: "control"}), "other CA-signed client admitted to control")
	check(rejectQUIC(ready.Datagrams, otherQUIC), "other CA-signed client admitted to QUIC")
	control := connect(ready.Control, tlsConfig)
	defer control.conn.Close()
	secondControl, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", ready.Control, tlsConfig)
	must(err)
	secondControl.SetDeadline(time.Now().Add(2 * time.Second))
	must(gateway.WriteFrame(secondControl, gateway.Request{Version: gateway.Version, ID: 1, Method: "control"}))
	var limited gateway.Response
	must(gateway.ReadFrame(secondControl, &limited))
	check(limited.Error == "client_limit", "one-tenant session limit bypassed")
	secondControl.Close()
	evidence["exactClientCertificateAndSingleTenant"] = true
	check(control.request(gateway.Request{Method: "acquire", Path: "one", Generation: 1, TCP: true, UDP: true, TTLSeconds: 10}).Error == "datagrams_required", "UDP advertised without carrier")
	udp := udpChannel(ready.Datagrams, quicConfig, control.session)
	defer udp.CloseWithError(0, "fixture_done")
	lease := control.acquire("one", 1, true, 20)
	check(control.request(gateway.Request{Method: "acquire", Path: "one", Generation: 1, TCP: true, TTLSeconds: 10}).Error == "generation_rejected", "generation replay accepted")
	check(control.request(gateway.Request{Method: "acquire", Path: "port", Generation: 1, TCP: true, Port: 12345, TTLSeconds: 10}).Error == "port_denied", "port ACL bypass")
	second := control.acquire("two", 1, false, 20)
	check(control.request(gateway.Request{Method: "acquire", Path: "three", Generation: 1, TCP: true, TTLSeconds: 10}).Error == "lease_limit", "lease quota bypass")
	check(control.request(gateway.Request{Method: "release", Lease: second.Lease, Generation: 1}).Error == "", "release failed")
	firstPeer, err := net.DialTimeout("tcp", lease.Endpoint, time.Second)
	must(err)
	defer firstPeer.Close()
	firstAccepted := control.accepted()
	check(firstAccepted.Remote == firstPeer.LocalAddr().String(), "original TCP endpoint lost")
	check(rejectTLS(ready.Control, otherTLS, gateway.Request{Version: gateway.Version, ID: 1, Method: "work", Session: firstAccepted.Session, Lease: firstAccepted.Lease, Generation: firstAccepted.Generation, Connection: firstAccepted.Connection}), "other CA-signed client admitted to work")
	firstWork, accepted := work(ready.Control, tlsConfig, firstAccepted)
	mustErr := accepted.Error
	check(mustErr == "" && accepted.Accepted.Remote == firstPeer.LocalAddr().String(), "trusted work metadata mismatch")
	defer firstWork.Close()
	duplicate, rejected := work(ready.Control, tlsConfig, firstAccepted)
	check(rejected.Error == "work_rejected", "work replay admitted")
	duplicate.Close()
	secondPeer, err := net.DialTimeout("tcp", lease.Endpoint, time.Second)
	must(err)
	defer secondPeer.Close()
	secondAccepted := control.accepted()
	secondWork, accepted := work(ready.Control, tlsConfig, secondAccepted)
	check(accepted.Error == "", "second work rejected")
	defer secondWork.Close()
	thirdPeer, err := net.DialTimeout("tcp", lease.Endpoint, time.Second)
	must(err)
	expectClosed(thirdPeer)
	thirdPeer.Close()
	// A blocked independent stream cannot block control or the other stream.
	blocked := make(chan struct{})
	go func() { defer close(blocked); firstPeer.Write(bytes.Repeat([]byte{0x51}, 16*1024*1024)) }()
	payload := bytes.Repeat([]byte("verified-independent-stream\x00"), 4096)
	written := make(chan error, 1)
	go func() { _, err := secondPeer.Write(payload); written <- err }()
	secondWork.SetReadDeadline(time.Now().Add(3 * time.Second))
	received := make([]byte, len(payload))
	_, err = io.ReadFull(secondWork, received)
	must(err)
	must(<-written)
	check(bytes.Equal(received, payload), "TCP payload mismatch")
	start := time.Now()
	check(control.request(gateway.Request{Method: "renew", Lease: lease.Lease, Generation: 1, TTLSeconds: 20}).Error == "", "renew blocked")
	check(time.Since(start) < time.Second, "control blocked by payload")
	digest := sha256.Sum256(received)
	evidence["tcpVerifiedBytes"] = len(received)
	evidence["tcpSHA256"] = hex.EncodeToString(digest[:])
	evidence["independentStreamsAndControl"] = true
	publicUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	must(err)
	defer publicUDP.Close()
	endpoint := netip.MustParseAddrPort(lease.Endpoint)
	var packet gateway.Datagram
	var replay [][]byte
	verifiedUDP := 0
	for index, size := range []int{1200, 1500, gateway.MaxDatagramPayload} {
		udpPayload := bytes.Repeat([]byte{byte(41 + index)}, size)
		_, err = publicUDP.WriteToUDPAddrPort(udpPayload, endpoint)
		must(err)
		packet = receive(udp)
		check(packet.Lease == lease.Lease && packet.Generation == 1 && packet.Remote == publicUDP.LocalAddr().(*net.UDPAddr).AddrPort() && bytes.Equal(packet.Payload, udpPayload), "fragmented public UDP payload or endpoint mismatch")
		verifiedUDP += len(packet.Payload)
		replay, err = gateway.EncodeDatagram(packet, uint64(index+1))
		must(err)
		for left, right := 0, len(replay)-1; left < right; left, right = left+1, right-1 {
			replay[left], replay[right] = replay[right], replay[left]
		}
		for fragmentIndex, fragment := range replay {
			must(udp.SendDatagram(fragment))
			if size == 1500 && fragmentIndex == 0 {
				must(udp.SendDatagram(fragment))
			}
		}
		publicUDP.SetReadDeadline(time.Now().Add(3 * time.Second))
		buffer := make([]byte, 65535)
		n, source, err := publicUDP.ReadFromUDPAddrPort(buffer)
		must(err)
		check(source == endpoint && bytes.Equal(buffer[:n], udpPayload), "fragmented client UDP payload or listener endpoint mismatch")
		verifiedUDP += n
	}
	evidence["fragmentedUDPVerifiedBytes"] = verifiedUDP
	evidence["fragmentedUDPSizes"] = []int{1200, 1500, gateway.MaxDatagramPayload}
	for _, fragment := range replay {
		must(udp.SendDatagram(fragment))
	}
	expectNoUDP(publicUDP)

	lost := gateway.Datagram{Lease: lease.Lease, Generation: 1, Remote: publicUDP.LocalAddr().(*net.UDPAddr).AddrPort(), Payload: bytes.Repeat([]byte{0x71}, 1500)}
	lostFragments, err := gateway.EncodeDatagram(lost, 100)
	must(err)
	must(udp.SendDatagram(lostFragments[0]))
	expectNoUDP(publicUDP)
	time.Sleep(gateway.DatagramFragmentLifetime + 100*time.Millisecond)
	must(udp.SendDatagram(lostFragments[1]))
	expectNoUDP(publicUDP)
	for message := uint64(200); message < 240; message++ {
		incomplete, encodeErr := gateway.EncodeDatagram(gateway.Datagram{Lease: lease.Lease, Generation: 1, Remote: lost.Remote, Payload: bytes.Repeat([]byte{0x72}, gateway.MaxDatagramPayload)}, message)
		must(encodeErr)
		must(udp.SendDatagram(incomplete[0]))
	}
	time.Sleep(gateway.DatagramFragmentLifetime + 100*time.Millisecond)
	postLoss := gateway.Datagram{Lease: lease.Lease, Generation: 1, Remote: lost.Remote, Payload: []byte("valid after incomplete fragments")}
	send(udp, postLoss, 300, false, -1)
	publicUDP.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 65535)
	n, source, err := publicUDP.ReadFromUDPAddrPort(buffer)
	must(err)
	check(source == endpoint && bytes.Equal(buffer[:n], postLoss.Payload), "incomplete fragments poisoned later datagram")

	stale, err := gateway.EncodeDatagram(gateway.Datagram{Lease: lease.Lease, Generation: 2, Remote: lost.Remote, Payload: []byte("stale")}, 301)
	must(err)
	for _, fragment := range stale {
		must(udp.SendDatagram(fragment))
	}
	expectNoUDP(publicUDP)
	unseen, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	must(err)
	defer unseen.Close()
	packet.Remote = unseen.LocalAddr().(*net.UDPAddr).AddrPort()
	packet.Payload = []byte("authenticated first contact")
	send(udp, packet, 302, false, -1)
	unseen.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, source, err = unseen.ReadFromUDPAddrPort(buffer)
	must(err)
	check(source == endpoint && bytes.Equal(buffer[:n], packet.Payload), "authenticated first-contact UDP did not use the leased public endpoint")
	_, err = unseen.WriteToUDPAddrPort([]byte("first-contact reply"), endpoint)
	must(err)
	replyPacket := receive(udp)
	check(replyPacket.Lease == lease.Lease && replyPacket.Generation == 1 &&
		replyPacket.Remote == packet.Remote && bytes.Equal(replyPacket.Payload, []byte("first-contact reply")),
		"first-contact destination did not admit its exact reply")
	wrongFamily := packet
	wrongFamily.Remote = netip.MustParseAddrPort("[::1]:12345")
	wrongFamily.Payload = []byte("wrong family")
	policyBefore := control.request(gateway.Request{Method: "stats"})
	check(policyBefore.Error == "" && policyBefore.Datagrams != nil, "policy diagnostics unavailable")
	send(udp, wrongFamily, 303, false, -1)
	privateRemote := packet
	privateRemote.Remote = netip.MustParseAddrPort("10.255.255.254:9")
	privateRemote.Payload = []byte("private destination denied")
	send(udp, privateRemote, 304, false, -1)
	expectNoUDP(publicUDP)
	policyAfter := control.request(gateway.Request{Method: "stats"})
	check(policyAfter.Error == "" && policyAfter.Datagrams != nil &&
		policyAfter.Datagrams.PolicyDrops >= policyBefore.Datagrams.PolicyDrops+2,
		"wrong-family or private destination was not rejected")

	time.Sleep(time.Second)
	byteRatePackets := 8
	byteRateReceived := make(chan int, 1)
	go func() {
		count := 0
		largeBuffer := make([]byte, 65535)
		for {
			publicUDP.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			if _, _, readErr := publicUDP.ReadFromUDPAddrPort(largeBuffer); readErr != nil {
				byteRateReceived <- count
				return
			}
			count++
		}
	}()
	for message := uint64(350); message < uint64(350+byteRatePackets); message++ {
		send(udp, gateway.Datagram{Lease: lease.Lease, Generation: 1, Remote: lost.Remote, Payload: bytes.Repeat([]byte{0x62}, gateway.MaxDatagramPayload)}, message, false, -1)
	}
	deliveredByteRate := <-byteRateReceived
	check(deliveredByteRate > 0 && deliveredByteRate < byteRatePackets, "tenant byte rate cap was not observable")
	time.Sleep(time.Second)
	for message := uint64(400); message < 500; message++ {
		send(udp, gateway.Datagram{Lease: lease.Lease, Generation: 1, Remote: lost.Remote, Payload: []byte("rate")}, message, false, -1)
	}
	receivedRatePackets := 0
	for {
		publicUDP.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, _, readErr := publicUDP.ReadFromUDPAddrPort(buffer)
		if readErr != nil {
			break
		}
		receivedRatePackets++
	}
	check(receivedRatePackets > 0 && receivedRatePackets < 100, "tenant packet rate cap was not observable")
	statsResponse := control.request(gateway.Request{Method: "stats"})
	check(statsResponse.Error == "" && statsResponse.Datagrams != nil, "datagram diagnostics unavailable")
	stats := *statsResponse.Datagrams
	check(stats.DuplicateFragments > 0 && stats.ExpiredAssemblies > 0 && stats.ReassemblyDrops > 0 && stats.PolicyDrops >= 2 && stats.PacketRateDrops > 0 && stats.ByteRateDrops > 0, "bounded datagram diagnostics incomplete")
	evidence["datagramStats"] = stats
	evidence["byteRateDeliveredPackets"] = deliveredByteRate
	evidence["rateDeliveredPackets"] = receivedRatePackets
	evidence["trueDatagramsOriginalEndpointAndAuthenticatedFirstContact"] = true
	replacement := control.acquire("one", 2, true, 20)
	check(replacement.Lease != lease.Lease, "lease token reused")
	// The replacement has an empty destination table. Fill it with distinct
	// authenticated first contacts, then prove the next tuple cannot be used.
	time.Sleep(time.Second)
	capacityPeers := make([]*net.UDPConn, 0, 129)
	defer func() {
		for _, peer := range capacityPeers {
			peer.Close()
		}
	}()
	for index := 0; index < 129; index++ {
		peer, listenErr := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		must(listenErr)
		capacityPeers = append(capacityPeers, peer)
		contact := gateway.Datagram{Lease: replacement.Lease, Generation: 2,
			Remote: peer.LocalAddr().(*net.UDPAddr).AddrPort(), Payload: []byte("destination bound")}
		send(udp, contact, uint64(600+index), false, -1)
		if index < 128 {
			peer.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, source, readErr := peer.ReadFromUDPAddrPort(buffer)
			must(readErr)
			check(source == netip.MustParseAddrPort(replacement.Endpoint) &&
				bytes.Equal(buffer[:n], contact.Payload), "bounded first-contact destination lost")
		} else {
			expectNoUDP(peer)
		}
		time.Sleep(25 * time.Millisecond)
	}
	statsResponse = control.request(gateway.Request{Method: "stats"})
	check(statsResponse.Error == "" && statsResponse.Datagrams != nil &&
		statsResponse.Datagrams.PolicyDrops > stats.PolicyDrops,
		"destination table did not reject the 129th tuple")
	stats = *statsResponse.Datagrams
	evidence["datagramStats"] = stats
	evidence["boundedDestinationsPerGeneration"] = 128
	for _, peer := range capacityPeers {
		peer.Close()
	}
	capacityPeers = nil
	expectClosed(firstWork)
	expectClosed(secondWork)
	firstPeer.Close()
	<-blocked
	for _, fragment := range replay {
		must(udp.SendDatagram(fragment))
	}
	expectNoUDP(publicUDP)
	check(control.request(gateway.Request{Method: "renew", Lease: lease.Lease, Generation: 1, TTLSeconds: 20}).Error == "lease_rejected", "old lease renewed")
	check(control.request(gateway.Request{Method: "release", Lease: replacement.Lease, Generation: 2}).Error == "", "replacement release failed")
	renewed := control.acquire("renew-boundary", 1, false, 1)
	time.Sleep(750 * time.Millisecond)
	check(control.request(gateway.Request{Method: "renew", Lease: renewed.Lease, Generation: 1, TTLSeconds: 2}).Error == "", "near-deadline renew failed")
	time.Sleep(500 * time.Millisecond)
	renewedPeer, err := net.DialTimeout("tcp", renewed.Endpoint, time.Second)
	must(err)
	renewedAccepted := control.accepted()
	renewedWork, accepted := work(ready.Control, tlsConfig, renewedAccepted)
	check(accepted.Error == "", "renewed lease was retired at its old deadline")
	renewedWork.Close()
	renewedPeer.Close()
	check(control.request(gateway.Request{Method: "release", Lease: renewed.Lease, Generation: 1}).Error == "", "renewed lease release failed")
	evidence["renewalSurvivesPreviousDeadline"] = true
	expiring := control.acquire("expires", 1, false, 1)
	expiresPeer, err := net.DialTimeout("tcp", expiring.Endpoint, time.Second)
	must(err)
	expiryAccepted := control.accepted()
	expiryWork, accepted := work(ready.Control, tlsConfig, expiryAccepted)
	check(accepted.Error == "", "expiry work rejected")
	expectClosed(expiryWork)
	expiryWork.Close()
	expiresPeer.Close()
	check(control.request(gateway.Request{Method: "renew", Lease: expiring.Lease, Generation: 1, TTLSeconds: 1}).Error == "lease_rejected", "expired lease revived")
	evidence["generationReplacementExpiryAndQuotas"] = true
	active := control.acquire("disconnect", 1, true, 20)
	udp.CloseWithError(0, "fixture_transport_failure")
	time.Sleep(150 * time.Millisecond)
	check(control.request(gateway.Request{Method: "renew", Lease: active.Lease, Generation: 1, TTLSeconds: 20}).Error == "lease_rejected", "UDP transport death retained public capability")
	control.conn.Close()
	time.Sleep(100 * time.Millisecond)
	fresh := connect(ready.Control, tlsConfig)
	defer fresh.conn.Close()
	check(fresh.session != control.session, "control session token reused")
	reset := fresh.acquire("one", 1, false, 20)
	check(reset.Lease != lease.Lease, "restart token replay")
	persistentStats := fresh.request(gateway.Request{Method: "stats"})
	check(persistentStats.Error == "" && persistentStats.Datagrams != nil && persistentStats.Datagrams.ToPublicBytes == stats.ToPublicBytes && persistentStats.Datagrams.PacketRateDrops == stats.PacketRateDrops && persistentStats.Datagrams.ByteRateDrops == stats.ByteRateDrops, "control reconnect reset process diagnostics")
	oldWork, rejected := work(ready.Control, tlsConfig, firstAccepted)
	check(rejected.Error == "work_rejected", "old control session work accepted")
	oldWork.Close()
	// Invalid framing closes the owning session and its public listener.
	var oversized [4]byte
	binary.BigEndian.PutUint32(oversized[:], gateway.MaxFrameBytes+1)
	fresh.conn.Write(oversized[:])
	expectClosed(fresh.conn)
	_, err = net.DialTimeout("tcp", reset.Endpoint, 300*time.Millisecond)
	check(err != nil, "malformed control retained listener")
	evidence["controlAndQUICFailureRetireLeases"] = true
	firstPID := process.command.Process.Pid
	process.stop()
	process = startGateway(os.Args[1], configPath, filepath.Join(root, "server.log"))
	ready = process.ready
	check(process.command.Process.Pid != firstPID, "gateway process did not restart")
	restarted := connect(ready.Control, tlsConfig)
	restartedLease := restarted.acquire("one", 1, false, 20)
	check(restarted.session != fresh.session && restartedLease.Lease != reset.Lease, "process restart reused authentication state")
	restartedStats := restarted.request(gateway.Request{Method: "stats"})
	check(restartedStats.Error == "" && restartedStats.Datagrams != nil && *restartedStats.Datagrams == (gateway.DatagramStats{}), "process restart retained diagnostics")
	oldProcessWork, rejected := work(ready.Control, tlsConfig, firstAccepted)
	check(rejected.Error == "work_rejected", "process restart accepted old work identity")
	oldProcessWork.Close()
	restarted.conn.Close()
	evidence["actualProcessRestartClearsState"] = true
	evidence["controlReconnectPreservesDiagnostics"] = true
	evidence["status"] = "passed"
	return evidence
}

func main() {
	evidence := run()
	json.NewEncoder(os.Stdout).Encode(evidence)
	if evidence["status"] != "passed" {
		os.Exit(1)
	}
}
