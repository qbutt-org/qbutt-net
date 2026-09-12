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
	must(gateway.WriteFrame(conn, gateway.Request{Version: 1, ID: 1, Method: "control"}))
	var response gateway.Response
	must(gateway.ReadFrame(conn, &response))
	check(response.Error == "" && response.Session != "", "control authentication failed")
	return &control{conn: conn, session: response.Session, next: 1}
}
func (c *control) request(request gateway.Request) gateway.Response {
	c.next++
	request.Version = 1
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
	must(gateway.WriteFrame(conn, gateway.Request{Version: 1, ID: 1, Method: "work", Session: accepted.Session, Lease: accepted.Lease, Generation: accepted.Generation, Connection: accepted.Connection}))
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
	must(gateway.WriteFrame(stream, gateway.Request{Version: 1, ID: 1, Method: "datagrams", Session: session}))
	var response gateway.Response
	must(gateway.ReadFrame(stream, &response))
	check(response.Error == "" && response.Session == session, "datagram authentication failed")
	stream.Close()
	return conn
}
func receive(conn *quic.Conn) gateway.Datagram {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	data, err := conn.ReceiveDatagram(ctx)
	must(err)
	packet, err := gateway.DecodeDatagram(data)
	must(err)
	return packet
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
	for name, data := range map[string][]byte{"ca.pem": caPEM, "server.pem": serverPair.certificate, "server-key.pem": serverPair.key} {
		must(os.WriteFile(filepath.Join(root, name), data, 0600))
	}
	config := map[string]any{"controlAddress": "127.0.0.1:0", "datagramAddress": "127.0.0.1:0", "listenerIP": "127.0.0.1", "advertiseIP": "127.0.0.1", "allowedPorts": []int{0}, "maxClients": 2, "maxLeases": 2, "maxTCPPerLease": 2, "maxTCP": 4, "maxTTLSeconds": 20, "certificate": filepath.Join(root, "server.pem"), "privateKey": filepath.Join(root, "server-key.pem"), "clientCA": filepath.Join(root, "ca.pem")}
	encoded, _ := json.Marshal(config)
	configPath := filepath.Join(root, "config.json")
	must(os.WriteFile(configPath, encoded, 0600))
	command := exec.Command(os.Args[1], "--config", configPath, "--stdio")
	stdout, err := command.StdoutPipe()
	must(err)
	stdin, err := command.StdinPipe()
	must(err)
	log, err := os.Create(filepath.Join(root, "server.log"))
	must(err)
	defer log.Close()
	command.Stderr = log
	must(command.Start())
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	defer func() {
		stdin.Close()
		select {
		case err := <-wait:
			must(err)
		case <-time.After(8 * time.Second):
			command.Process.Kill()
			<-wait
			panic("gateway shutdown timeout")
		}
	}()
	var ready struct {
		Ready     bool   `json:"ready"`
		Control   string `json:"control"`
		Datagrams string `json:"datagrams"`
	}
	must(json.NewDecoder(stdout).Decode(&ready))
	check(ready.Ready, "server not ready")
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
	bad, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", ready.Control, noCertificate)
	if err == nil {
		bad.SetDeadline(time.Now().Add(2 * time.Second))
		gateway.WriteFrame(bad, gateway.Request{Version: 1, ID: 1, Method: "control"})
		var response gateway.Response
		err = gateway.ReadFrame(bad, &response)
		bad.Close()
	}
	check(err != nil, "anonymous TLS admitted")
	control := connect(ready.Control, tlsConfig)
	defer control.conn.Close()
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
	otherTLS := tlsConfig.Clone()
	otherTLS.Certificates = []tls.Certificate{otherCert}
	stolen, rejected := work(ready.Control, otherTLS, firstAccepted)
	check(rejected.Error == "work_rejected", "other principal stole accepted socket")
	stolen.Close()
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
	udpPayload := []byte("original UDP datagram\x00not a stream")
	_, err = publicUDP.WriteToUDPAddrPort(udpPayload, endpoint)
	must(err)
	packet := receive(udp)
	check(packet.Lease == lease.Lease && packet.Generation == 1 && packet.Remote == publicUDP.LocalAddr().(*net.UDPAddr).AddrPort() && bytes.Equal(packet.Payload, udpPayload), "UDP metadata or payload mismatch")
	packet.Payload = []byte("reply datagram")
	wire, err := gateway.EncodeDatagram(packet)
	must(err)
	must(udp.SendDatagram(wire))
	publicUDP.SetReadDeadline(time.Now().Add(3 * time.Second))
	var buffer [2048]byte
	n, source, err := publicUDP.ReadFromUDPAddrPort(buffer[:])
	must(err)
	check(source == endpoint && bytes.Equal(buffer[:n], packet.Payload), "UDP listener port or payload lost")
	_, err = publicUDP.WriteToUDPAddrPort(bytes.Repeat([]byte{0x7f}, gateway.MaxDatagramPayload+1024), endpoint)
	must(err)
	afterOversize := []byte("valid datagram after oversized public packet")
	_, err = publicUDP.WriteToUDPAddrPort(afterOversize, endpoint)
	must(err)
	packet = receive(udp)
	check(packet.Remote == publicUDP.LocalAddr().(*net.UDPAddr).AddrPort() && bytes.Equal(packet.Payload, afterOversize),
		"oversized public packet terminated the UDP lease")
	evidence["oversizedDatagramDroppedWithoutRetiringLease"] = true
	stale := append([]byte{}, wire...)
	binary.BigEndian.PutUint64(stale[17:25], 2)
	must(udp.SendDatagram(stale))
	expectNoUDP(publicUDP)
	unseen, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	must(err)
	defer unseen.Close()
	packet.Remote = unseen.LocalAddr().(*net.UDPAddr).AddrPort()
	forged, err := gateway.EncodeDatagram(packet)
	must(err)
	must(udp.SendDatagram(forged))
	expectNoUDP(unseen)
	evidence["trueDatagramsOriginalEndpointAndNoReflection"] = true
	replacement := control.acquire("one", 2, true, 20)
	check(replacement.Lease != lease.Lease, "lease token reused")
	expectClosed(firstWork)
	expectClosed(secondWork)
	firstPeer.Close()
	<-blocked
	must(udp.SendDatagram(wire))
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
