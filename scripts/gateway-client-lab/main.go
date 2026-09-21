package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	parentProtocol        = 6
	effectiveSOCKSPayload = 65485
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

type credentials struct {
	certificate []byte
	der         []byte
	key         []byte
}

func issue(ca *x509.Certificate, caKey *ecdsa.PrivateKey, server bool) credentials {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	must(err)
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "qbutt-generated-fixture"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	must(err)
	encodedKey, err := x509.MarshalPKCS8PrivateKey(key)
	must(err)
	return credentials{certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), der: der,
		key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey})}
}

type socksFixture struct {
	listener   net.Listener
	mu         sync.Mutex
	tcpTargets []string
	udpTargets []string
	wg         sync.WaitGroup
}

func newSOCKSFixture() *socksFixture {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	must(err)
	fixture := &socksFixture{listener: listener}
	fixture.wg.Add(1)
	go fixture.accept()
	return fixture
}

func (fixture *socksFixture) close() {
	fixture.listener.Close()
	fixture.wg.Wait()
}

func (fixture *socksFixture) accept() {
	defer fixture.wg.Done()
	for {
		conn, err := fixture.listener.Accept()
		if err != nil {
			return
		}
		fixture.wg.Add(1)
		go func() {
			defer fixture.wg.Done()
			defer conn.Close()
			fixture.serve(conn)
		}()
	}
}

func readSOCKSAddress(reader io.Reader, kind byte) (string, error) {
	var host string
	switch kind {
	case 1:
		var address [4]byte
		if _, err := io.ReadFull(reader, address[:]); err != nil {
			return "", err
		}
		host = net.IP(address[:]).String()
	case 4:
		var address [16]byte
		if _, err := io.ReadFull(reader, address[:]); err != nil {
			return "", err
		}
		host = net.IP(address[:]).String()
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(reader, size[:]); err != nil || size[0] == 0 {
			return "", errors.New("invalid_domain")
		}
		name := make([]byte, size[0])
		if _, err := io.ReadFull(reader, name); err != nil {
			return "", err
		}
		host = string(name)
	default:
		return "", errors.New("invalid_address")
	}
	var port [2]byte
	if _, err := io.ReadFull(reader, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port[0])<<8|int(port[1]))), nil
}

func encodeSOCKSAddress(address string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("invalid_port")
	}
	ip := net.ParseIP(host)
	result := make([]byte, 0, 19)
	if ipv4 := ip.To4(); ipv4 != nil {
		result = append(result, 1)
		result = append(result, ipv4...)
	} else if ipv6 := ip.To16(); ipv6 != nil {
		result = append(result, 4)
		result = append(result, ipv6...)
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("invalid_host")
		}
		result = append(result, 3, byte(len(host)))
		result = append(result, host...)
	}
	return append(result, byte(port>>8), byte(port)), nil
}

func (fixture *socksFixture) serve(conn net.Conn) {
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	var hello [2]byte
	if _, err := io.ReadFull(conn, hello[:]); err != nil || hello[0] != 5 || hello[1] == 0 {
		return
	}
	methods := make([]byte, hello[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}
	var request [4]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil || request[0] != 5 || request[2] != 0 {
		return
	}
	target, err := readSOCKSAddress(conn, request[3])
	if err != nil {
		return
	}
	if request[1] == 3 {
		fixture.serveUDP(conn)
		return
	}
	if request[1] != 1 {
		return
	}
	remote, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil {
		conn.Write([]byte{5, 4, 0, 1, 127, 0, 0, 1, 0, 0})
		return
	}
	defer remote.Close()
	fixture.mu.Lock()
	fixture.tcpTargets = append(fixture.tcpTargets, target)
	fixture.mu.Unlock()
	if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	conn.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() {
		io.Copy(remote, conn)
		if tcp, ok := remote.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
		close(done)
	}()
	io.Copy(conn, remote)
	if tcp, ok := conn.(*net.TCPConn); ok {
		tcp.CloseWrite()
	}
	<-done
}

func (fixture *socksFixture) serveUDP(conn net.Conn) {
	local, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return
	}
	defer local.Close()
	encoded, err := encodeSOCKSAddress(local.LocalAddr().String())
	if err != nil {
		return
	}
	if _, err := conn.Write(append([]byte{5, 0, 0}, encoded...)); err != nil {
		return
	}
	conn.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() {
		io.Copy(io.Discard, conn)
		local.Close()
		close(done)
	}()
	defer func() { conn.Close(); <-done }()
	buffer := make([]byte, 65535)
	var client *net.UDPAddr
	for {
		n, from, err := local.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		if client == nil || from.IP.Equal(client.IP) && from.Port == client.Port {
			if n < 4 || buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0 {
				continue
			}
			reader := bytes.NewReader(buffer[4:n])
			target, err := readSOCKSAddress(reader, buffer[3])
			if err != nil {
				continue
			}
			remote, err := net.ResolveUDPAddr("udp", target)
			if err != nil {
				continue
			}
			client = &net.UDPAddr{IP: append(net.IP(nil), from.IP...), Port: from.Port}
			fixture.mu.Lock()
			fixture.udpTargets = append(fixture.udpTargets, target)
			fixture.mu.Unlock()
			local.WriteToUDP(buffer[n-reader.Len():n], remote)
			continue
		}
		encoded, err := encodeSOCKSAddress(from.String())
		if err != nil {
			continue
		}
		packet := append([]byte{0, 0, 0}, encoded...)
		packet = append(packet, buffer[:n]...)
		local.WriteToUDP(packet, client)
	}
}

func (fixture *socksFixture) countTCP(target string) int {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	count := 0
	for _, current := range fixture.tcpTargets {
		if current == target {
			count++
		}
	}
	return count
}

func (fixture *socksFixture) countUDP(target string) int {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	count := 0
	for _, current := range fixture.udpTargets {
		if current == target {
			count++
		}
	}
	return count
}

type dnsFixture struct {
	server *dns.Server
	count  int
	mu     sync.Mutex
}

func newDNSFixture() (*dnsFixture, string) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	must(err)
	fixture := &dnsFixture{}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(writer dns.ResponseWriter, request *dns.Msg) {
		fixture.mu.Lock()
		fixture.count++
		fixture.mu.Unlock()
		response := new(dns.Msg)
		response.SetReply(request)
		for _, question := range request.Question {
			if strings.EqualFold(question.Name, "gateway.test.") && question.Qtype == dns.TypeA {
				response.Answer = append(response.Answer, &dns.A{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("127.0.0.1")})
			}
		}
		writer.WriteMsg(response)
	})
	fixture.server = &dns.Server{Listener: listener, Handler: mux}
	go fixture.server.ActivateAndServe()
	return fixture, listener.Addr().String()
}

type frame struct {
	Version        int             `json:"v"`
	ID             uint64          `json:"id"`
	Event          string          `json:"event"`
	Result         json.RawMessage `json:"result"`
	Error          *controlError   `json:"error"`
	PathID         string          `json:"pathId"`
	Generation     uint64          `json:"generation"`
	Remote         string          `json:"remote"`
	PublicEndpoint string          `json:"publicEndpoint"`
	RelayHost      string          `json:"relayHost"`
	RelayPort      int             `json:"relayPort"`
	RelayToken     string          `json:"relayToken"`
	Reason         string          `json:"reason"`
	FieldCount     int             `json:"-"`
}

type controlError struct {
	Code string `json:"code"`
}

type child struct {
	command *exec.Cmd
	stdin   io.WriteCloser
	mu      sync.Mutex
	next    uint64
	pending map[uint64]chan frame
	events  chan frame
	done    chan struct{}
	stderr  bytes.Buffer
}

func startChild(executable string) *child {
	command := exec.Command(executable, "--stdio")
	stdin, err := command.StdinPipe()
	must(err)
	stdout, err := command.StdoutPipe()
	must(err)
	child := &child{command: command, stdin: stdin, next: 0, pending: make(map[uint64]chan frame), events: make(chan frame, 32), done: make(chan struct{})}
	command.Stderr = &child.stderr
	must(command.Start())
	go child.read(stdout)
	return child
}

func (child *child) read(stdout io.Reader) {
	defer close(child.done)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), 65536)
	for scanner.Scan() {
		var value frame
		var fields map[string]json.RawMessage
		if json.Unmarshal(scanner.Bytes(), &value) != nil || json.Unmarshal(scanner.Bytes(), &fields) != nil || value.Version != parentProtocol {
			return
		}
		value.FieldCount = len(fields)
		if value.ID == 0 {
			child.events <- value
			continue
		}
		child.mu.Lock()
		reply := child.pending[value.ID]
		delete(child.pending, value.ID)
		child.mu.Unlock()
		if reply == nil {
			return
		}
		reply <- value
		close(reply)
	}
}

func (child *child) request(method string, fields map[string]any) frame {
	return child.requestVersion(parentProtocol, method, fields)
}

func (child *child) requestVersion(version int, method string, fields map[string]any) frame {
	child.mu.Lock()
	child.next++
	id := child.next
	reply := make(chan frame, 1)
	child.pending[id] = reply
	child.mu.Unlock()
	request := map[string]any{"v": version, "id": id, "method": method}
	for key, value := range fields {
		request[key] = value
	}
	data, err := json.Marshal(request)
	must(err)
	_, err = child.stdin.Write(append(data, '\n'))
	must(err)
	select {
	case response := <-reply:
		return response
	case <-time.After(8 * time.Second):
		panic("qbutt-net response timeout")
	}
}

func (child *child) event() frame {
	select {
	case event := <-child.events:
		return event
	case <-time.After(8 * time.Second):
		panic("qbutt-net event timeout")
	}
}

func (child *child) expectNoEvent(wait time.Duration) {
	select {
	case event := <-child.events:
		panic("unexpected qbutt-net event: " + event.Event)
	case <-time.After(wait):
	}
}

type gatewayEndpoint struct {
	PathID           string `json:"pathId"`
	Generation       uint64 `json:"generation"`
	PublicEndpoint   string `json:"publicEndpoint"`
	TCP              bool   `json:"tcp"`
	UDP              bool   `json:"udp"`
	ExpiresUnixMilli int64  `json:"expiresUnixMilli"`
	RelayHost        string `json:"relayHost"`
	RelayPort        int    `json:"relayPort"`
}

type pathEndpoint struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	SocksUsername string `json:"socksUsername"`
	SocksPassword string `json:"socksPassword"`
}

type wireSnapshot struct {
	RelayDownloadBytes     uint64 `json:"relayDownloadBytes"`
	RelayUploadBytes       uint64 `json:"relayUploadBytes"`
	CarrierDownloadBytes   uint64 `json:"carrierDownloadBytes"`
	CarrierUploadBytes     uint64 `json:"carrierUploadBytes"`
	CarrierDownloadPackets uint64 `json:"carrierDownloadPackets"`
	CarrierUploadPackets   uint64 `json:"carrierUploadPackets"`
	RelayDownloadCopies    uint64 `json:"relayDownloadCopies"`
}

type pathStatus struct {
	PathID     string       `json:"pathId"`
	Generation uint64       `json:"generation"`
	Wire       wireSnapshot `json:"wire"`
}

func decodeStatus(response frame) []pathStatus {
	check(response.Error == nil, "status failed: "+errorCode(response))
	var resultFields map[string]json.RawMessage
	must(json.Unmarshal(response.Result, &resultFields))
	check(len(resultFields) == 1 && resultFields["paths"] != nil, "status result fields mismatch")
	var rawPaths []json.RawMessage
	must(json.Unmarshal(resultFields["paths"], &rawPaths))
	paths := make([]pathStatus, len(rawPaths))
	for index, rawPath := range rawPaths {
		var fields map[string]json.RawMessage
		must(json.Unmarshal(rawPath, &fields))
		check(len(fields) == 4 && fields["pathId"] != nil && fields["generation"] != nil && fields["wire"] != nil && fields["transport"] != nil, "path status fields mismatch")
		var transport map[string]string
		must(json.Unmarshal(fields["transport"], &transport))
		check(len(transport) == 2 && transport["state"] == "disabled" && transport["recommended"] == "", "unexpected transport health without reserves")
		var wireFields map[string]json.RawMessage
		must(json.Unmarshal(fields["wire"], &wireFields))
		for _, name := range []string{"relayDownloadBytes", "relayUploadBytes", "carrierDownloadBytes", "carrierUploadBytes", "carrierDownloadPackets", "carrierUploadPackets", "relayDownloadCopies"} {
			check(wireFields[name] != nil, "wire status missing "+name)
		}
		check(len(wireFields) == 7, "wire status has unknown fields")
		must(json.Unmarshal(rawPath, &paths[index]))
	}
	return paths
}

func pathWire(child *child, pathID string, generation uint64) wireSnapshot {
	paths := decodeStatus(child.request("status", nil))
	for _, path := range paths {
		if path.PathID == pathID {
			check(path.Generation == generation, "status generation mismatch")
			return path.Wire
		}
	}
	panic("status path missing")
}

func checkMonotonic(before, after wireSnapshot) {
	check(after.RelayDownloadBytes >= before.RelayDownloadBytes && after.RelayUploadBytes >= before.RelayUploadBytes &&
		after.CarrierDownloadBytes >= before.CarrierDownloadBytes && after.CarrierUploadBytes >= before.CarrierUploadBytes &&
		after.CarrierDownloadPackets >= before.CarrierDownloadPackets && after.CarrierUploadPackets >= before.CarrierUploadPackets &&
		after.RelayDownloadCopies >= before.RelayDownloadCopies, "wire counters decreased")
}

func checkGatewayClosedEvent(event frame, pathID string, generation uint64) {
	check(event.FieldCount == 6 && event.ID == 0 && event.Event == "gatewayClosed" && event.PathID == pathID &&
		event.Generation == generation && event.Reason == "gateway_closed", "gatewayClosed event mismatch")
}

func checkIncomingEvent(event frame, endpoint gatewayEndpoint) []byte {
	check(event.FieldCount == 10 && event.ID == 0 && event.Event == "incomingTcp" && event.PathID == endpoint.PathID &&
		event.Generation == endpoint.Generation && event.PublicEndpoint == endpoint.PublicEndpoint &&
		event.RelayHost == endpoint.RelayHost && event.RelayPort == endpoint.RelayPort, "incoming event mismatch")
	if _, err := net.ResolveTCPAddr("tcp", event.Remote); err != nil {
		panic("incoming event remote is not numeric")
	}
	token, err := hex.DecodeString(event.RelayToken)
	must(err)
	check(len(token) == 32 && event.RelayToken == strings.ToLower(event.RelayToken), "invalid relay token")
	return token
}

func decodeEndpoint(response frame) gatewayEndpoint {
	check(response.Error == nil, "gateway operation failed: "+errorCode(response))
	var fields map[string]json.RawMessage
	must(json.Unmarshal(response.Result, &fields))
	for _, name := range []string{"pathId", "generation", "publicEndpoint", "tcp", "udp", "expiresUnixMilli", "relayHost", "relayPort"} {
		check(fields[name] != nil, "gateway endpoint missing "+name)
	}
	check(len(fields) == 8, "gateway endpoint has unknown fields")
	var endpoint gatewayEndpoint
	must(json.Unmarshal(response.Result, &endpoint))
	return endpoint
}

func decodePathEndpoint(response frame) pathEndpoint {
	check(response.Error == nil, "path operation failed: "+errorCode(response))
	var endpoint pathEndpoint
	must(json.Unmarshal(response.Result, &endpoint))
	check(endpoint.Host == "127.0.0.1" && endpoint.Port > 0 && endpoint.SocksUsername != "" && endpoint.SocksPassword != "", "path endpoint mismatch")
	return endpoint
}

func requestAuthenticatedUDP(endpoint pathEndpoint) (net.Conn, byte, string) {
	control, err := net.DialTimeout("tcp", net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port)), time.Second)
	must(err)
	control.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = control.Write([]byte{5, 1, 2})
	must(err)
	var reply [2]byte
	_, err = io.ReadFull(control, reply[:])
	must(err)
	check(reply == [2]byte{5, 2}, "SOCKS authentication method mismatch")
	check(len(endpoint.SocksUsername) < 256 && len(endpoint.SocksPassword) < 256, "SOCKS credentials too long")
	auth := append([]byte{1, byte(len(endpoint.SocksUsername))}, endpoint.SocksUsername...)
	auth = append(auth, byte(len(endpoint.SocksPassword)))
	auth = append(auth, endpoint.SocksPassword...)
	_, err = control.Write(auth)
	must(err)
	_, err = io.ReadFull(control, reply[:])
	must(err)
	check(reply == [2]byte{1, 0}, "SOCKS authentication failed")
	_, err = control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	must(err)
	var header [4]byte
	_, err = io.ReadFull(control, header[:])
	must(err)
	check(header[0] == 5 && header[2] == 0, "invalid SOCKS UDP associate response")
	relayText, err := readSOCKSAddress(control, header[3])
	must(err)
	return control, header[1], relayText
}

func openAuthenticatedUDP(endpoint pathEndpoint) (net.Conn, *net.UDPConn, *net.UDPAddr) {
	control, status, relayText := requestAuthenticatedUDP(endpoint)
	check(status == 0, "SOCKS UDP associate failed")
	relay, err := net.ResolveUDPAddr("udp", relayText)
	must(err)
	local, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(err)
	control.SetDeadline(time.Time{})
	return control, local, relay
}

func expectUDPAssociateRejected(endpoint pathEndpoint) {
	control, status, _ := requestAuthenticatedUDP(endpoint)
	control.Close()
	check(status == 2, "SOCKS UDP association was not rejected")
}

func expectBadAuthentication(endpoint pathEndpoint) {
	control, err := net.DialTimeout("tcp", net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port)), time.Second)
	must(err)
	defer control.Close()
	control.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = control.Write([]byte{5, 1, 2})
	must(err)
	var reply [2]byte
	_, err = io.ReadFull(control, reply[:])
	must(err)
	check(reply == [2]byte{5, 2}, "SOCKS authentication method mismatch")
	auth := append([]byte{1, byte(len(endpoint.SocksUsername))}, endpoint.SocksUsername...)
	auth = append(auth, byte(len("wrong-password")))
	auth = append(auth, "wrong-password"...)
	_, err = control.Write(auth)
	must(err)
	_, err = io.ReadFull(control, reply[:])
	must(err)
	check(reply == [2]byte{1, 1}, "bad SOCKS authentication admitted")
}

func sendSOCKSDatagram(local *net.UDPConn, relay *net.UDPAddr, target string, payload []byte) {
	must(writeSOCKSDatagram(local, relay, target, payload))
}

func writeSOCKSDatagram(local *net.UDPConn, relay *net.UDPAddr, target string, payload []byte) error {
	encoded, err := encodeSOCKSAddress(target)
	if err != nil {
		return err
	}
	packet := append([]byte{0, 0, 0}, encoded...)
	packet = append(packet, payload...)
	_, err = local.WriteToUDP(packet, relay)
	return err
}

func readSOCKSDatagram(local *net.UDPConn) (string, []byte) {
	local.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 65535)
	n, _, err := local.ReadFromUDP(buffer)
	must(err)
	check(n >= 4 && buffer[0] == 0 && buffer[1] == 0 && buffer[2] == 0, "invalid SOCKS UDP response")
	reader := bytes.NewReader(buffer[4:n])
	source, err := readSOCKSAddress(reader, buffer[3])
	must(err)
	return source, append([]byte(nil), buffer[n-reader.Len():n]...)
}

func errorCode(response frame) string {
	if response.Error == nil {
		return ""
	}
	return response.Error.Code
}

func expectEOF(conn net.Conn) {
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var buffer [1024]byte
	_, err := conn.Read(buffer[:])
	check(err != nil, "connection remained open")
	if timeout, ok := err.(net.Error); ok {
		check(!timeout.Timeout(), "connection remained open until timeout")
	}
}

func expectRefused(address string) {
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err != nil {
			return
		}
		conn.Close()
		if time.Now().After(deadline) {
			panic("listener remained reachable")
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func loopbackInterface() string {
	interfaces, err := net.Interfaces()
	must(err)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 && iface.Flags&net.FlagUp != 0 {
			return iface.Name
		}
	}
	panic("loopback interface unavailable")
}

func run() (evidence map[string]any) {
	check(len(os.Args) == 4, "qbutt-net, gateway and fresh output directory required")
	root, err := filepath.Abs(os.Args[3])
	must(err)
	check(strings.HasPrefix(filepath.Base(root), "qbutt-gateway-client-"), "generated output directory required")
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
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "qbutt-gateway-client-fixture-CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	must(err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	serverPair := issue(ca, caKey, true)
	clientPair := issue(ca, caKey, false)
	clientFingerprint := sha256.Sum256(clientPair.der)
	paths := map[string]string{"ca": filepath.Join(root, "ca.pem"), "server": filepath.Join(root, "server.pem"),
		"serverKey": filepath.Join(root, "server-key.pem"), "client": filepath.Join(root, "client.pem"),
		"clientKey": filepath.Join(root, "client-key.pem")}
	for name, data := range map[string][]byte{paths["ca"]: caPEM, paths["server"]: serverPair.certificate,
		paths["serverKey"]: serverPair.key, paths["client"]: clientPair.certificate, paths["clientKey"]: clientPair.key} {
		must(os.WriteFile(name, data, 0600))
	}

	gatewayConfig := map[string]any{"controlAddress": "127.0.0.1:0", "datagramAddress": "127.0.0.1:0", "listenerIP": "127.0.0.1",
		"advertiseIP": "127.0.0.1", "allowedPorts": []int{0}, "maxClients": 1, "maxLeases": 2, "maxTCPPerLease": 8,
		"maxTCP": 16, "maxTTLSeconds": 20, "maxUDPPacketsPerSecond": 1024, "maxUDPBytesPerSecond": 128 * 1024 * 1024,
		"clientCertificateSHA256": hex.EncodeToString(clientFingerprint[:]), "certificate": paths["server"],
		"privateKey": paths["serverKey"], "clientCA": paths["ca"]}
	configBytes, _ := json.Marshal(gatewayConfig)
	gatewayConfigPath := filepath.Join(root, "gateway.json")
	must(os.WriteFile(gatewayConfigPath, configBytes, 0600))
	gatewayCommand := exec.Command(os.Args[2], "--config", gatewayConfigPath, "--stdio")
	gatewayStdout, err := gatewayCommand.StdoutPipe()
	must(err)
	gatewayStdin, err := gatewayCommand.StdinPipe()
	must(err)
	var gatewayErrors bytes.Buffer
	gatewayCommand.Stderr = &gatewayErrors
	must(gatewayCommand.Start())
	gatewayDone := make(chan error, 1)
	go func() { gatewayDone <- gatewayCommand.Wait() }()
	gatewayStopped := false
	defer func() {
		if !gatewayStopped {
			gatewayStdin.Close()
			select {
			case err := <-gatewayDone:
				must(err)
			case <-time.After(5 * time.Second):
				gatewayCommand.Process.Kill()
				<-gatewayDone
				panic("gateway shutdown timeout")
			}
		}
	}()
	var ready struct {
		Ready     bool   `json:"ready"`
		Control   string `json:"control"`
		Datagrams string `json:"datagrams"`
	}
	must(json.NewDecoder(gatewayStdout).Decode(&ready))
	check(ready.Ready, "gateway not ready")

	proxy := newSOCKSFixture()
	defer proxy.close()
	dnsFixture, dnsAddress := newDNSFixture()
	defer dnsFixture.server.Shutdown()
	_, proxyPort, _ := net.SplitHostPort(proxy.listener.Addr().String())
	profilePath := filepath.Join(root, "profile.yaml")
	must(os.WriteFile(profilePath, []byte("proxies:\n  - name: selected\n    type: socks5\n    server: 127.0.0.1\n    port: "+proxyPort+"\n    udp: true\n"), 0600))

	child := startChild(os.Args[1])
	defer func() {
		if child.command.ProcessState == nil {
			child.stdin.Close()
			select {
			case <-child.done:
			case <-time.After(5 * time.Second):
				child.command.Process.Kill()
				<-child.done
			}
			must(child.command.Wait())
		}
		check(child.stderr.Len() == 0, "qbutt-net emitted stderr")
	}()
	check(errorCode(child.requestVersion(4, "hello", nil)) == "protocol_mismatch", "legacy v4 handshake admitted")
	check(errorCode(child.requestVersion(5, "hello", nil)) == "protocol_mismatch", "legacy v5 handshake admitted")
	evidence["legacyProtocolRejected"] = true
	hello := child.request("hello", nil)
	check(hello.Error == nil, "v6 hello failed")
	listed := child.request("list", map[string]any{"configPath": profilePath, "proxyName": "selected"})
	check(listed.Error == nil, "selected list failed")
	var identities struct {
		Proxies []struct {
			ConfiguredServerID string `json:"configuredServerId"`
		} `json:"proxies"`
	}
	must(json.Unmarshal(listed.Result, &identities))
	check(len(identities.Proxies) == 1 && len(identities.Proxies[0].ConfiguredServerID) == 64, "selected identity missing")
	configuredServerID := identities.Proxies[0].ConfiguredServerID
	pathFields := map[string]any{"configPath": profilePath, "proxyName": "selected", "configuredServerId": configuredServerID, "pathId": "gateway-path", "generation": 1,
		"interfaceName": loopbackInterface(), "dns": map[string]any{"server": dnsAddress, "bootstrapServer": dnsAddress, "family": "ipv4"}}
	pathEndpoint := decodePathEndpoint(child.request("open", pathFields))
	check(pathWire(child, "gateway-path", 1) == (wireSnapshot{}), "new path counters were not zero")
	baseGateway := map[string]any{"controlAddress": net.JoinHostPort("gateway.test", strings.Split(ready.Control, ":")[1]),
		"datagramAddress": ready.Datagrams, "serverName": "127.0.0.1", "caPath": paths["ca"], "certificatePath": paths["client"],
		"privateKeyPath": paths["clientKey"], "port": 0, "tcp": true, "udp": true, "ttlSeconds": 10}
	check(errorCode(child.request("gateway.open", map[string]any{"pathId": "missing", "generation": 1, "gateway": baseGateway})) == "path_not_found", "missing path admitted")
	check(errorCode(child.request("gateway.open", map[string]any{"pathId": "gateway-path", "generation": 2, "gateway": baseGateway})) == "generation_mismatch", "wrong generation admitted")
	preControl, preLocal, preRelay := openAuthenticatedUDP(pathEndpoint)
	defer preControl.Close()
	defer preLocal.Close()
	directPeer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(err)
	defer directPeer.Close()
	sendSOCKSDatagram(preLocal, preRelay, directPeer.LocalAddr().String(), []byte("direct-before-gateway"))
	directPeer.SetReadDeadline(time.Now().Add(3 * time.Second))
	var directBuffer [64]byte
	directSize, _, err := directPeer.ReadFromUDP(directBuffer[:])
	must(err)
	check(string(directBuffer[:directSize]) == "direct-before-gateway", "ordinary UDP fixture path failed")
	directCount := proxy.countUDP(directPeer.LocalAddr().String())
	check(directCount == 1, "ordinary UDP fixture path was not selected")
	endpoint := decodeEndpoint(child.request("gateway.open", map[string]any{"pathId": "gateway-path", "generation": 1, "gateway": baseGateway}))
	expectEOF(preControl)
	_ = writeSOCKSDatagram(preLocal, preRelay, directPeer.LocalAddr().String(), []byte("must-not-fall-open"))
	time.Sleep(200 * time.Millisecond)
	check(proxy.countUDP(directPeer.LocalAddr().String()) == directCount, "pre-existing UDP association survived gateway activation")
	check(endpoint.PathID == "gateway-path" && endpoint.Generation == 1 && endpoint.TCP && endpoint.UDP && endpoint.RelayHost == "127.0.0.1" && endpoint.RelayPort > 0, "gateway endpoint mismatch")
	check(errorCode(child.request("gateway.open", map[string]any{"pathId": "gateway-path", "generation": 1, "gateway": baseGateway})) == "gateway_exists", "duplicate gateway admitted")
	immediateRenewal := decodeEndpoint(child.request("gateway.renew", map[string]any{"pathId": "gateway-path", "generation": 1}))
	check(immediateRenewal.ExpiresUnixMilli > endpoint.ExpiresUnixMilli && immediateRenewal.PublicEndpoint == endpoint.PublicEndpoint &&
		immediateRenewal.RelayHost == endpoint.RelayHost && immediateRenewal.RelayPort == endpoint.RelayPort, "immediate renew did not advance expiry")
	type udpFixtureAssociation struct {
		control net.Conn
		local   *net.UDPConn
		relay   *net.UDPAddr
	}
	udpAssociations := make([]udpFixtureAssociation, 4)
	for index := range udpAssociations {
		udpAssociations[index].control, udpAssociations[index].local, udpAssociations[index].relay = openAuthenticatedUDP(pathEndpoint)
		defer udpAssociations[index].control.Close()
		defer udpAssociations[index].local.Close()
	}
	expectUDPAssociateRejected(pathEndpoint)
	expectBadAuthentication(pathEndpoint)
	publicUDP, err := net.ResolveUDPAddr("udp", endpoint.PublicEndpoint)
	must(err)
	peerUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(err)
	defer peerUDP.Close()
	// Each opaque association learns its authenticated local endpoint. The
	// gateway intentionally drops these until a public peer is observed.
	for index, association := range udpAssociations {
		sendSOCKSDatagram(association.local, association.relay, "127.0.0.1:9", []byte(fmt.Sprintf("association-prime-%d", index)))
	}
	beforeInbound := pathWire(child, "gateway-path", 1)
	inboundUDP := bytes.Repeat([]byte{0xa5}, effectiveSOCKSPayload)
	_, err = peerUDP.WriteToUDP(inboundUDP, publicUDP)
	must(err)
	for _, association := range udpAssociations {
		udpSource, receivedUDP := readSOCKSDatagram(association.local)
		check(udpSource == peerUDP.LocalAddr().String() && bytes.Equal(receivedUDP, inboundUDP), "public UDP fanout mismatch")
	}
	afterInbound := pathWire(child, "gateway-path", 1)
	checkMonotonic(beforeInbound, afterInbound)
	check(afterInbound.RelayDownloadBytes-beforeInbound.RelayDownloadBytes == uint64(len(inboundUDP)*len(udpAssociations)) &&
		afterInbound.RelayDownloadCopies-beforeInbound.RelayDownloadCopies == uint64(len(udpAssociations)), "UDP fanout counters mismatch")
	check(afterInbound.CarrierDownloadBytes > beforeInbound.CarrierDownloadBytes &&
		afterInbound.CarrierDownloadPackets > beforeInbound.CarrierDownloadPackets, "inbound carrier counters did not advance")
	outboundPayloads := make([][]byte, len(udpAssociations))
	start := make(chan struct{})
	sendErrors := make(chan error, len(udpAssociations))
	outboundBytes := 0
	for index, association := range udpAssociations {
		size := 1200 + index
		if index == 0 {
			size = effectiveSOCKSPayload
		}
		outboundPayloads[index] = bytes.Repeat([]byte{byte(0x50 + index)}, size)
		outboundBytes += len(outboundPayloads[index])
		go func(association udpFixtureAssociation, payload []byte) {
			<-start
			sendErrors <- writeSOCKSDatagram(association.local, association.relay, peerUDP.LocalAddr().String(), payload)
		}(association, outboundPayloads[index])
	}
	close(start)
	for range udpAssociations {
		must(<-sendErrors)
	}
	peerUDP.SetReadDeadline(time.Now().Add(5 * time.Second))
	udpBuffer := make([]byte, 65535)
	receivedOutbound := make(map[string]bool, len(outboundPayloads))
	for range outboundPayloads {
		udpSize, udpFrom, err := peerUDP.ReadFromUDP(udpBuffer)
		must(err)
		check(udpFrom.String() == publicUDP.String(), "public UDP source mismatch")
		receivedOutbound[string(udpBuffer[:udpSize])] = true
	}
	for _, payload := range outboundPayloads {
		check(receivedOutbound[string(payload)], "concurrent outbound UDP payload missing")
	}
	afterOutbound := pathWire(child, "gateway-path", 1)
	checkMonotonic(afterInbound, afterOutbound)
	check(afterOutbound.RelayUploadBytes-afterInbound.RelayUploadBytes == uint64(outboundBytes), "outbound relay counter mismatch")
	check(afterOutbound.CarrierUploadBytes > afterInbound.CarrierUploadBytes &&
		afterOutbound.CarrierUploadPackets > afterInbound.CarrierUploadPackets, "outbound carrier counters did not advance")
	sendSOCKSDatagram(udpAssociations[0].local, udpAssociations[0].relay, peerUDP.LocalAddr().String(), bytes.Repeat([]byte{0xff}, effectiveSOCKSPayload+1))
	expectEOF(udpAssociations[0].control)
	peerUDP.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, _, err = peerUDP.ReadFromUDP(udpBuffer)
	check(err != nil, "oversized SOCKS payload reached public UDP endpoint")
	udpAssociations[0].local.Close()
	udpAssociations[0].control, udpAssociations[0].local, udpAssociations[0].relay = openAuthenticatedUDP(pathEndpoint)
	defer udpAssociations[0].control.Close()
	defer udpAssociations[0].local.Close()
	sendSOCKSDatagram(udpAssociations[0].local, udpAssociations[0].relay, "127.0.0.1:9", []byte("replacement-prime"))
	beforeTCP := pathWire(child, "gateway-path", 1)
	peer, err := net.DialTimeout("tcp", endpoint.PublicEndpoint, 2*time.Second)
	must(err)
	defer peer.Close()
	event := child.event()
	token := checkIncomingEvent(event, endpoint)
	remote, err := net.ResolveTCPAddr("tcp", event.Remote)
	must(err)
	check(remote.String() == peer.LocalAddr().String(), "original peer address lost")
	badRelay, err := net.DialTimeout("tcp", net.JoinHostPort(endpoint.RelayHost, strconv.Itoa(endpoint.RelayPort)), time.Second)
	must(err)
	badPrelude := append([]byte("QBIN\x01"), bytes.Repeat([]byte{0xff}, 32)...)
	_, err = badRelay.Write(badPrelude)
	must(err)
	expectEOF(badRelay)
	badRelay.Close()
	wrongVersion, err := net.DialTimeout("tcp", net.JoinHostPort(endpoint.RelayHost, strconv.Itoa(endpoint.RelayPort)), time.Second)
	must(err)
	_, err = wrongVersion.Write(append([]byte("QBIN\x02"), token...))
	must(err)
	expectEOF(wrongVersion)
	wrongVersion.Close()
	relay, err := net.DialTimeout("tcp", net.JoinHostPort(endpoint.RelayHost, strconv.Itoa(endpoint.RelayPort)), time.Second)
	must(err)
	defer relay.Close()
	_, err = relay.Write(append([]byte("QBIN\x01"), token...))
	must(err)
	payload := bytes.Repeat([]byte("gateway-client-through-selected-path\x00"), 4096)
	_, err = peer.Write(payload)
	must(err)
	must(peer.(*net.TCPConn).CloseWrite())
	relay.SetReadDeadline(time.Now().Add(4 * time.Second))
	received := make([]byte, len(payload))
	_, err = io.ReadFull(relay, received)
	must(err)
	check(bytes.Equal(received, payload), "inbound payload mismatch")
	expectEOF(relay)
	replyPayload := bytes.Repeat([]byte("return-stream\x00"), 2048)
	_, err = relay.Write(replyPayload)
	must(err)
	must(relay.(*net.TCPConn).CloseWrite())
	peer.SetReadDeadline(time.Now().Add(4 * time.Second))
	replied := make([]byte, len(replyPayload))
	_, err = io.ReadFull(peer, replied)
	must(err)
	check(bytes.Equal(replied, replyPayload), "return payload mismatch")
	expectEOF(peer)
	afterTCP := pathWire(child, "gateway-path", 1)
	checkMonotonic(beforeTCP, afterTCP)
	check(afterTCP.RelayDownloadBytes-beforeTCP.RelayDownloadBytes == uint64(len(payload)) &&
		afterTCP.RelayUploadBytes-beforeTCP.RelayUploadBytes == uint64(len(replyPayload)), "TCP relay counters mismatch")
	check(afterTCP.CarrierDownloadBytes > beforeTCP.CarrierDownloadBytes && afterTCP.CarrierUploadBytes > beforeTCP.CarrierUploadBytes,
		"TCP carrier counters did not advance")
	reused, err := net.DialTimeout("tcp", net.JoinHostPort(endpoint.RelayHost, strconv.Itoa(endpoint.RelayPort)), time.Second)
	must(err)
	_, err = reused.Write(append([]byte("QBIN\x01"), token...))
	must(err)
	expectEOF(reused)
	reused.Close()
	renewed := decodeEndpoint(child.request("gateway.renew", map[string]any{"pathId": "gateway-path", "generation": 1}))
	check(renewed.ExpiresUnixMilli > immediateRenewal.ExpiresUnixMilli && renewed.PublicEndpoint == endpoint.PublicEndpoint &&
		renewed.TCP == endpoint.TCP && renewed.UDP == endpoint.UDP && renewed.RelayHost == endpoint.RelayHost && renewed.RelayPort == endpoint.RelayPort,
		"renew changed lease or relay")
	check(proxy.countTCP(dnsAddress) >= 1 && proxy.countTCP(ready.Control) >= 2 && proxy.countUDP(ready.Datagrams) > 0,
		"gateway DNS/control/work/datagrams bypassed selected proxy fixture")
	evidence["tcpVerifiedBytes"] = len(payload) + len(replyPayload)
	evidence["udpVerifiedBytes"] = len(inboundUDP) + outboundBytes
	evidence["selectedProxyGatewayDials"] = proxy.countTCP(ready.Control)
	evidence["selectedProxyGatewayDatagrams"] = proxy.countUDP(ready.Datagrams)
	evidence["selectedProxyDNSDials"] = proxy.countTCP(dnsAddress)
	evidence["stableAuthenticatedRelay"] = true
	closed := child.request("gateway.close", map[string]any{"pathId": "gateway-path", "generation": 1})
	check(closed.Error == nil && closed.FieldCount == 3 && string(closed.Result) == "{}", "gateway close result mismatch")
	child.expectNoEvent(300 * time.Millisecond)
	for _, association := range udpAssociations {
		expectEOF(association.control)
	}
	expectEOF(peer)
	_, err = net.DialTimeout("tcp", net.JoinHostPort(endpoint.RelayHost, strconv.Itoa(endpoint.RelayPort)), 300*time.Millisecond)
	check(err != nil, "relay listener survived close")
	check(errorCode(child.request("gateway.open", map[string]any{"pathId": "gateway-path", "generation": 1, "gateway": baseGateway})) == "gateway_exists",
		"same-generation gateway replacement admitted")

	check(child.request("close", map[string]any{"pathId": "gateway-path", "generation": 1}).Error == nil, "first path close failed")
	child.expectNoEvent(200 * time.Millisecond)
	check(len(decodeStatus(child.request("status", nil))) == 0, "closed path remained in status")
	pathFields["generation"] = 2
	secondPath := decodePathEndpoint(child.request("open", pathFields))
	check(pathWire(child, "gateway-path", 2) == (wireSnapshot{}), "next generation inherited counters")
	tcpOnlyGateway := make(map[string]any)
	for key, value := range baseGateway {
		tcpOnlyGateway[key] = value
	}
	tcpOnlyGateway["udp"] = false
	tcpOnlyGateway["datagramAddress"] = ""
	reconnected := decodeEndpoint(child.request("gateway.open", map[string]any{"pathId": "gateway-path", "generation": 2, "gateway": tcpOnlyGateway}))
	check(reconnected.PublicEndpoint != "" && reconnected.TCP && !reconnected.UDP, "next-generation TCP-only reconnect failed")
	tcpOnlyControl, tcpOnlyLocal, tcpOnlyRelay := openAuthenticatedUDP(secondPath)
	directCount = proxy.countUDP(directPeer.LocalAddr().String())
	sendSOCKSDatagram(tcpOnlyLocal, tcpOnlyRelay, directPeer.LocalAddr().String(), []byte("direct-with-tcp-only-gateway"))
	directPeer.SetReadDeadline(time.Now().Add(3 * time.Second))
	directSize, _, err = directPeer.ReadFromUDP(directBuffer[:])
	must(err)
	check(string(directBuffer[:directSize]) == "direct-with-tcp-only-gateway" && proxy.countUDP(directPeer.LocalAddr().String()) == directCount+1,
		"TCP-only gateway changed ordinary UDP")
	tcpOnlyControl.Close()
	tcpOnlyLocal.Close()
	check(child.request("gateway.close", map[string]any{"pathId": "gateway-path", "generation": 2}).Error == nil, "reconnect close failed")
	check(child.request("close", map[string]any{"pathId": "gateway-path", "generation": 2}).Error == nil, "second path close failed")
	child.expectNoEvent(300 * time.Millisecond)
	expiringGateway := make(map[string]any)
	for key, value := range baseGateway {
		expiringGateway[key] = value
	}
	expiringGateway["ttlSeconds"] = 1
	pathFields["generation"] = 3
	decodePathEndpoint(child.request("open", pathFields))
	decodeEndpoint(child.request("gateway.open", map[string]any{"pathId": "gateway-path", "generation": 3, "gateway": expiringGateway}))
	check(errorCode(child.request("gateway.close", map[string]any{"pathId": "gateway-path", "generation": 2})) == "generation_mismatch",
		"stale gateway close admitted")
	time.Sleep(1300 * time.Millisecond)
	checkGatewayClosedEvent(child.event(), "gateway-path", 3)
	child.expectNoEvent(300 * time.Millisecond)
	check(errorCode(child.request("gateway.renew", map[string]any{"pathId": "gateway-path", "generation": 3})) == "gateway_not_open", "expired lease remained active")
	evidence["renewCloseReconnectExpiry"] = true
	check(child.request("close", map[string]any{"pathId": "gateway-path", "generation": 3}).Error == nil, "path close failed")
	evidence["pathScopedCleanup"] = true
	pathFields["generation"] = 4
	decodePathEndpoint(child.request("open", pathFields))
	activeCloseEndpoint := decodeEndpoint(child.request("gateway.open", map[string]any{"pathId": "gateway-path", "generation": 4, "gateway": baseGateway}))
	check(child.request("close", map[string]any{"pathId": "gateway-path", "generation": 4}).Error == nil, "active gateway path close failed")
	child.expectNoEvent(300 * time.Millisecond)
	expectRefused(activeCloseEndpoint.PublicEndpoint)
	expectRefused(net.JoinHostPort(activeCloseEndpoint.RelayHost, strconv.Itoa(activeCloseEndpoint.RelayPort)))
	pathFields["generation"] = 5
	decodePathEndpoint(child.request("open", pathFields))
	eofEndpoint := decodeEndpoint(child.request("gateway.open", map[string]any{"pathId": "gateway-path", "generation": 5, "gateway": baseGateway}))
	must(child.stdin.Close())
	select {
	case <-child.done:
	case <-time.After(5 * time.Second):
		panic("qbutt-net did not exit after parent EOF")
	}
	child.expectNoEvent(10 * time.Millisecond)
	must(child.command.Wait())
	expectRefused(eofEndpoint.PublicEndpoint)
	expectRefused(net.JoinHostPort(eofEndpoint.RelayHost, strconv.Itoa(eofEndpoint.RelayPort)))
	evidence["parentEOFCleanup"] = true

	shutdownChild := startChild(os.Args[1])
	check(shutdownChild.request("hello", nil).Error == nil, "shutdown v6 hello failed")
	shutdownPathFields := map[string]any{"configPath": profilePath, "proxyName": "selected", "configuredServerId": configuredServerID, "pathId": "shutdown-path", "generation": 1,
		"interfaceName": loopbackInterface(), "dns": map[string]any{"server": dnsAddress, "bootstrapServer": dnsAddress, "family": "ipv4"}}
	decodePathEndpoint(shutdownChild.request("open", shutdownPathFields))
	shutdownEndpoint := decodeEndpoint(shutdownChild.request("gateway.open", map[string]any{"pathId": "shutdown-path", "generation": 1, "gateway": baseGateway}))
	shutdown := shutdownChild.request("shutdown", nil)
	check(shutdown.Error == nil && shutdown.FieldCount == 3 && string(shutdown.Result) == "{}", "shutdown result mismatch")
	shutdownChild.expectNoEvent(300 * time.Millisecond)
	select {
	case <-shutdownChild.done:
	case <-time.After(5 * time.Second):
		shutdownChild.command.Process.Kill()
		<-shutdownChild.done
		panic("qbutt-net did not exit after shutdown")
	}
	shutdownChild.expectNoEvent(10 * time.Millisecond)
	must(shutdownChild.command.Wait())
	check(shutdownChild.stderr.Len() == 0, "shutdown qbutt-net emitted stderr")
	expectRefused(shutdownEndpoint.PublicEndpoint)
	evidence["explicitCloseSuppressedEvent"] = true

	failureChild := startChild(os.Args[1])
	defer func() {
		if failureChild.command.ProcessState == nil {
			failureChild.stdin.Close()
			select {
			case <-failureChild.done:
			case <-time.After(5 * time.Second):
				failureChild.command.Process.Kill()
				<-failureChild.done
			}
			must(failureChild.command.Wait())
		}
		check(failureChild.stderr.Len() == 0, "failure qbutt-net emitted stderr")
	}()
	check(failureChild.request("hello", nil).Error == nil, "failure v6 hello failed")
	failurePathFields := map[string]any{"configPath": profilePath, "proxyName": "selected", "configuredServerId": configuredServerID, "pathId": "failure-path", "generation": 1,
		"interfaceName": loopbackInterface(), "dns": map[string]any{"server": dnsAddress, "bootstrapServer": dnsAddress, "family": "ipv4"}}
	failurePath := decodePathEndpoint(failureChild.request("open", failurePathFields))
	failureGateway := decodeEndpoint(failureChild.request("gateway.open", map[string]any{"pathId": "failure-path", "generation": 1, "gateway": baseGateway}))
	failureAssociations := make([]udpFixtureAssociation, 4)
	for index := range failureAssociations {
		failureAssociations[index].control, failureAssociations[index].local, failureAssociations[index].relay = openAuthenticatedUDP(failurePath)
		defer failureAssociations[index].control.Close()
		defer failureAssociations[index].local.Close()
		sendSOCKSDatagram(failureAssociations[index].local, failureAssociations[index].relay, "127.0.0.1:9", []byte(fmt.Sprintf("failure-association-prime-%d", index)))
	}
	expectUDPAssociateRejected(failurePath)
	fallbackPeer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(err)
	defer fallbackPeer.Close()
	check(proxy.countUDP(fallbackPeer.LocalAddr().String()) == 0, "fallback target used before carrier failure")
	pendingPeer, err := net.DialTimeout("tcp", failureGateway.PublicEndpoint, 2*time.Second)
	must(err)
	defer pendingPeer.Close()
	checkIncomingEvent(failureChild.event(), failureGateway)
	concurrentDials := make(chan net.Conn, 4)
	for index := 0; index < 4; index++ {
		go func() {
			connection, _ := net.DialTimeout("tcp", failureGateway.PublicEndpoint, time.Second)
			concurrentDials <- connection
		}()
	}
	beforeFailure := pathWire(failureChild, "failure-path", 1)
	failureStarted := time.Now()
	must(gatewayStdin.Close())
	incomingBeforeTerminal := 1
	for {
		event := failureChild.event()
		if event.Event == "incomingTcp" {
			checkIncomingEvent(event, failureGateway)
			incomingBeforeTerminal++
			continue
		}
		checkGatewayClosedEvent(event, "failure-path", 1)
		break
	}
	eventLatency := time.Since(failureStarted)
	check(eventLatency < 3*time.Second, "gatewayClosed event was delayed")
	select {
	case err := <-gatewayDone:
		gatewayStopped = true
		must(err)
	case <-time.After(5 * time.Second):
		gatewayCommand.Process.Kill()
		<-gatewayDone
		gatewayStopped = true
		panic("gateway carrier shutdown timeout")
	}
	for index := 0; index < 4; index++ {
		if connection := <-concurrentDials; connection != nil {
			connection.Close()
		}
	}
	failureChild.expectNoEvent(300 * time.Millisecond)
	expectEOF(pendingPeer)
	afterFailure := pathWire(failureChild, "failure-path", 1)
	checkMonotonic(beforeFailure, afterFailure)
	for _, association := range failureAssociations {
		expectEOF(association.control)
		_ = writeSOCKSDatagram(association.local, association.relay, fallbackPeer.LocalAddr().String(), []byte("must-not-fall-open"))
	}
	time.Sleep(200 * time.Millisecond)
	check(proxy.countUDP(fallbackPeer.LocalAddr().String()) == 0, "gateway failure switched UDP association to direct egress")
	expectUDPAssociateRejected(failurePath)
	check(errorCode(failureChild.request("gateway.renew", map[string]any{"pathId": "failure-path", "generation": 1})) == "gateway_not_open",
		"dead gateway remained active")
	must(failureChild.stdin.Close())
	select {
	case <-failureChild.done:
	case <-time.After(5 * time.Second):
		panic("failure qbutt-net did not exit after parent EOF")
	}
	must(failureChild.command.Wait())
	check(gatewayErrors.Len() == 0, "gateway emitted stderr")
	evidence["udpAssociationsFailClosed"] = true
	evidence["udpMultiplexBounded"] = true
	evidence["wireCounters"] = true
	evidence["gatewayClosedExactlyOnce"] = true
	evidence["gatewayClosedLatencyMillis"] = eventLatency.Milliseconds()
	evidence["terminalAfterIncomingTcp"] = incomingBeforeTerminal >= 1
	evidence["loopbackPublicEndpointProven"] = true
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
