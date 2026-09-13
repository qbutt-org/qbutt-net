package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/gateway"
	C "github.com/metacubex/mihomo/constant"
	quic "github.com/metacubex/quic-go"
	qtls "github.com/metacubex/tls"
)

const (
	maxGatewayCredentialBytes = 256 * 1024
	maxGatewayTickets         = 64
	maxRelayHandshakes        = 32
	gatewayOperationTimeout   = 5 * time.Second
	relayTicketLifetime       = 5 * time.Second
)

type gatewayOptions struct {
	ControlAddress  string `json:"controlAddress"`
	DatagramAddress string `json:"datagramAddress"`
	ServerName      string `json:"serverName"`
	CAPath          string `json:"caPath"`
	CertificatePath string `json:"certificatePath"`
	PrivateKeyPath  string `json:"privateKeyPath"`
	Port            uint16 `json:"port"`
	TCP             bool   `json:"tcp"`
	UDP             bool   `json:"udp"`
	TTLSeconds      int    `json:"ttlSeconds"`
}

type incomingTCPEvent struct {
	Version        int    `json:"v"`
	ID             uint64 `json:"id"`
	Event          string `json:"event"`
	PathID         string `json:"pathId"`
	Generation     uint64 `json:"generation"`
	Remote         string `json:"remote"`
	PublicEndpoint string `json:"publicEndpoint"`
	RelayHost      string `json:"relayHost"`
	RelayPort      int    `json:"relayPort"`
	RelayToken     string `json:"relayToken"`
}

type relayTicket struct {
	work    net.Conn
	expires time.Time
}

type gatewayClient struct {
	path       *path
	pathID     string
	generation uint64
	options    gatewayOptions
	output     *controlWriter
	tlsConfig  *tls.Config
	control    net.Conn
	datagrams  *quic.Conn
	relay      net.Listener
	session    string
	lease      gateway.LeaseInfo
	ctx        context.Context
	cancel     context.CancelFunc
	ready      chan struct{}
	workSlots  chan struct{}

	writeMu      sync.Mutex
	datagramMu   sync.Mutex
	mu           sync.Mutex
	nextID       uint64
	nextDatagram uint64
	pending      map[uint64]chan gateway.Response
	tickets      map[[32]byte]*relayTicket
	active       map[io.Closer]struct{}
	closed       bool
	readyOnce    sync.Once
	closeOnce    sync.Once
	wg           sync.WaitGroup
}

type pathOwnedConn struct {
	net.Conn
	owner *path
	once  sync.Once
}

type pathOwnedPacketConn struct {
	net.PacketConn
	owner *path
	once  sync.Once
}

func (conn *pathOwnedPacketConn) Close() error {
	var err error
	conn.once.Do(func() {
		err = conn.PacketConn.Close()
		conn.owner.mu.Lock()
		delete(conn.owner.connections, conn.PacketConn)
		conn.owner.mu.Unlock()
	})
	return err
}

func (conn *pathOwnedConn) Close() error {
	var err error
	conn.once.Do(func() {
		err = conn.Conn.Close()
		conn.owner.mu.Lock()
		delete(conn.owner.connections, conn.Conn)
		conn.owner.mu.Unlock()
	})
	return err
}

func openGateway(owner *path, pathID string, generation uint64, options *gatewayOptions, output *controlWriter) (*gatewayClient, *controlError) {
	if options == nil || (!options.TCP && !options.UDP) || (options.UDP && !owner.proxy.SupportUDP()) ||
		options.TTLSeconds < 1 || options.TTLSeconds > 300 || len(options.ControlAddress) == 0 || len(options.ControlAddress) > 512 ||
		(options.UDP && len(options.DatagramAddress) == 0) || len(options.DatagramAddress) > 512 ||
		len(options.ServerName) == 0 || len(options.ServerName) > 253 {
		return nil, failure("invalid_gateway")
	}
	serverName, err := validGatewayServerName(options.ServerName)
	if err != nil {
		return nil, failure("invalid_gateway")
	}
	caBytes, err := readGatewayCredential(options.CAPath)
	if err != nil {
		return nil, failure("gateway_credentials_unreadable")
	}
	certificateBytes, err := readGatewayCredential(options.CertificatePath)
	if err != nil {
		return nil, failure("gateway_credentials_unreadable")
	}
	keyBytes, err := readGatewayCredential(options.PrivateKeyPath)
	if err != nil {
		return nil, failure("gateway_credentials_unreadable")
	}
	root := x509.NewCertPool()
	certificate, err := tls.X509KeyPair(certificateBytes, keyBytes)
	if !root.AppendCertsFromPEM(caBytes) || err != nil {
		return nil, failure("gateway_credentials_invalid")
	}
	var datagramCertificate qtls.Certificate
	if options.UDP {
		datagramCertificate, err = qtls.X509KeyPair(certificateBytes, keyBytes)
		if err != nil {
			return nil, failure("gateway_credentials_invalid")
		}
	}
	relay, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, failure("gateway_relay_failed")
	}
	ctx, cancel := context.WithCancel(owner.ctx)
	client := &gatewayClient{path: owner, pathID: pathID, generation: generation, options: *options, output: output,
		relay: relay, ctx: ctx, cancel: cancel, ready: make(chan struct{}), workSlots: make(chan struct{}, maxGatewayTickets),
		nextID: 1, pending: make(map[uint64]chan gateway.Response),
		tickets: make(map[[32]byte]*relayTicket), active: make(map[io.Closer]struct{})}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{gateway.ALPN}, RootCAs: root,
		Certificates: []tls.Certificate{certificate}, ServerName: serverName}
	client.tlsConfig = tlsConfig
	operation, stop := context.WithTimeout(ctx, gatewayOperationTimeout)
	control, dialErr := owner.gatewayTCP(operation, options.ControlAddress)
	if dialErr != nil {
		stop()
		client.retire()
		return nil, failure("gateway_connect_failed")
	}
	secure := tls.Client(control, tlsConfig)
	if secure.HandshakeContext(operation) != nil || secure.ConnectionState().NegotiatedProtocol != gateway.ALPN {
		stop()
		secure.Close()
		client.retire()
		return nil, failure("gateway_authentication_failed")
	}
	secure.SetDeadline(time.Now().Add(gatewayOperationTimeout))
	if gateway.WriteFrame(secure, gateway.Request{Version: gateway.Version, ID: 1, Method: "control"}) != nil {
		stop()
		secure.Close()
		client.retire()
		return nil, failure("gateway_connect_failed")
	}
	var connected gateway.Response
	if gateway.ReadFrame(secure, &connected) != nil || connected.Version != gateway.Version || connected.ID != 1 || connected.Error != "" || !validGatewayToken(connected.Session) {
		stop()
		secure.Close()
		client.retire()
		return nil, failure("gateway_protocol_error")
	}
	stop()
	secure.SetDeadline(time.Time{})
	client.control = secure
	client.session = connected.Session
	client.wg.Add(3)
	go client.readControl()
	go client.acceptRelay()
	go client.expireTickets()
	if options.UDP {
		operation, stop = context.WithTimeout(ctx, gatewayOperationTimeout)
		if client.openDatagrams(operation, datagramCertificate, root) != nil {
			stop()
			client.close()
			return nil, failure("gateway_datagrams_failed")
		}
		stop()
	}
	operation, stop = context.WithTimeout(ctx, gatewayOperationTimeout)
	response, requestErr := client.request(operation, gateway.Request{Method: "acquire", Path: pathID, Generation: generation,
		TCP: options.TCP, UDP: options.UDP, Port: options.Port, TTLSeconds: options.TTLSeconds})
	stop()
	if requestErr != nil || response.Error != "" || response.Lease == nil || !client.acceptLease(*response.Lease) {
		client.close()
		return nil, failure("gateway_lease_rejected")
	}
	return client, nil
}

func (client *gatewayClient) openDatagrams(ctx context.Context, certificate qtls.Certificate, root *x509.CertPool) error {
	packetConn, destination, err := client.path.gatewayPacket(ctx, client.options.DatagramAddress)
	if err != nil {
		return err
	}
	transport := &quic.Transport{Conn: packetConn}
	transport.SetCreatedConn(true)
	transport.SetSingleUse(true)
	tlsConfig := &qtls.Config{MinVersion: qtls.VersionTLS13, NextProtos: []string{gateway.ALPN}, RootCAs: root,
		Certificates: []qtls.Certificate{certificate}, ServerName: client.tlsConfig.ServerName}
	connection, err := transport.Dial(ctx, net.UDPAddrFromAddrPort(destination), tlsConfig, gateway.QUICConfig())
	if err != nil {
		packetConn.Close()
		return err
	}
	stream, err := connection.OpenStreamSync(ctx)
	if err != nil {
		connection.CloseWithError(1, "datagrams_failed")
		return err
	}
	stream.SetDeadline(time.Now().Add(gatewayOperationTimeout))
	if gateway.WriteFrame(stream, gateway.Request{Version: gateway.Version, ID: 1, Method: "datagrams", Session: client.session}) != nil {
		connection.CloseWithError(1, "datagrams_failed")
		return errors.New("gateway_datagrams_failed")
	}
	var response gateway.Response
	if gateway.ReadFrame(stream, &response) != nil || response.Version != gateway.Version || response.ID != 1 || response.Error != "" ||
		response.Session != client.session || response.DatagramPayload != gateway.MaxDatagramPayload {
		connection.CloseWithError(1, "datagrams_failed")
		return errors.New("gateway_datagrams_failed")
	}
	stream.Close()
	client.mu.Lock()
	if client.closed {
		client.mu.Unlock()
		connection.CloseWithError(0, "gateway_closed")
		return errors.New("gateway_closed")
	}
	client.datagrams = connection
	client.mu.Unlock()
	client.wg.Add(1)
	go client.readDatagrams()
	return nil
}

func validGatewayServerName(value string) (string, error) {
	if address, err := netip.ParseAddr(value); err == nil {
		address = address.Unmap()
		if address.IsUnspecified() || address.IsMulticast() || address.Zone() != "" {
			return "", errors.New("invalid_server_name")
		}
		return address.String(), nil
	}
	name, err := dnsName(value)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(name, "."), nil
}

func readGatewayCredential(filename string) ([]byte, error) {
	if len(filename) == 0 || len(filename) > 1024 || !filepath.IsAbs(filename) || strings.HasPrefix(filepath.VolumeName(filename), `\\`) {
		return nil, errors.New("invalid_credential_path")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxGatewayCredentialBytes {
		return nil, errors.New("invalid_credential_file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxGatewayCredentialBytes+1))
	if err != nil || len(data) > maxGatewayCredentialBytes {
		return nil, errors.New("invalid_credential_file")
	}
	return data, nil
}

func (p *path) gatewayAddress(ctx context.Context, value string) (netip.AddrPort, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" || len(host) > 253 {
		return netip.AddrPort{}, errors.New("invalid_gateway_address")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, errors.New("invalid_gateway_address")
	}
	var address netip.Addr
	if address, err = netip.ParseAddr(host); err != nil {
		addresses, lookupErr := p.resolver.lookup(ctx, host, p.resolver.family)
		if lookupErr != nil || len(addresses) == 0 {
			return netip.AddrPort{}, errors.New("gateway_resolution_failed")
		}
		address = addresses[0]
	}
	address = address.Unmap()
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.Zone() != "" {
		return netip.AddrPort{}, errors.New("invalid_gateway_address")
	}
	return netip.AddrPortFrom(address, uint16(port)), nil
}

func (p *path) gatewayTCP(ctx context.Context, address string) (net.Conn, error) {
	destination, err := p.gatewayAddress(ctx, address)
	if err != nil {
		return nil, err
	}
	metadata := &C.Metadata{NetWork: C.TCP, Type: C.SOCKS5}
	if metadata.SetRemoteAddress(destination.String()) != nil {
		return nil, errors.New("invalid_gateway_address")
	}
	conn, err := p.proxy.DialContext(ctx, metadata)
	if err != nil {
		return nil, err
	}
	counted := newCountedConn(conn, &p.wire.carrierDownloadBytes, &p.wire.carrierUploadBytes)
	if !p.track(counted) {
		return nil, errors.New("path_closed")
	}
	return &pathOwnedConn{Conn: counted, owner: p}, nil
}

func (p *path) gatewayPacket(ctx context.Context, address string) (net.PacketConn, netip.AddrPort, error) {
	destination, err := p.gatewayAddress(ctx, address)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	metadata := &C.Metadata{NetWork: C.UDP, Type: C.SOCKS5}
	if metadata.SetRemoteAddress(destination.String()) != nil {
		return nil, netip.AddrPort{}, errors.New("invalid_gateway_address")
	}
	packetConn, err := p.proxy.ListenPacketContext(ctx, metadata)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	counted := &countedPacketConn{PacketConn: packetConn, downloadBytes: &p.wire.carrierDownloadBytes,
		uploadBytes: &p.wire.carrierUploadBytes, downloadPackets: &p.wire.carrierDownloadPackets,
		uploadPackets: &p.wire.carrierUploadPackets}
	if !p.track(counted) {
		return nil, netip.AddrPort{}, errors.New("path_closed")
	}
	return &pathOwnedPacketConn{PacketConn: counted, owner: p}, destination, nil
}

func validGatewayToken(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(value) == 32 && len(decoded) == 16 && value == strings.ToLower(value)
}

func validNumericEndpoint(value string) (string, bool) {
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil || endpoint.Port() == 0 {
		return "", false
	}
	address := endpoint.Addr().Unmap()
	if address.IsUnspecified() || address.IsMulticast() || address.Zone() != "" {
		return "", false
	}
	return netip.AddrPortFrom(address, endpoint.Port()).String(), true
}

func (client *gatewayClient) acceptLease(lease gateway.LeaseInfo) bool {
	endpoint, valid := validNumericEndpoint(lease.Endpoint)
	if !valid || !validGatewayToken(lease.Lease) || lease.Session != client.session || lease.Path != client.pathID ||
		lease.Generation != client.generation || lease.TCP != client.options.TCP || lease.UDP != client.options.UDP ||
		lease.ExpiresUnixMilli <= time.Now().UnixMilli() {
		return false
	}
	lease.Endpoint = endpoint
	client.mu.Lock()
	current := client.lease
	if current.Lease != "" && (lease.Lease != current.Lease || lease.Endpoint != current.Endpoint || lease.TCP != current.TCP ||
		lease.UDP != current.UDP || lease.ExpiresUnixMilli <= current.ExpiresUnixMilli) {
		client.mu.Unlock()
		return false
	}
	client.lease = lease
	client.mu.Unlock()
	return true
}

func (client *gatewayClient) endpoint() map[string]any {
	client.mu.Lock()
	lease := client.lease
	client.mu.Unlock()
	return map[string]any{"pathId": client.pathID, "generation": client.generation, "publicEndpoint": lease.Endpoint,
		"tcp": lease.TCP, "udp": lease.UDP, "expiresUnixMilli": lease.ExpiresUnixMilli, "relayHost": "127.0.0.1",
		"relayPort": client.relay.Addr().(*net.TCPAddr).Port}
}

func (client *gatewayClient) isClosed() bool {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.closed
}

func (client *gatewayClient) hasUDP() bool {
	client.mu.Lock()
	defer client.mu.Unlock()
	return !client.closed && client.lease.UDP && client.datagrams != nil
}

func (client *gatewayClient) activate() {
	client.readyOnce.Do(func() { close(client.ready) })
}

func (client *gatewayClient) request(ctx context.Context, request gateway.Request) (gateway.Response, error) {
	client.mu.Lock()
	if client.closed {
		client.mu.Unlock()
		return gateway.Response{}, errors.New("gateway_closed")
	}
	client.nextID++
	if client.nextID == 0 || client.nextID > 9007199254740991 {
		client.mu.Unlock()
		return gateway.Response{}, errors.New("request_limit")
	}
	request.Version = gateway.Version
	request.ID = client.nextID
	request.Session = client.session
	replies := make(chan gateway.Response, 1)
	client.pending[request.ID] = replies
	client.mu.Unlock()
	client.writeMu.Lock()
	client.control.SetWriteDeadline(time.Now().Add(gatewayOperationTimeout))
	err := gateway.WriteFrame(client.control, request)
	client.control.SetWriteDeadline(time.Time{})
	client.writeMu.Unlock()
	if err != nil {
		client.removePending(request.ID)
		client.retire()
		return gateway.Response{}, err
	}
	select {
	case response, ok := <-replies:
		if !ok {
			return gateway.Response{}, errors.New("gateway_closed")
		}
		return response, nil
	case <-ctx.Done():
		client.removePending(request.ID)
		client.retire()
		return gateway.Response{}, ctx.Err()
	case <-client.ctx.Done():
		client.removePending(request.ID)
		return gateway.Response{}, errors.New("gateway_closed")
	}
}

func (client *gatewayClient) removePending(id uint64) {
	client.mu.Lock()
	delete(client.pending, id)
	client.mu.Unlock()
}

func (client *gatewayClient) readControl() {
	defer client.wg.Done()
	defer client.retire()
	for {
		var response gateway.Response
		if gateway.ReadFrame(client.control, &response) != nil || response.Version != gateway.Version {
			return
		}
		if response.ID != 0 {
			client.mu.Lock()
			replies := client.pending[response.ID]
			delete(client.pending, response.ID)
			client.mu.Unlock()
			if replies == nil {
				return
			}
			replies <- response
			close(replies)
			continue
		}
		if response.Accepted != nil {
			select {
			case client.workSlots <- struct{}{}:
			default:
				continue
			}
			client.wg.Add(1)
			go func(accepted gateway.Accepted) {
				defer client.wg.Done()
				defer func() { <-client.workSlots }()
				client.handleAccepted(accepted)
			}(*response.Accepted)
			continue
		}
		if response.Revoked != "" {
			client.mu.Lock()
			valid := response.Revoked == client.lease.Lease
			client.mu.Unlock()
			if valid {
				return
			}
			continue
		}
		return
	}
}

func (client *gatewayClient) sendDatagram(remote netip.AddrPort, payload []byte) bool {
	client.datagramMu.Lock()
	defer client.datagramMu.Unlock()
	client.mu.Lock()
	lease := client.lease
	connection := client.datagrams
	if client.closed || connection == nil || !lease.UDP || len(payload) > maxGatewaySOCKSUDPPayload ||
		!time.Now().Before(time.UnixMilli(lease.ExpiresUnixMilli)) || client.nextDatagram == 9007199254740991 {
		client.mu.Unlock()
		return false
	}
	client.nextDatagram++
	message := client.nextDatagram
	client.mu.Unlock()
	fragments, err := gateway.EncodeDatagram(gateway.Datagram{Lease: lease.Lease, Generation: client.generation,
		Remote: remote, Payload: payload}, message)
	if err != nil {
		return false
	}
	for _, fragment := range fragments {
		if connection.SendDatagram(fragment) != nil {
			client.retire()
			return false
		}
	}
	client.path.wire.relayUploadBytes.add(len(payload))
	return true
}

func (client *gatewayClient) readDatagrams() {
	defer client.wg.Done()
	defer client.retire()
	select {
	case <-client.ready:
	case <-client.ctx.Done():
		return
	}
	var reassembler gateway.Reassembler
	for {
		client.mu.Lock()
		connection := client.datagrams
		client.mu.Unlock()
		if connection == nil {
			return
		}
		data, err := connection.ReceiveDatagram(client.ctx)
		if err != nil {
			return
		}
		fragment, err := gateway.DecodeDatagram(data)
		if err != nil {
			continue
		}
		packet, status, _ := reassembler.Add(fragment, time.Now())
		if status != gateway.ReassemblyComplete {
			continue
		}
		client.mu.Lock()
		lease := client.lease
		valid := !client.closed && lease.UDP && packet.Lease == lease.Lease && packet.Generation == client.generation &&
			time.Now().Before(time.UnixMilli(lease.ExpiresUnixMilli))
		client.mu.Unlock()
		if valid {
			client.path.deliverGatewayUDP(packet.Remote, packet.Payload)
		}
	}
}

func (client *gatewayClient) handleAccepted(accepted gateway.Accepted) {
	remote, validRemote := validNumericEndpoint(accepted.Remote)
	publicEndpoint, validPublic := validNumericEndpoint(accepted.Endpoint)
	client.mu.Lock()
	lease := client.lease
	valid := !client.closed && validRemote && validPublic && accepted.Session == client.session && accepted.Lease == lease.Lease &&
		accepted.Path == client.pathID && accepted.Generation == client.generation && publicEndpoint == lease.Endpoint &&
		accepted.TCP == lease.TCP && accepted.UDP == lease.UDP && accepted.Connection != 0 &&
		accepted.ExpiresUnixMilli > time.Now().UnixMilli()
	client.mu.Unlock()
	if !valid {
		return
	}
	operation, cancel := context.WithTimeout(client.ctx, gatewayOperationTimeout)
	defer cancel()
	raw, err := client.path.gatewayTCP(operation, client.options.ControlAddress)
	if err != nil {
		return
	}
	secure := tls.Client(raw, client.tlsConfig.Clone())
	if secure.HandshakeContext(operation) != nil || secure.ConnectionState().NegotiatedProtocol != gateway.ALPN {
		secure.Close()
		return
	}
	secure.SetDeadline(time.Now().Add(gatewayOperationTimeout))
	request := gateway.Request{Version: gateway.Version, ID: 1, Method: "work", Session: client.session,
		Lease: lease.Lease, Generation: client.generation, Connection: accepted.Connection}
	if gateway.WriteFrame(secure, request) != nil {
		secure.Close()
		return
	}
	var response gateway.Response
	if gateway.ReadFrame(secure, &response) != nil || response.Version != gateway.Version || response.ID != 1 || response.Error != "" || response.Accepted == nil {
		secure.Close()
		return
	}
	confirmed := *response.Accepted
	confirmedRemote, remoteOK := validNumericEndpoint(confirmed.Remote)
	confirmedPublic, publicOK := validNumericEndpoint(confirmed.Endpoint)
	if !remoteOK || !publicOK || confirmedRemote != remote || confirmedPublic != lease.Endpoint || confirmed.Session != client.session ||
		confirmed.Lease != lease.Lease || confirmed.Path != client.pathID || confirmed.Generation != client.generation ||
		confirmed.Connection != accepted.Connection || confirmed.TCP != lease.TCP || confirmed.UDP != lease.UDP ||
		confirmed.ExpiresUnixMilli <= time.Now().UnixMilli() {
		secure.Close()
		return
	}
	secure.SetDeadline(time.Time{})
	select {
	case <-client.ready:
	case <-client.ctx.Done():
		secure.Close()
		return
	}
	if !client.addTicket(secure, remote) {
		secure.Close()
	}
}

func (client *gatewayClient) acceptRelay() {
	defer client.wg.Done()
	limit := make(chan struct{}, maxRelayHandshakes)
	for {
		conn, err := client.relay.Accept()
		if err != nil {
			return
		}
		if !client.trackActive(conn) {
			conn.Close()
			continue
		}
		select {
		case limit <- struct{}{}:
			client.wg.Add(1)
			go func() {
				defer client.wg.Done()
				defer func() { <-limit }()
				client.serveRelay(conn)
			}()
		default:
			client.releaseActive(conn)
		}
	}
}

func (client *gatewayClient) serveRelay(conn net.Conn) {
	defer client.releaseActive(conn)
	conn.SetDeadline(time.Now().Add(relayTicketLifetime))
	var prelude [37]byte
	if _, err := io.ReadFull(conn, prelude[:]); err != nil {
		return
	}
	ticket := client.takeTicket(prelude[:])
	if ticket == nil {
		return
	}
	defer client.releaseActive(ticket.work)
	conn.SetDeadline(time.Time{})
	local := newCountedConn(conn, nil, &client.path.wire.relayDownloadBytes)
	work := newCountedConn(ticket.work, nil, &client.path.wire.relayUploadBytes)
	N.Relay(local, work)
}

func (client *gatewayClient) takeTicket(prelude []byte) *relayTicket {
	now := time.Now()
	var selected [32]byte
	found := 0
	var expired []*relayTicket
	client.mu.Lock()
	for token, ticket := range client.tickets {
		if !now.Before(ticket.expires) {
			delete(client.tickets, token)
			expired = append(expired, ticket)
			continue
		}
		match := subtle.ConstantTimeCompare(prelude[:4], []byte("QBIN")) & subtle.ConstantTimeByteEq(prelude[4], 1) &
			subtle.ConstantTimeCompare(prelude[5:], token[:])
		if match == 1 {
			selected = token
			found = 1
		}
	}
	var ticket *relayTicket
	if found == 1 {
		ticket = client.tickets[selected]
		delete(client.tickets, selected)
	}
	client.mu.Unlock()
	for _, current := range expired {
		client.releaseActive(current.work)
	}
	return ticket
}

func (client *gatewayClient) expireTickets() {
	defer client.wg.Done()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-client.ctx.Done():
			return
		case now := <-ticker.C:
			var expired []*relayTicket
			client.mu.Lock()
			for token, ticket := range client.tickets {
				if !now.Before(ticket.expires) {
					delete(client.tickets, token)
					expired = append(expired, ticket)
				}
			}
			client.mu.Unlock()
			for _, ticket := range expired {
				client.releaseActive(ticket.work)
			}
		}
	}
}

func (client *gatewayClient) renew() (map[string]any, *controlError) {
	client.mu.Lock()
	lease := client.lease
	client.mu.Unlock()
	ctx, cancel := context.WithTimeout(client.ctx, gatewayOperationTimeout)
	defer cancel()
	response, err := client.request(ctx, gateway.Request{Method: "renew", Lease: lease.Lease, Generation: client.generation,
		TTLSeconds: client.options.TTLSeconds})
	if err != nil || response.Error != "" || response.Lease == nil || !client.acceptLease(*response.Lease) {
		client.retire()
		return nil, failure("gateway_renew_failed")
	}
	return client.endpoint(), nil
}

func (client *gatewayClient) release() *controlError {
	client.mu.Lock()
	lease := client.lease
	client.mu.Unlock()
	if lease.Lease == "" {
		return failure("gateway_close_failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), gatewayOperationTimeout)
	defer cancel()
	response, err := client.request(ctx, gateway.Request{Method: "release", Lease: lease.Lease, Generation: client.generation})
	if err != nil || response.Error != "" {
		return failure("gateway_close_failed")
	}
	return nil
}

func (client *gatewayClient) close() {
	client.retire()
	client.wg.Wait()
}

func (client *gatewayClient) retire() {
	client.closeOnce.Do(func() {
		client.mu.Lock()
		client.closed = true
		client.cancel()
		datagrams := client.datagrams
		client.datagrams = nil
		pending := client.pending
		client.pending = make(map[uint64]chan gateway.Response)
		client.tickets = make(map[[32]byte]*relayTicket)
		active := client.active
		client.active = make(map[io.Closer]struct{})
		client.mu.Unlock()
		client.relay.Close()
		if client.control != nil {
			client.control.Close()
		}
		if datagrams != nil {
			datagrams.CloseWithError(0, "gateway_closed")
		}
		for _, replies := range pending {
			close(replies)
		}
		for closer := range active {
			closer.Close()
		}
		client.path.clearGateway(client)
	})
}

func (client *gatewayClient) addTicket(work net.Conn, remote string) bool {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return false
	}
	ticket := &relayTicket{work: work, expires: time.Now().Add(relayTicketLifetime)}
	client.mu.Lock()
	if client.closed || len(client.tickets) >= maxGatewayTickets || len(client.active) >= maxGatewayTickets+maxRelayHandshakes {
		client.mu.Unlock()
		return false
	}
	if _, exists := client.tickets[token]; exists {
		client.mu.Unlock()
		return false
	}
	client.tickets[token] = ticket
	client.active[work] = struct{}{}
	lease := client.lease
	client.mu.Unlock()
	event := incomingTCPEvent{Version: protocolVersion, ID: 0, Event: "incomingTcp", PathID: client.pathID,
		Generation: client.generation, Remote: remote, PublicEndpoint: lease.Endpoint, RelayHost: "127.0.0.1",
		RelayPort: client.relay.Addr().(*net.TCPAddr).Port, RelayToken: hex.EncodeToString(token[:])}
	if client.output.write(event, 0) != nil {
		client.mu.Lock()
		delete(client.tickets, token)
		delete(client.active, work)
		client.mu.Unlock()
		client.retire()
		return false
	}
	return true
}

func (client *gatewayClient) trackActive(closer io.Closer) bool {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed || len(client.active) >= maxGatewayTickets+maxRelayHandshakes {
		return false
	}
	client.active[closer] = struct{}{}
	return true
}

func (client *gatewayClient) releaseActive(closer io.Closer) {
	closer.Close()
	client.mu.Lock()
	delete(client.active, closer)
	client.mu.Unlock()
}
