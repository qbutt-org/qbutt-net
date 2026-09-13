package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	quic "github.com/metacubex/quic-go"
	qtls "github.com/metacubex/tls"
)

type Config struct {
	ControlAddress          string   `json:"controlAddress"`
	DatagramAddress         string   `json:"datagramAddress"`
	ListenerIP              string   `json:"listenerIP"`
	AdvertiseIP             string   `json:"advertiseIP"`
	AllowedPorts            []uint16 `json:"allowedPorts"`
	MaxClients              int      `json:"maxClients"`
	MaxLeases               int      `json:"maxLeases"`
	MaxTCPPerLease          int      `json:"maxTCPPerLease"`
	MaxTCP                  int      `json:"maxTCP"`
	MaxTTLSeconds           int      `json:"maxTTLSeconds"`
	MaxUDPPacketsPerSecond  int      `json:"maxUDPPacketsPerSecond"`
	MaxUDPBytesPerSecond    int      `json:"maxUDPBytesPerSecond"`
	ClientCertificateSHA256 string   `json:"clientCertificateSHA256"`
}

type Server struct {
	config      Config
	control     net.Listener
	datagrams   *quic.Listener
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.Mutex
	sessions    map[string]*session
	connections map[net.Conn]struct{}
	peers       int
	rate        datagramRate
	stats       DatagramStats
	wg          sync.WaitGroup
}

type session struct {
	server      *Server
	id          string
	principal   [32]byte
	control     net.Conn
	writeMu     sync.Mutex
	leases      map[string]*lease
	generation  map[string]uint64
	udp         *quic.Conn
	sendUDP     chan outgoingDatagram
	nextMessage uint64
	closed      bool
}

type outgoingDatagram struct {
	lease     *lease
	fragments [][]byte
	bytes     int
}

type datagramRate struct {
	updated      time.Time
	packetTokens float64
	byteTokens   float64
}

type lease struct {
	owner    *session
	info     LeaseInfo
	deadline time.Time
	tcp      net.Listener
	udp      *net.UDPConn
	done     chan struct{}
	peers    map[uint64]*peer
	nextPeer uint64
	remote   map[netip.AddrPort]time.Time
	active   bool
}

const ephemeralLeaseAttempts = 16

type peer struct {
	incoming net.Conn
	work     net.Conn
	claimed  chan struct{}
}

func New(config Config, tlsConfig *tls.Config, datagramTLS *qtls.Config) (*Server, error) {
	if _, err := netip.ParseAddrPort(config.ControlAddress); err != nil {
		return nil, errors.New("numeric_control_address_required")
	}
	if _, err := netip.ParseAddrPort(config.DatagramAddress); err != nil {
		return nil, errors.New("numeric_datagram_address_required")
	}
	bind, err := netip.ParseAddr(config.ListenerIP)
	advertise, advertiseErr := netip.ParseAddr(config.AdvertiseIP)
	if err != nil || advertiseErr != nil || bind.IsMulticast() || advertise.IsUnspecified() || advertise.IsMulticast() || len(config.AllowedPorts) == 0 || len(config.AllowedPorts) > 256 {
		return nil, errors.New("invalid_listener_acl")
	}
	for _, port := range config.AllowedPorts {
		if port == 0 && !bind.IsLoopback() {
			return nil, errors.New("ephemeral_requires_loopback")
		}
	}
	if config.MaxClients != 1 || config.MaxLeases < 1 || config.MaxLeases > 8 || config.MaxTCPPerLease < 1 || config.MaxTCPPerLease > 64 || config.MaxTCP < 1 || config.MaxTCP > 256 || config.MaxTTLSeconds < 1 || config.MaxTTLSeconds > 300 ||
		config.MaxUDPPacketsPerSecond < 1 || config.MaxUDPPacketsPerSecond > 4096 || config.MaxUDPBytesPerSecond < MaxDatagramPayload || config.MaxUDPBytesPerSecond > 256*1024*1024 {
		return nil, errors.New("invalid_limits")
	}
	if tlsConfig == nil || tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert || tlsConfig.MinVersion < tls.VersionTLS13 || datagramTLS == nil || datagramTLS.ClientAuth != qtls.RequireAndVerifyClientCert || datagramTLS.MinVersion < qtls.VersionTLS13 {
		return nil, errors.New("mutual_tls_required")
	}
	fingerprintBytes, err := hex.DecodeString(config.ClientCertificateSHA256)
	if err != nil || len(fingerprintBytes) != sha256.Size {
		return nil, errors.New("client_certificate_fingerprint_required")
	}
	var fingerprint [sha256.Size]byte
	copy(fingerprint[:], fingerprintBytes)
	tlsConfig = tlsConfig.Clone()
	datagramTLS = datagramTLS.Clone()
	tlsConfig.SessionTicketsDisabled = true
	datagramTLS.SessionTicketsDisabled = true
	tlsConfig.VerifyPeerCertificate = fingerprintVerifier(fingerprint, tlsConfig.VerifyPeerCertificate)
	datagramTLS.VerifyPeerCertificate = fingerprintVerifier(fingerprint, datagramTLS.VerifyPeerCertificate)
	control, err := tls.Listen("tcp", config.ControlAddress, tlsConfig)
	if err != nil {
		return nil, errors.New("control_listen_failed")
	}
	udp, err := quic.ListenAddr(config.DatagramAddress, datagramTLS, QUICConfig())
	if err != nil {
		control.Close()
		return nil, errors.New("datagram_listen_failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{config: config, control: control, datagrams: udp, ctx: ctx, cancel: cancel,
		sessions: make(map[string]*session), connections: make(map[net.Conn]struct{}),
		rate: datagramRate{updated: time.Now(), packetTokens: float64(config.MaxUDPPacketsPerSecond), byteTokens: float64(config.MaxUDPBytesPerSecond)}}
	s.wg.Add(3)
	go s.acceptTLS()
	go s.acceptQUIC()
	go s.expire()
	return s, nil
}

func fingerprintVerifier(expected [sha256.Size]byte, previous func([][]byte, [][]*x509.Certificate) error) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if previous != nil {
			if err := previous(rawCerts, verifiedChains); err != nil {
				return err
			}
		}
		if len(rawCerts) == 0 {
			return errors.New("client_certificate_rejected")
		}
		actual := sha256.Sum256(rawCerts[0])
		if subtle.ConstantTimeCompare(actual[:], expected[:]) != 1 {
			return errors.New("client_certificate_rejected")
		}
		return nil
	}
}

func QUICConfig() *quic.Config {
	return &quic.Config{EnableDatagrams: true, Allow0RTT: false, HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 10 * time.Second, MaxIncomingStreams: 1, MaxIncomingUniStreams: -1,
		InitialStreamReceiveWindow: 32768, MaxStreamReceiveWindow: 32768,
		InitialConnectionReceiveWindow: 65536, MaxConnectionReceiveWindow: 65536, MaxDatagramFrameSize: 1200}
}

func (s *Server) Addresses() (string, string) {
	return s.control.Addr().String(), s.datagrams.Addr().String()
}

func (s *Server) Close() {
	s.cancel()
	s.control.Close()
	s.datagrams.Close()
	s.mu.Lock()
	owners := make([]*session, 0, len(s.sessions))
	connections := make([]net.Conn, 0, len(s.connections))
	for _, owner := range s.sessions {
		owners = append(owners, owner)
	}
	for conn := range s.connections {
		connections = append(connections, conn)
	}
	s.mu.Unlock()
	for _, conn := range connections {
		conn.Close()
	}
	for _, owner := range owners {
		owner.close()
	}
	s.wg.Wait()
}

func token() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", errors.New("cryptographic_random_unavailable")
	}
	return hex.EncodeToString(bytes[:]), nil
}

func (s *Server) acceptTLS() {
	defer s.wg.Done()
	for {
		conn, err := s.control.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if len(s.connections) >= 512 || s.ctx.Err() != nil {
			s.mu.Unlock()
			conn.Close()
			continue
		}
		s.connections[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() { conn.Close(); s.mu.Lock(); delete(s.connections, conn); s.mu.Unlock() }()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			secure := conn.(*tls.Conn)
			if secure.HandshakeContext(s.ctx) != nil {
				return
			}
			state := secure.ConnectionState()
			if state.NegotiatedProtocol != ALPN || len(state.PeerCertificates) == 0 {
				return
			}
			principal := sha256.Sum256(state.PeerCertificates[0].Raw)
			var first Request
			if ReadFrame(conn, &first) != nil || first.Version != Version || first.ID == 0 {
				return
			}
			switch first.Method {
			case "control":
				s.serveControl(conn, first, principal)
			case "work":
				s.serveWork(conn, first, principal)
			}
		}()
	}
}

func (owner *session) send(response Response) error {
	owner.writeMu.Lock()
	defer owner.writeMu.Unlock()
	owner.server.mu.Lock()
	if accepted := response.Accepted; accepted != nil {
		current := owner.leases[accepted.Lease]
		connection := (*peer)(nil)
		if current != nil {
			connection = current.peers[accepted.Connection]
		}
		valid := current != nil && current.active && time.Now().Before(current.deadline) &&
			(current.info.Generation == accepted.Generation) && (connection != nil)
		owner.server.mu.Unlock()
		if !valid {
			return nil
		}
	} else if leaseInfo := response.Lease; leaseInfo != nil {
		current := owner.leases[leaseInfo.Lease]
		valid := current != nil && current.active && time.Now().Before(current.deadline) &&
			(current.info.Generation == leaseInfo.Generation)
		owner.server.mu.Unlock()
		if !valid {
			response.Lease = nil
			response.Error = "lease_rejected"
		}
	} else {
		owner.server.mu.Unlock()
	}
	owner.control.SetWriteDeadline(time.Now().Add(5 * time.Second))
	response.Version = Version
	return WriteFrame(owner.control, response)
}

func (s *Server) serveControl(conn net.Conn, first Request, principal [32]byte) {
	id, err := token()
	if err != nil {
		WriteFrame(conn, Response{Version: Version, ID: first.ID, Error: err.Error()})
		return
	}
	owner := &session{server: s, id: id, principal: principal, control: conn, leases: make(map[string]*lease), generation: make(map[string]uint64)}
	s.mu.Lock()
	if len(s.sessions) >= s.config.MaxClients {
		s.mu.Unlock()
		WriteFrame(conn, Response{Version: Version, ID: first.ID, Error: "client_limit"})
		return
	}
	// One control session per authenticated principal prevents reconnects from
	// bypassing per-client quotas. A closed session may restart its generations.
	for _, existing := range s.sessions {
		if existing.principal == principal {
			s.mu.Unlock()
			WriteFrame(conn, Response{Version: Version, ID: first.ID, Error: "client_active"})
			return
		}
	}
	s.sessions[owner.id] = owner
	s.mu.Unlock()
	defer owner.close()
	if owner.send(Response{ID: first.ID, Session: owner.id, DatagramPayload: MaxDatagramPayload}) != nil {
		return
	}
	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		var request Request
		if ReadFrame(conn, &request) != nil || request.Version != Version || request.ID == 0 || request.Session != owner.id {
			return
		}
		response := Response{ID: request.ID}
		switch request.Method {
		case "acquire":
			response.Lease, response.Error = owner.acquire(request)
		case "renew", "release":
			s.mu.Lock()
			current := owner.leases[request.Lease]
			valid := current != nil && current.active && current.info.Generation == request.Generation && time.Now().Before(current.deadline)
			if valid && request.Method == "renew" {
				if request.TTLSeconds < 1 || request.TTLSeconds > s.config.MaxTTLSeconds {
					valid = false
				} else {
					deadline := time.Now().Add(time.Duration(request.TTLSeconds) * time.Second)
					expires := deadline.UnixMilli()
					if expires <= current.info.ExpiresUnixMilli {
						expires = current.info.ExpiresUnixMilli + 1
						deadline = time.UnixMilli(expires)
					}
					current.deadline = deadline
					current.info.ExpiresUnixMilli = expires
					copy := current.info
					response.Lease = &copy
				}
			}
			s.mu.Unlock()
			if !valid {
				response.Error = "lease_rejected"
			} else if request.Method == "release" {
				current.close()
			}
		case "stats":
			s.mu.Lock()
			stats := s.stats
			s.mu.Unlock()
			response.Datagrams = &stats
		default:
			response.Error = "unknown_method"
		}
		if owner.send(response) != nil {
			return
		}
	}
}

func validPath(path string) bool {
	if len(path) < 1 || len(path) > 64 {
		return false
	}
	for _, char := range path {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func (owner *session) acquire(request Request) (*LeaseInfo, string) {
	s := owner.server
	if !validPath(request.Path) || request.Generation == 0 || request.Generation > 9007199254740991 || (!request.TCP && !request.UDP) || request.TTLSeconds < 1 || request.TTLSeconds > s.config.MaxTTLSeconds {
		return nil, "invalid_lease"
	}
	allowed := false
	for _, port := range s.config.AllowedPorts {
		allowed = allowed || port == request.Port
	}
	if !allowed {
		return nil, "port_denied"
	}
	s.mu.Lock()
	if owner.closed || request.Generation <= owner.generation[request.Path] || (owner.generation[request.Path] == 0 && len(owner.generation) >= 64) {
		s.mu.Unlock()
		return nil, "generation_rejected"
	}
	if request.UDP && owner.udp == nil {
		s.mu.Unlock()
		return nil, "datagrams_required"
	}
	var previous *lease
	for _, current := range owner.leases {
		if current.info.Path == request.Path {
			previous = current
			break
		}
	}
	if previous == nil && len(owner.leases) >= s.config.MaxLeases {
		s.mu.Unlock()
		return nil, "lease_limit"
	}
	s.mu.Unlock()
	if previous != nil {
		previous.close()
	}
	current := &lease{owner: owner, done: make(chan struct{}), peers: make(map[uint64]*peer), remote: make(map[netip.AddrPort]time.Time)}
	var port uint16
	current.tcp, current.udp, port = listenLease(s.config.ListenerIP, request.Port, request.TCP, request.UDP)
	if port == 0 {
		return nil, "listener_failed"
	}
	leaseID, tokenErr := token()
	if tokenErr != nil {
		if current.tcp != nil {
			current.tcp.Close()
		}
		if current.udp != nil {
			current.udp.Close()
		}
		return nil, tokenErr.Error()
	}
	current.deadline = time.Now().Add(time.Duration(request.TTLSeconds) * time.Second)
	current.info = LeaseInfo{Session: owner.id, Lease: leaseID, Path: request.Path, Generation: request.Generation,
		Endpoint: net.JoinHostPort(s.config.AdvertiseIP, strconv.Itoa(int(port))), TCP: request.TCP, UDP: request.UDP,
		ExpiresUnixMilli: current.deadline.UnixMilli()}
	s.mu.Lock()
	if owner.closed || s.ctx.Err() != nil || (request.UDP && owner.udp == nil) {
		s.mu.Unlock()
		if current.tcp != nil {
			current.tcp.Close()
		}
		if current.udp != nil {
			current.udp.Close()
		}
		return nil, "control_closed"
	}
	current.active = true
	owner.generation[request.Path] = request.Generation
	owner.leases[current.info.Lease] = current
	if current.tcp != nil {
		s.wg.Add(1)
		go current.acceptTCP()
	}
	if current.udp != nil {
		s.wg.Add(1)
		go current.readUDP()
	}
	s.mu.Unlock()
	copy := current.info
	return &copy, ""
}

func listenLease(listenerIP string, requestedPort uint16, tcpEnabled, udpEnabled bool) (net.Listener, *net.UDPConn, uint16) {
	attempts := 1
	if requestedPort == 0 && tcpEnabled && udpEnabled {
		attempts = ephemeralLeaseAttempts
	}
	for attempt := 0; attempt < attempts; attempt++ {
		port := requestedPort
		var tcpListener net.Listener
		if tcpEnabled {
			address := net.JoinHostPort(listenerIP, strconv.Itoa(int(port)))
			var err error
			tcpListener, err = net.Listen("tcp", address)
			if err != nil {
				return nil, nil, 0
			}
			port = uint16(tcpListener.Addr().(*net.TCPAddr).Port)
		}
		if udpEnabled {
			udpAddress, _ := net.ResolveUDPAddr("udp", net.JoinHostPort(listenerIP, strconv.Itoa(int(port))))
			udpListener, err := net.ListenUDP("udp", udpAddress)
			if err != nil {
				if tcpListener != nil {
					tcpListener.Close()
				}
				if attempts > 1 {
					continue
				}
				return nil, nil, 0
			}
			return tcpListener, udpListener, uint16(udpListener.LocalAddr().(*net.UDPAddr).Port)
		}
		return tcpListener, nil, port
	}
	return nil, nil, 0
}

func (current *lease) close() {
	current.closeIfExpired(nil)
}

func (current *lease) closeIfExpired(expected *time.Time) bool {
	s := current.owner.server
	s.mu.Lock()
	if !current.active || ((expected != nil) && (!current.deadline.Equal(*expected) || time.Now().Before(current.deadline))) {
		s.mu.Unlock()
		return false
	}
	current.active = false
	delete(current.owner.leases, current.info.Lease)
	close(current.done)
	var connections []net.Conn
	for _, peer := range current.peers {
		connections = append(connections, peer.incoming)
		if peer.work != nil {
			connections = append(connections, peer.work)
		}
	}
	s.mu.Unlock()
	if current.tcp != nil {
		current.tcp.Close()
	}
	if current.udp != nil {
		current.udp.Close()
	}
	for _, conn := range connections {
		conn.Close()
	}
	return true
}

func (owner *session) close() {
	s := owner.server
	s.mu.Lock()
	if owner.closed {
		s.mu.Unlock()
		return
	}
	owner.closed = true
	current := make([]*lease, 0, len(owner.leases))
	for _, entry := range owner.leases {
		current = append(current, entry)
	}
	udp := owner.udp
	s.mu.Unlock()
	if udp != nil {
		udp.CloseWithError(0, "control_closed")
	}
	owner.control.Close()
	for _, entry := range current {
		entry.close()
	}
	s.mu.Lock()
	delete(s.sessions, owner.id)
	s.mu.Unlock()
}

func (s *Server) expire() {
	defer s.wg.Done()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	type expiry struct {
		lease    *lease
		deadline time.Time
	}
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-ticker.C:
			s.mu.Lock()
			var expired []expiry
			for _, owner := range s.sessions {
				for _, current := range owner.leases {
					if !now.Before(current.deadline) {
						expired = append(expired, expiry{lease: current, deadline: current.deadline})
					}
				}
			}
			s.mu.Unlock()
			for _, current := range expired {
				if current.lease.closeIfExpired(&current.deadline) && (current.lease.owner.send(Response{Revoked: current.lease.info.Lease}) != nil) {
					current.lease.owner.close()
				}
			}
		}
	}
}

func (current *lease) acceptTCP() {
	s := current.owner.server
	defer s.wg.Done()
	for {
		conn, err := current.tcp.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if !current.active || !time.Now().Before(current.deadline) || len(current.peers) >= s.config.MaxTCPPerLease || s.peers >= s.config.MaxTCP {
			s.mu.Unlock()
			conn.Close()
			continue
		}
		current.nextPeer++
		id := current.nextPeer
		connection := &peer{incoming: conn, claimed: make(chan struct{})}
		current.peers[id] = connection
		s.peers++
		event := Accepted{LeaseInfo: current.info, Connection: id, Remote: conn.RemoteAddr().String()}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			if current.owner.send(Response{Accepted: &event}) != nil {
				current.owner.close()
			}
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			select {
			case <-connection.claimed:
				return
			case <-current.done:
			case <-timer.C:
			}
			s.mu.Lock()
			if connection.work == nil {
				delete(current.peers, id)
				s.peers--
				conn.Close()
			}
			s.mu.Unlock()
		}()
	}
}

func (s *Server) serveWork(conn net.Conn, request Request, principal [32]byte) {
	s.mu.Lock()
	owner := s.sessions[request.Session]
	var current *lease
	if owner != nil && !owner.closed && owner.principal == principal {
		current = owner.leases[request.Lease]
	}
	var connection *peer
	if current != nil && current.active && current.info.Generation == request.Generation && time.Now().Before(current.deadline) {
		connection = current.peers[request.Connection]
	}
	if connection == nil || connection.work != nil {
		s.mu.Unlock()
		WriteFrame(conn, Response{Version: Version, ID: request.ID, Error: "work_rejected"})
		return
	}
	connection.work = conn
	close(connection.claimed)
	metadata := Accepted{LeaseInfo: current.info, Connection: request.Connection, Remote: connection.incoming.RemoteAddr().String()}
	s.mu.Unlock()
	defer func() {
		connection.incoming.Close()
		s.mu.Lock()
		delete(current.peers, request.Connection)
		s.peers--
		s.mu.Unlock()
	}()
	if WriteFrame(conn, Response{Version: Version, ID: request.ID, Accepted: &metadata}) != nil {
		return
	}
	conn.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() {
		io.CopyBuffer(conn, connection.incoming, make([]byte, 32768))
		conn.(*tls.Conn).CloseWrite()
		close(done)
	}()
	io.CopyBuffer(connection.incoming, conn, make([]byte, 32768))
	connection.incoming.(*net.TCPConn).CloseWrite()
	<-done
}

func (s *Server) acceptQUIC() {
	defer s.wg.Done()
	slots := make(chan struct{}, 32)
	for {
		conn, err := s.datagrams.Accept(s.ctx)
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			conn.CloseWithError(1, "datagram_limit")
			continue
		}
		s.wg.Add(1)
		go func() { defer s.wg.Done(); defer func() { <-slots }(); s.serveQUIC(conn) }()
	}
}

func (s *Server) serveQUIC(conn *quic.Conn) {
	defer conn.CloseWithError(0, "datagrams_closed")
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	stream, err := conn.AcceptStream(ctx)
	cancel()
	if err != nil {
		return
	}
	stream.SetDeadline(time.Now().Add(5 * time.Second))
	var request Request
	if ReadFrame(stream, &request) != nil || request.Version != Version || request.Method != "datagrams" || request.ID == 0 {
		return
	}
	state := conn.ConnectionState()
	if len(state.TLS.PeerCertificates) == 0 || !state.SupportsDatagrams.Remote || state.TLS.NegotiatedProtocol != ALPN {
		return
	}
	principal := sha256.Sum256(state.TLS.PeerCertificates[0].Raw)
	s.mu.Lock()
	owner := s.sessions[request.Session]
	if owner == nil || owner.closed || owner.principal != principal || owner.udp != nil {
		s.mu.Unlock()
		WriteFrame(stream, Response{Version: Version, ID: request.ID, Error: "datagrams_rejected"})
		return
	}
	owner.udp = conn
	queue := make(chan outgoingDatagram, 16)
	owner.sendUDP = queue
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		var retired []*lease
		if owner.udp == conn {
			owner.udp = nil
			owner.sendUDP = nil
			for _, current := range owner.leases {
				if current.udp != nil {
					retired = append(retired, current)
				}
			}
		}
		s.mu.Unlock()
		for _, current := range retired {
			current.close()
			if owner.send(Response{Revoked: current.info.Lease}) != nil {
				owner.close()
			}
		}
	}()
	if WriteFrame(stream, Response{Version: Version, ID: request.ID, Session: owner.id, DatagramPayload: MaxDatagramPayload}) != nil {
		return
	}
	stream.Close()
	senderDone := make(chan struct{})
	go func() {
		defer close(senderDone)
		for {
			select {
			case <-conn.Context().Done():
				return
			case packet := <-queue:
				s.mu.Lock()
				valid := packet.lease.active && owner.udp == conn && time.Now().Before(packet.lease.deadline)
				s.mu.Unlock()
				if valid {
					for _, fragment := range packet.fragments {
						if conn.SendDatagram(fragment) != nil {
							conn.CloseWithError(1, "datagram_send_failed")
							return
						}
						s.mu.Lock()
						s.stats.FragmentsSent++
						s.mu.Unlock()
					}
					s.mu.Lock()
					s.stats.ToClientPackets++
					s.stats.ToClientBytes += uint64(packet.bytes)
					s.mu.Unlock()
				}
			}
		}
	}()
	defer func() { conn.CloseWithError(0, "datagrams_closed"); <-senderDone }()
	var reassembler Reassembler
	for {
		data, err := conn.ReceiveDatagram(s.ctx)
		if err != nil {
			return
		}
		s.mu.Lock()
		s.stats.FragmentsReceived++
		s.mu.Unlock()
		fragment, err := DecodeDatagram(data)
		if err != nil {
			s.mu.Lock()
			s.stats.InvalidFragments++
			s.mu.Unlock()
			continue
		}
		packet, status, expired := reassembler.Add(fragment, time.Now())
		s.mu.Lock()
		s.stats.ExpiredAssemblies += uint64(expired)
		switch status {
		case ReassemblyDuplicate:
			s.stats.DuplicateFragments++
		case ReassemblyDropped:
			s.stats.ReassemblyDrops++
		}
		s.mu.Unlock()
		if status != ReassemblyComplete {
			continue
		}
		s.mu.Lock()
		current := owner.leases[packet.Lease]
		valid := current != nil && current.active && current.udp != nil && current.info.Generation == packet.Generation && time.Now().Before(current.deadline) && time.Since(current.remote[packet.Remote]) < 30*time.Second
		if !valid {
			s.stats.PolicyDrops++
		} else if allowed, packetLimited := s.allowDatagram(len(packet.Payload)); !allowed {
			valid = false
			s.recordRateDrop(packetLimited)
		}
		s.mu.Unlock()
		if valid {
			current.udp.SetWriteDeadline(time.Now().Add(time.Second))
			if written, err := current.udp.WriteToUDPAddrPort(packet.Payload, packet.Remote); err == nil && written == len(packet.Payload) {
				s.mu.Lock()
				s.stats.ToPublicPackets++
				s.stats.ToPublicBytes += uint64(written)
				s.mu.Unlock()
			}
		}
	}
}

// Called under the server lock; one tenant budget includes both directions and
// is shared by every lease so more listeners cannot multiply it.
func (s *Server) allowDatagram(bytes int) (bool, bool) {
	now := time.Now()
	elapsed := now.Sub(s.rate.updated).Seconds()
	s.rate.updated = now
	s.rate.packetTokens += elapsed * float64(s.config.MaxUDPPacketsPerSecond)
	if s.rate.packetTokens > float64(s.config.MaxUDPPacketsPerSecond) {
		s.rate.packetTokens = float64(s.config.MaxUDPPacketsPerSecond)
	}
	s.rate.byteTokens += elapsed * float64(s.config.MaxUDPBytesPerSecond)
	if s.rate.byteTokens > float64(s.config.MaxUDPBytesPerSecond) {
		s.rate.byteTokens = float64(s.config.MaxUDPBytesPerSecond)
	}
	if s.rate.packetTokens < 1 {
		return false, true
	}
	if s.rate.byteTokens < float64(bytes) {
		return false, false
	}
	s.rate.packetTokens--
	s.rate.byteTokens -= float64(bytes)
	return true, false
}

func (s *Server) recordRateDrop(packetLimited bool) {
	if packetLimited {
		s.stats.PacketRateDrops++
	} else {
		s.stats.ByteRateDrops++
	}
}

func (current *lease) readUDP() {
	s := current.owner.server
	defer s.wg.Done()
	// Read the complete UDP payload before enforcing the gateway limit. A short
	// Windows buffer reports WSAEMSGSIZE and would otherwise terminate the lease.
	buffer := make([]byte, 65535)
	for {
		size, remote, err := current.udp.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return
		}
		remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
		s.mu.Lock()
		conn := current.owner.udp
		valid := size <= MaxDatagramPayload && current.active && time.Now().Before(current.deadline) && conn != nil
		if valid {
			now := time.Now()
			for peer, seen := range current.remote {
				if now.Sub(seen) >= 30*time.Second {
					delete(current.remote, peer)
				}
			}
			if _, exists := current.remote[remote]; !exists && len(current.remote) >= 128 {
				valid = false
			} else {
				current.remote[remote] = now
			}
		}
		if !valid {
			s.stats.PolicyDrops++
		} else if allowed, packetLimited := s.allowDatagram(size); !allowed {
			valid = false
			s.recordRateDrop(packetLimited)
		}
		current.owner.nextMessage++
		if current.owner.nextMessage == 0 {
			current.owner.nextMessage++
		}
		message := current.owner.nextMessage
		packet := Datagram{Lease: current.info.Lease, Generation: current.info.Generation, Remote: remote, Payload: buffer[:size]}
		s.mu.Unlock()
		if valid {
			fragments, err := EncodeDatagram(packet, message)
			if err == nil {
				s.mu.Lock()
				if current.active && current.owner.udp == conn {
					select {
					case current.owner.sendUDP <- outgoingDatagram{lease: current, fragments: fragments, bytes: size}:
					default:
						s.stats.QueueDrops++
					}
				}
				s.mu.Unlock()
			}
		}
	}
}
