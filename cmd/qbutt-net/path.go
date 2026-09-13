package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
)

// The SOCKS UDP response adds 22 bytes for RSV, FRAG and a numeric IPv6 source.
const maxGatewaySOCKSUDPPayload = 65485

type path struct {
	proxy              C.Proxy
	resolver           *pathResolver
	listener           net.Listener
	generation         uint64
	username           string
	password           string
	ctx                context.Context
	cancel             context.CancelFunc
	mu                 sync.Mutex
	connections        map[io.Closer]struct{}
	gateway            *gatewayClient
	gatewayUDP         *udpAssociation
	udpAssociations    map[*udpAssociation]struct{}
	installingGateway  bool
	udpGatewayReserved bool
	closing            bool
	wg                 sync.WaitGroup
}

type udpAssociation struct {
	local      *net.UDPConn
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.RWMutex
	client     *net.UDPAddr
	remote     C.PacketConn
	closed     bool
	directWork sync.WaitGroup
}

func (association *udpAssociation) setClient(client *net.UDPAddr) {
	association.mu.Lock()
	association.client = &net.UDPAddr{IP: append(net.IP(nil), client.IP...), Port: client.Port, Zone: client.Zone}
	association.mu.Unlock()
}

func (association *udpAssociation) deliver(source netip.AddrPort, payload []byte) bool {
	association.mu.RLock()
	client := association.client
	association.mu.RUnlock()
	if client == nil {
		return false
	}
	packet, err := socks5.EncodeUDPPacket(socks5.ParseAddr(source.String()), payload)
	if err != nil {
		return false
	}
	_, err = association.local.WriteToUDP(packet, client)
	return err == nil
}

func (association *udpAssociation) beginDirect() bool {
	association.mu.Lock()
	defer association.mu.Unlock()
	if association.closed {
		return false
	}
	association.directWork.Add(1)
	return true
}

func (association *udpAssociation) endDirect() {
	association.directWork.Done()
}

func (association *udpAssociation) retire() {
	association.mu.Lock()
	if association.closed {
		association.mu.Unlock()
		return
	}
	association.closed = true
	remote := association.remote
	association.mu.Unlock()
	association.cancel()
	association.local.Close()
	if remote != nil {
		remote.Close()
	}
}

func (association *udpAssociation) setRemote(remote C.PacketConn) bool {
	association.mu.Lock()
	defer association.mu.Unlock()
	if association.closed {
		return false
	}
	association.remote = remote
	return true
}

func openPath(req request) (*path, *controlError) {
	if !validLabel(req.InterfaceName) {
		return nil, failure("interface_required")
	}
	iface, err := net.InterfaceByName(req.InterfaceName)
	if err != nil || iface.Flags&net.FlagUp == 0 {
		return nil, failure("interface_unavailable")
	}
	mapping, importErr := selectedProxy(req)
	if importErr != nil {
		return nil, importErr
	}
	if req.DNS == nil {
		return nil, failure("dns_policy_required")
	}
	dnsAddress, dnsErr := dnsServer(req.DNS.Server)
	bootstrapAddress, bootstrapErr := dnsServer(req.DNS.BootstrapServer)
	if dnsErr != nil || bootstrapErr != nil || !validFamily(req.DNS.Family) {
		return nil, failure("invalid_dns_policy")
	}
	serverHost, ok := mapping["server"].(string)
	if !ok {
		return nil, failure("adapter_rejected")
	}
	// A numeric server permits no bootstrap hostname (dnsName rejects root).
	serverName := "."
	if _, err := netip.ParseAddr(serverHost); err != nil {
		serverName, err = dnsName(serverHost)
		if err != nil {
			return nil, failure("adapter_rejected")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &path{generation: req.Generation, ctx: ctx, cancel: cancel, connections: make(map[io.Closer]struct{}),
		udpAssociations: make(map[*udpAssociation]struct{})}
	opened := false
	defer func() {
		if !opened {
			cancel()
		}
	}()
	physical := dialer.NewDialer(dialer.WithInterface(req.InterfaceName), dialer.WithResolver(&pathResolver{}), dialer.WithFallbackBind(false))
	bootstrap := &pathResolver{owner: p, server: bootstrapAddress, onlyHost: serverName, family: "dual",
		dial: func(ctx context.Context, address string) (net.Conn, error) {
			network := "tcp4"
			if bootstrapAddress.Addr().Is6() {
				network = "tcp6"
			}
			return physical.DialContext(ctx, network, address)
		}}
	bound := serverDialer{Dialer: dialer.NewDialer(dialer.WithInterface(req.InterfaceName), dialer.WithResolver(bootstrap), dialer.WithFallbackBind(false)), bootstrap: bootstrap}
	proxy, err := adapter.ParseProxy(mapping, adapter.WithDialerForAPI(bound))
	if err != nil {
		return nil, failure("adapter_rejected")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		proxy.Close()
		return nil, failure("listener_failed")
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		listener.Close()
		proxy.Close()
		return nil, failure("credentials_failed")
	}
	p.proxy = proxy
	p.listener = listener
	p.username = hex.EncodeToString(secret[:8])
	p.password = hex.EncodeToString(secret[8:])
	p.resolver = &pathResolver{owner: p, server: dnsAddress, family: req.DNS.Family,
		dial: func(ctx context.Context, address string) (net.Conn, error) {
			metadata := &C.Metadata{NetWork: C.TCP, Type: C.SOCKS5}
			if err := metadata.SetRemoteAddress(address); err != nil {
				return nil, err
			}
			return p.proxy.DialContext(ctx, metadata)
		}}
	opened = true
	p.wg.Add(1)
	go p.accept()
	return p, nil
}

func (p *path) endpoint(req request) map[string]any {
	udp := "source-unsupported"
	if p.proxy.SupportUDP() {
		udp = "source-supported"
	}
	return map[string]any{
		"pathId":        req.PathID,
		"generation":    p.generation,
		"interfaceName": req.InterfaceName,
		"host":          "127.0.0.1",
		"port":          p.listener.Addr().(*net.TCPAddr).Port,
		"socksUsername": p.username,
		"socksPassword": p.password,
		"capabilities": map[string]string{
			"tcp":         "supported",
			"udp":         udp,
			"dns":         "path-tcp",
			"publicTcp":   "unknown",
			"publicUdp":   "unknown",
			"measurement": "not-probed",
		},
	}
}

func (p *path) track(c io.Closer) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing || len(p.connections) >= 512 {
		c.Close()
		return false
	}
	p.connections[c] = struct{}{}
	return true
}

func (p *path) release(c io.Closer) {
	c.Close()
	p.mu.Lock()
	delete(p.connections, c)
	p.mu.Unlock()
}

func (p *path) close() {
	p.mu.Lock()
	p.closing = true
	p.cancel()
	p.listener.Close()
	gateway := p.gateway
	p.gateway = nil
	p.gatewayUDP = nil
	for association := range p.udpAssociations {
		association.retire()
	}
	for c := range p.connections {
		c.Close()
	}
	p.mu.Unlock()
	if gateway != nil {
		gateway.close()
	}
	p.proxy.Close()
	p.wg.Wait()
}

func (p *path) installGateway(gateway *gatewayClient) bool {
	usesUDP := gateway.hasUDP()
	p.mu.Lock()
	if p.closing || p.gateway != nil || p.installingGateway || usesUDP && p.udpGatewayReserved || gateway.isClosed() {
		p.mu.Unlock()
		return false
	}
	if !usesUDP {
		p.gateway = gateway
		p.mu.Unlock()
		return true
	}
	p.installingGateway = true
	p.udpGatewayReserved = true
	direct := make([]*udpAssociation, 0, len(p.udpAssociations))
	for association := range p.udpAssociations {
		direct = append(direct, association)
		association.retire()
	}
	p.mu.Unlock()
	for _, association := range direct {
		association.directWork.Wait()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.installingGateway = false
	if p.closing || p.gateway != nil || gateway.isClosed() {
		return false
	}
	p.gateway = gateway
	return true
}

func (p *path) gatewayOccupied() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.gateway != nil || p.installingGateway || p.udpGatewayReserved
}

func (p *path) currentGateway() *gatewayClient {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.gateway == nil || p.gateway.isClosed() {
		return nil
	}
	return p.gateway
}

func (p *path) clearGateway(gateway *gatewayClient) {
	p.mu.Lock()
	var association *udpAssociation
	if p.gateway == gateway {
		p.gateway = nil
		association = p.gatewayUDP
		p.gatewayUDP = nil
	}
	p.mu.Unlock()
	if association != nil {
		association.retire()
	}
}

func (p *path) registerUDP(association *udpAssociation) (*gatewayClient, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing || p.installingGateway {
		return nil, false
	}
	if p.udpGatewayReserved {
		if p.gateway == nil || !p.gateway.hasUDP() || p.gatewayUDP != nil {
			return nil, false
		}
		p.udpAssociations[association] = struct{}{}
		p.gatewayUDP = association
		return p.gateway, true
	}
	p.udpAssociations[association] = struct{}{}
	return nil, true
}

func (p *path) releaseUDP(association *udpAssociation) {
	p.mu.Lock()
	delete(p.udpAssociations, association)
	if p.gatewayUDP == association {
		p.gatewayUDP = nil
	}
	p.mu.Unlock()
}

func (p *path) deliverGatewayUDP(source netip.AddrPort, payload []byte) bool {
	p.mu.Lock()
	association := p.gatewayUDP
	p.mu.Unlock()
	if association != nil && len(payload) > maxGatewaySOCKSUDPPayload {
		association.retire()
		return false
	}
	return association != nil && association.deliver(source, payload)
}

func (p *path) accept() {
	defer p.wg.Done()
	for {
		c, err := p.listener.Accept()
		if err != nil {
			return
		}
		if !p.track(c) {
			continue
		}
		p.wg.Add(1)
		go func() { defer p.wg.Done(); defer p.release(c); p.serve(c) }()
	}
}

// We reuse upstream address/UDP framing and adapters. A short local handshake
// keeps mandatory authentication and delays CONNECT success until dial succeeds.
func (p *path) serve(c net.Conn) {
	c.SetDeadline(time.Now().Add(10 * time.Second))
	var header [2]byte
	if _, err := io.ReadFull(c, header[:]); err != nil || header[0] != 5 || header[1] == 0 {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	hasAuth := false
	for _, method := range methods {
		hasAuth = hasAuth || method == 2
	}
	if !hasAuth {
		c.Write([]byte{5, 255})
		return
	}
	if _, err := c.Write([]byte{5, 2}); err != nil {
		return
	}
	if _, err := io.ReadFull(c, header[:]); err != nil || header[0] != 1 || header[1] == 0 {
		return
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(c, username); err != nil {
		return
	}
	if _, err := io.ReadFull(c, header[:1]); err != nil || header[0] == 0 {
		return
	}
	password := make([]byte, int(header[0]))
	if _, err := io.ReadFull(c, password); err != nil {
		return
	}
	if subtle.ConstantTimeCompare(username, []byte(p.username))&subtle.ConstantTimeCompare(password, []byte(p.password)) != 1 {
		c.Write([]byte{1, 1})
		return
	}
	if _, err := c.Write([]byte{1, 0}); err != nil {
		return
	}
	var command [3]byte
	if _, err := io.ReadFull(c, command[:]); err != nil || command[0] != 5 || command[2] != 0 {
		return
	}
	addr, err := socks5.ReadAddr0(c)
	if err != nil {
		return
	}
	switch command[1] {
	case socks5.CmdConnect:
		metadata := &C.Metadata{NetWork: C.TCP, Type: C.SOCKS5}
		if err := metadata.SetRemoteAddress(addr.String()); err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(p.ctx, 20*time.Second)
		if err := p.resolveMetadata(ctx, metadata); err != nil {
			cancel()
			replySOCKS(c, byte(socks5.ErrHostUnreachable), nil)
			return
		}
		remote, err := p.proxy.DialContext(ctx, metadata)
		cancel()
		if err != nil {
			replySOCKS(c, byte(socks5.ErrHostUnreachable), nil)
			return
		}
		if !p.track(remote) {
			return
		}
		defer p.release(remote)
		if !replySOCKS(c, 0, remote.LocalAddr()) {
			return
		}
		c.SetDeadline(time.Time{})
		N.Relay(c, remote)
	case socks5.CmdUDPAssociate:
		if !p.proxy.SupportUDP() {
			replySOCKS(c, byte(socks5.ErrCommandNotSupported), nil)
			return
		}
		p.serveUDP(c, addr)
	default:
		replySOCKS(c, byte(socks5.ErrCommandNotSupported), nil)
	}
}

func replySOCKS(c net.Conn, status byte, addr net.Addr) bool {
	encoded := socks5.ParseAddrToSocksAddr(addr)
	if encoded == nil {
		encoded = socks5.ParseAddr("127.0.0.1:0")
	}
	_, err := c.Write(append([]byte{5, status, 0}, encoded...))
	return err == nil
}

func (p *path) serveUDP(c net.Conn, requested socks5.Addr) {
	client := requested.UDPAddr()
	if client == nil {
		replySOCKS(c, byte(socks5.ErrAddressNotSupported), nil)
		return
	}
	peerIP := c.RemoteAddr().(*net.TCPAddr).IP
	if !client.IP.IsUnspecified() && !client.IP.Equal(peerIP) {
		replySOCKS(c, byte(socks5.ErrConnectionNotAllowed), nil)
		return
	}
	local, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		replySOCKS(c, byte(socks5.ErrGeneralFailure), nil)
		return
	}
	if !p.track(local) {
		return
	}
	defer p.release(local)
	associationContext, associationCancel := context.WithCancel(p.ctx)
	association := &udpAssociation{local: local, ctx: associationContext, cancel: associationCancel}
	if client.Port != 0 {
		association.setClient(client)
	}
	gateway, accepted := p.registerUDP(association)
	if !accepted {
		association.retire()
		replySOCKS(c, byte(socks5.ErrConnectionNotAllowed), nil)
		return
	}
	defer association.retire()
	defer p.releaseUDP(association)
	if !replySOCKS(c, 0, local.LocalAddr()) {
		return
	}
	c.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() { io.Copy(io.Discard, c); local.Close(); close(done) }()
	defer func() { c.Close(); <-done }()
	var remote C.PacketConn
	var readDone chan struct{}
	defer func() {
		if remote != nil {
			p.release(remote)
			<-readDone
		}
	}()
	buffer := make([]byte, 65535)
	for {
		n, from, err := local.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		if !from.IP.Equal(peerIP) || (client.Port != 0 && from.Port != client.Port) {
			continue
		}
		addr, payload, err := socks5.DecodeUDPPacket(buffer[:n])
		if err != nil {
			continue
		}
		metadata := &C.Metadata{NetWork: C.UDP, Type: C.SOCKS5}
		if err := metadata.SetRemoteAddress(addr.String()); err != nil {
			continue
		}
		if client.Port == 0 {
			client = from
		}
		association.setClient(client)
		if gateway != nil {
			if err = p.resolveMetadata(association.ctx, metadata); err != nil || !gateway.sendDatagram(metadata.UDPAddr().AddrPort(), payload) {
				return
			}
			continue
		}
		if !association.beginDirect() {
			return
		}
		if err = p.resolveMetadata(association.ctx, metadata); err != nil {
			association.endDirect()
			continue
		}
		if remote == nil {
			ctx, cancel := context.WithTimeout(association.ctx, 20*time.Second)
			remote, err = p.proxy.ListenPacketContext(ctx, metadata)
			cancel()
			if err != nil {
				association.endDirect()
				return
			}
			if !p.track(remote) {
				remote = nil
				association.endDirect()
				return
			}
			if !association.setRemote(remote) {
				p.release(remote)
				remote = nil
				association.endDirect()
				return
			}
			readDone = make(chan struct{})
			go func() {
				defer close(readDone)
				incoming := make([]byte, 65535)
				for {
					n, source, err := remote.ReadFrom(incoming)
					if err != nil {
						local.Close()
						return
					}
					packet, err := socks5.EncodeUDPPacket(socks5.ParseAddrToSocksAddr(source), incoming[:n])
					if err != nil {
						continue
					}
					if _, err := local.WriteToUDP(packet, client); err != nil {
						return
					}
				}
			}()
		}
		if _, err := remote.WriteTo(payload, metadata.UDPAddr()); err != nil {
			association.endDirect()
			return
		}
		association.endDirect()
	}
}
