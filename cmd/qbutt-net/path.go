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

type path struct {
	proxy       C.Proxy
	resolver    *pathResolver
	listener    net.Listener
	generation  uint64
	username    string
	password    string
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.Mutex
	connections map[io.Closer]struct{}
	closing     bool
	wg          sync.WaitGroup
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
	p := &path{generation: req.Generation, ctx: ctx, cancel: cancel, connections: make(map[io.Closer]struct{})}
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
	for c := range p.connections {
		c.Close()
	}
	p.mu.Unlock()
	p.proxy.Close()
	p.wg.Wait()
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
		if err = p.resolveMetadata(p.ctx, metadata); err != nil {
			continue
		}
		if remote == nil {
			ctx, cancel := context.WithTimeout(p.ctx, 20*time.Second)
			remote, err = p.proxy.ListenPacketContext(ctx, metadata)
			cancel()
			if err != nil {
				return
			}
			if !p.track(remote) {
				remote = nil
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
			return
		}
	}
}
