package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

const dnsTimeout = 5 * time.Second

var errDNS = errors.New("path_dns_failed")

type dnsPolicy struct {
	Server          string `json:"server"`
	BootstrapServer string `json:"bootstrapServer"`
	Family          string `json:"family"`
}

type dnsAnswer struct {
	addresses []netip.Addr
	expires   time.Time
}

// A resolver belongs to one path generation. Bootstrap has one allowed name;
// torrent queries use the selected adapter. Neither uses OS DNS or hosts files.
type pathResolver struct {
	owner    *path
	server   netip.AddrPort
	onlyHost string
	family   string
	dial     func(context.Context, string) (net.Conn, error)
	mu       sync.Mutex
	cache    map[string]dnsAnswer
}

func validFamily(family string) bool {
	return family == "ipv4" || family == "ipv6" || family == "dual"
}

func dnsServer(value string) (netip.AddrPort, error) {
	address, err := netip.ParseAddrPort(value)
	if err != nil || address.Port() == 0 || address.Addr().IsUnspecified() || address.Addr().IsMulticast() || address.Addr().Zone() != "" {
		return netip.AddrPort{}, errDNS
	}
	return address, nil
}

func dnsName(host string) (string, error) {
	host, err := idna.Lookup.ToASCII(strings.TrimSuffix(host, "."))
	if err != nil || len(host) == 0 || len(host) > 253 {
		return "", errDNS
	}
	name := strings.ToLower(host) + "."
	if _, valid := dns.IsDomainName(name); !valid || strings.ContainsAny(name, "\\\x00\r\n") {
		return "", errDNS
	}
	return name, nil
}

func boundResolver(owner *path, server netip.AddrPort, family, interfaceName string) *pathResolver {
	physical := dialer.NewDialer(dialer.WithInterface(interfaceName), dialer.WithResolver(&pathResolver{}), dialer.WithFallbackBind(false))
	return &pathResolver{owner: owner, server: server, family: family,
		dial: func(ctx context.Context, address string) (net.Conn, error) {
			network := "tcp4"
			if server.Addr().Is6() {
				network = "tcp6"
			}
			return physical.DialContext(ctx, network, address)
		}}
}

func resolveNative(req request) ([]netip.Addr, *controlError) {
	if !validLabel(req.PathID) || req.Generation == 0 || req.Generation > 9007199254740991 {
		return nil, failure("invalid_path")
	}
	if !validLabel(req.InterfaceName) {
		return nil, failure("interface_required")
	}
	iface, err := net.InterfaceByName(req.InterfaceName)
	if err != nil || iface.Flags&net.FlagUp == 0 {
		return nil, failure("interface_unavailable")
	}
	if req.DNS == nil {
		return nil, failure("dns_policy_required")
	}
	server, err := dnsServer(req.DNS.Server)
	_, bootstrapErr := dnsServer(req.DNS.BootstrapServer)
	if err != nil || bootstrapErr != nil || !validFamily(req.DNS.Family) {
		return nil, failure("invalid_dns_policy")
	}
	if !validFamily(req.Family) {
		return nil, failure("invalid_dns_family")
	}
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()
	// Own only this query's tracked sockets. No proxy or payload listener exists,
	// and no result/cache survives the request's parent-supplied generation.
	owner := &path{ctx: ctx, connections: make(map[io.Closer]struct{})}
	resolver := boundResolver(owner, server, req.DNS.Family, req.InterfaceName)
	addresses, err := resolver.lookup(ctx, req.Host, req.Family)
	if err != nil {
		return nil, failure("path_dns_failed")
	}
	return addresses, nil
}

// Mihomo's Resolver.Invalid() means usable, despite its historical name.
func (r *pathResolver) Invalid() bool    { return true }
func (r *pathResolver) ResetConnection() {}
func (r *pathResolver) ClearCache() {
	r.mu.Lock()
	r.cache = nil
	r.mu.Unlock()
}
func (r *pathResolver) ResolveECH(context.Context, string) ([]byte, error) { return nil, errDNS }
func (r *pathResolver) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookup(ctx, host, r.family)
}
func (r *pathResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookup(ctx, host, "ipv4")
}
func (r *pathResolver) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookup(ctx, host, "ipv6")
}

func (r *pathResolver) lookup(ctx context.Context, host, family string) ([]netip.Addr, error) {
	if r.owner == nil || r.owner.ctx.Err() != nil || ctx.Err() != nil || !validFamily(family) {
		return nil, errDNS
	}
	if r.family != "dual" {
		if family != "dual" && family != r.family {
			return nil, errDNS
		}
		family = r.family
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Zone() != "" || (family == "ipv4" && !ip.Is4()) || (family == "ipv6" && !ip.Is6()) {
			return nil, errDNS
		}
		return []netip.Addr{ip}, nil
	}
	name, err := dnsName(host)
	if err != nil || (r.onlyHost != "" && r.onlyHost != name) {
		return nil, errDNS
	}
	key := family + ":" + name
	r.mu.Lock()
	cached, exists := r.cache[key]
	r.mu.Unlock()
	if exists && time.Now().Before(cached.expires) {
		return append([]netip.Addr(nil), cached.addresses...), nil
	}
	ctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()
	types := []uint16{dns.TypeA, dns.TypeAAAA}
	if family == "ipv4" {
		types = types[:1]
	} else if family == "ipv6" {
		types = types[1:]
	}
	answers := make(chan dnsAnswer, len(types))
	for _, qtype := range types {
		go func(qtype uint16) { answer, _ := r.query(ctx, name, qtype); answers <- answer }(qtype)
	}
	answer := dnsAnswer{expires: time.Now().Add(time.Minute)}
	for range types {
		part := <-answers
		answer.addresses = append(answer.addresses, part.addresses...)
		if len(part.addresses) > 0 && part.expires.Before(answer.expires) {
			answer.expires = part.expires
		}
	}
	if len(answer.addresses) == 0 || len(answer.addresses) > 64 || r.owner.ctx.Err() != nil || ctx.Err() != nil {
		return nil, errDNS
	}
	// Keep deterministic IPv4 preference, with every returned address available
	// to the parent for an explicit family choice.
	slices.SortFunc(answer.addresses, func(a, b netip.Addr) int { return a.Compare(b) })
	answer.addresses = slices.Compact(answer.addresses)
	r.mu.Lock()
	if r.cache == nil || len(r.cache) >= 128 {
		r.cache = make(map[string]dnsAnswer)
	}
	r.cache[key] = answer
	r.mu.Unlock()
	return append([]netip.Addr(nil), answer.addresses...), nil
}

func (r *pathResolver) query(ctx context.Context, name string, qtype uint16) (dnsAnswer, error) {
	answer := dnsAnswer{expires: time.Now().Add(time.Minute)}
	visited := make(map[string]bool)
	for hop := 0; hop < 8; hop++ {
		if visited[name] {
			return dnsAnswer{}, errDNS
		}
		visited[name] = true
		query := new(dns.Msg)
		query.SetQuestion(name, qtype)
		message, err := r.ExchangeContext(ctx, query)
		if err != nil || message.Rcode != dns.RcodeSuccess || message.Truncated {
			return dnsAnswer{}, errDNS
		}
		next := ""
		for _, record := range message.Answer {
			if !strings.EqualFold(record.Header().Name, name) || record.Header().Class != dns.ClassINET {
				continue
			}
			expires := time.Now().Add(time.Duration(record.Header().Ttl) * time.Second)
			if expires.Before(answer.expires) {
				answer.expires = expires
			}
			switch record := record.(type) {
			case *dns.CNAME:
				next, err = dnsName(record.Target)
				if err != nil {
					return dnsAnswer{}, errDNS
				}
			case *dns.A:
				if qtype == dns.TypeA {
					if ip, ok := netip.AddrFromSlice(record.A); ok && ip.Unmap().Is4() {
						answer.addresses = append(answer.addresses, ip.Unmap())
					}
				}
			case *dns.AAAA:
				if qtype == dns.TypeAAAA {
					if ip, ok := netip.AddrFromSlice(record.AAAA); ok && ip.Is6() && !ip.Is4In6() {
						answer.addresses = append(answer.addresses, ip.Unmap())
					}
				}
			}
		}
		if len(answer.addresses) > 0 {
			return answer, nil
		}
		if next == "" {
			return dnsAnswer{}, errDNS
		}
		name = next
	}
	return dnsAnswer{}, errDNS
}

func (r *pathResolver) ExchangeContext(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	if r.owner == nil || r.dial == nil || r.owner.ctx.Err() != nil || len(query.Question) != 1 {
		return nil, errDNS
	}
	question := query.Question[0]
	if question.Qclass != dns.ClassINET || (question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA) {
		return nil, errDNS
	}
	ctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()
	stop := context.AfterFunc(r.owner.ctx, cancel)
	defer stop()
	connection, err := r.dial(ctx, r.server.String())
	if err != nil {
		return nil, errDNS
	}
	if !r.owner.track(connection) {
		return nil, errDNS
	}
	defer r.owner.release(connection)
	closeOnCancel := context.AfterFunc(ctx, func() { connection.Close() })
	defer closeOnCancel()
	client := dns.Client{Net: "tcp", Timeout: dnsTimeout}
	reply, _, err := client.ExchangeWithConnContext(ctx, query, &dns.Conn{Conn: connection})
	if err != nil || !reply.Response || reply.Opcode != dns.OpcodeQuery || len(reply.Question) != 1 || reply.Question[0] != question {
		return nil, errDNS
	}
	return reply, nil
}

type serverDialer struct {
	dialer.Dialer
	bootstrap *pathResolver
}

func (d serverDialer) Resolver() resolver.Resolver { return d.bootstrap }

func (d serverDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.bootstrap.owner.ctx.Err() != nil {
		return nil, errDNS
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(d.bootstrap.owner.ctx, cancel)
	defer stop()
	return d.Dialer.DialContext(ctx, network, address)
}

func (d serverDialer) ListenPacket(ctx context.Context, network, address string, destination netip.AddrPort) (net.PacketConn, error) {
	if d.bootstrap.owner.ctx.Err() != nil {
		return nil, errDNS
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(d.bootstrap.owner.ctx, cancel)
	defer stop()
	return d.Dialer.ListenPacket(ctx, network, address, destination)
}

func (p *path) resolveMetadata(ctx context.Context, metadata *C.Metadata) error {
	host := metadata.Host
	if host == "" {
		host = metadata.DstIP.String()
	}
	addresses, err := p.resolver.lookup(ctx, host, p.resolver.family)
	if err != nil {
		return err
	}
	metadata.Host = ""
	metadata.DstIP = addresses[0]
	return nil
}
