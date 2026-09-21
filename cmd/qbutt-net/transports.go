package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/miekg/dns"
)

const transportProbeCooldown = 30 * time.Second

type transportProtocol uint8

const (
	transportTCP transportProtocol = iota
	transportUDP
)

type transportCandidate struct {
	name     string
	mapping  map[string]any
	revision [32]byte
}

type transportStatus struct {
	State       string `json:"state"`
	Recommended string `json:"recommended"`
}

// Protected by the path mutex. A recommendation belongs to this exact path
// generation; only the parent can retire it and authorize a replacement.
type transportHealth struct {
	checking  bool
	lastProbe time.Time
	protocol  transportProtocol
	flows     [2]transportFlow
	status    transportStatus
}

type transportFlow struct {
	upload       monotonicCounter
	download     monotonicCounter
	pending      bool
	dialFailed   bool
	lastProgress time.Time
	downloaded   uint64
	uploaded     uint64
}

func selectedTransports(req request) ([]transportCandidate, *controlError) {
	if len(req.ReserveNames) > 3 {
		return nil, failure("transport_limit")
	}
	if len(req.ReserveServerIDs) != len(req.ReserveNames) {
		return nil, failure("invalid_transport_selection")
	}
	proxies, readErr := readProxies(req.ConfigPath)
	if readErr != nil {
		return nil, readErr
	}
	names := append([]string{req.ProxyName}, req.ReserveNames...)
	seen := make(map[string]bool)
	result := make([]transportCandidate, 0, len(names))
	for _, name := range names {
		if !validLabel(name) || seen[name] {
			return nil, failure("invalid_transport_selection")
		}
		seen[name] = true
		selected := req
		selected.ProxyName = name
		if name != req.ProxyName {
			selected.ConfiguredServerID = req.ReserveServerIDs[name]
		}
		mapping, err := selectedProxy(selected, proxies)
		if err != nil {
			return nil, err
		}
		if selected.ConfiguredServerID == "" {
			return nil, failure("configured_server_id_required")
		}
		if configuredServerID(mapping) != selected.ConfiguredServerID {
			return nil, failure("server_identity_changed")
		}
		encoded, encodeErr := json.Marshal(mapping)
		if encodeErr != nil {
			return nil, failure("adapter_rejected")
		}
		result = append(result, transportCandidate{name: name, mapping: mapping, revision: sha256.Sum256(encoded)})
	}
	return result, nil
}

func (p *path) unchangedTransports() ([]transportCandidate, *controlError) {
	candidates, err := selectedTransports(p.openRequest)
	if err != nil || len(candidates) != len(p.transports) {
		return nil, failure("transport_config_changed")
	}
	for index, candidate := range candidates {
		if candidate.name != p.transports[index].name || candidate.revision != p.transports[index].revision {
			return nil, failure("transport_config_changed")
		}
	}
	return candidates, nil
}

func (p *path) replacementRequest(req request) (request, []transportCandidate, *controlError) {
	candidates, err := p.unchangedTransports()
	if err != nil {
		return request{}, nil, err
	}
	found := false
	for _, candidate := range candidates[1:] {
		found = found || candidate.name == req.ProxyName
	}
	if !found {
		return request{}, nil, failure("invalid_transport_selection")
	}
	next := p.openRequest
	next.Generation = req.NextGeneration
	next.ProxyName = req.ProxyName
	next.ReserveNames = nil
	next.ReserveServerIDs = make(map[string]string)
	ordered := make([]transportCandidate, 1, len(candidates))
	for _, candidate := range candidates {
		if candidate.name == next.ProxyName {
			ordered[0] = candidate
			next.ConfiguredServerID = configuredServerID(candidate.mapping)
		} else {
			next.ReserveNames = append(next.ReserveNames, candidate.name)
			next.ReserveServerIDs[candidate.name] = configuredServerID(candidate.mapping)
			ordered = append(ordered, candidate)
		}
	}
	return next, ordered, nil
}

func (p *path) transportDialResult(protocol transportProtocol, err error) {
	if err == nil || len(p.transports) < 2 || p.ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.health.checking {
		return
	}
	p.health.flows[protocol].dialFailed = true
}

func (p *path) transportStatus() transportStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.transports) < 2 {
		return transportStatus{State: "disabled"}
	}
	now := time.Now()
	for protocol := transportTCP; protocol <= transportUDP; protocol++ {
		flow := &p.health.flows[protocol]
		downloaded := flow.download.value.Load()
		progress := downloaded != flow.downloaded
		if progress {
			flow.downloaded = downloaded
			flow.lastProgress = now
			flow.pending = false
			// Traffic on a different protocol cannot conceal a failed UDP/TCP
			// round trip or withdraw its already confirmed recommendation.
			if p.health.status.State != "config-changed" && ((!p.health.checking && p.health.status.State != "ready" && p.health.status.State != "unavailable") || p.health.protocol == protocol) {
				p.health.status = transportStatus{State: "active"}
			}
		}
		// Local writes never prove remote delivery, particularly for UDP.
		if uploaded := flow.upload.value.Load(); uploaded != flow.uploaded {
			flow.uploaded = uploaded
			flow.pending = flow.pending || !progress
		}
	}
	if p.health.status.State == "" {
		p.health.status.State = "unknown"
	}
	if p.closing || p.health.checking || p.health.status.State == "ready" || p.health.status.State == "config-changed" {
		return p.health.status
	}
	// Give the other protocol first chance after a completed check, so a
	// stream of TCP dial failures cannot starve a pending UDP diagnosis.
	for offset := transportProtocol(1); offset <= 2; offset++ {
		protocol := (p.health.protocol + offset) % 2
		flow := &p.health.flows[protocol]
		if (flow.pending || flow.dialFailed) && now.Sub(p.health.lastProbe) >= transportProbeCooldown && now.Sub(flow.lastProgress) >= 3*time.Second {
			flow.pending = false
			flow.dialFailed = false
			p.health.checking = true
			p.health.lastProbe = now
			p.health.protocol = protocol
			p.health.status = transportStatus{State: "checking"}
			p.wg.Add(1)
			go p.checkTransports(protocol, flow.downloaded)
			break
		}
	}
	return p.health.status
}

func (p *path) probeReachability(ctx context.Context, protocol transportProtocol) bool {
	query := new(dns.Msg)
	query.SetQuestion(".", dns.TypeA)
	// Even NXDOMAIN/REFUSED is a DNS response carried by this adapter. We are
	// measuring a round trip to the configured resolver, not resolving a new
	// health-service domain or claiming the whole server is up/down.
	if protocol == transportTCP {
		_, err := p.resolver.ExchangeContext(ctx, query)
		return err == nil
	}
	if !p.proxy.SupportUDP() {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()
	metadata := &C.Metadata{NetWork: C.UDP, Type: C.SOCKS5}
	if metadata.SetRemoteAddress(p.resolver.server.String()) != nil {
		return false
	}
	connection, err := p.proxy.ListenPacketContext(ctx, metadata)
	if err != nil || !p.track(connection) {
		return false
	}
	defer p.release(connection)
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	connection.SetDeadline(deadline)
	packet, err := query.Pack()
	if err != nil {
		return false
	}
	if _, err = connection.WriteTo(packet, net.UDPAddrFromAddrPort(p.resolver.server)); err != nil {
		return false
	}
	buffer := make([]byte, 4096)
	size, source, err := connection.ReadFrom(buffer)
	if err != nil || source == nil || source.String() != p.resolver.server.String() {
		return false
	}
	reply := new(dns.Msg)
	return reply.Unpack(buffer[:size]) == nil && reply.Id == query.Id && reply.Response && reply.Opcode == dns.OpcodeQuery && len(reply.Question) == 1 && reply.Question[0] == query.Question[0]
}

func (p *path) checkTransports(protocol transportProtocol, startDownloaded uint64) {
	defer p.wg.Done()
	status := transportStatus{State: "reachable"}
	if !p.probeReachability(p.ctx, protocol) {
		status.State = "unavailable"
		candidates, err := p.unchangedTransports()
		if err != nil {
			status.State = "config-changed"
		} else {
			for _, candidate := range candidates[1:] {
				if p.ctx.Err() != nil {
					break
				}
				req := p.openRequest
				req.ProxyName = candidate.name
				req.ConfiguredServerID = req.ReserveServerIDs[candidate.name]
				probe, err := newPath(req, candidate.mapping)
				if err != nil {
					continue
				}
				stop := context.AfterFunc(p.ctx, probe.cancel)
				reachable := probe.probeReachability(probe.ctx, protocol)
				stop()
				probe.close()
				if reachable {
					status = transportStatus{State: "ready", Recommended: candidate.name}
					break
				}
			}
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.health.checking = false
	flow := &p.health.flows[protocol]
	if !p.closing && p.ctx.Err() == nil && !flow.lastProgress.After(p.health.lastProbe) && startDownloaded == flow.download.value.Load() {
		p.health.status = status
	}
}
