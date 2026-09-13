// qbutt-net exposes selected Mihomo adapters to its owning desktop process.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	stdlog "log"
	"os"
	"sort"
	"sync"

	mierulog "github.com/enfein/mieru/v3/pkg/log"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/sirupsen/logrus"
)

const (
	protocolVersion  = 3
	maxFrameBytes    = 65536
	upstreamRevision = "d3ec342d441b086ec4318332f59dd05d8a2b5697"
)

type request struct {
	Version       int             `json:"v"`
	ID            uint64          `json:"id"`
	Method        string          `json:"method"`
	ConfigPath    string          `json:"configPath"`
	ProxyName     string          `json:"proxyName"`
	PathID        string          `json:"pathId"`
	Generation    uint64          `json:"generation"`
	InterfaceName string          `json:"interfaceName"`
	DNS           *dnsPolicy      `json:"dns"`
	Host          string          `json:"host"`
	Family        string          `json:"family"`
	Gateway       *gatewayOptions `json:"gateway"`
}

type response struct {
	Version int           `json:"v"`
	ID      uint64        `json:"id"`
	Result  any           `json:"result,omitempty"`
	Error   *controlError `json:"error,omitempty"`
}

type controlError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type controlWriter struct {
	mu sync.Mutex
}

func (writer *controlWriter) write(value any, id uint64) error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data)+1 > maxFrameBytes {
		data, _ = json.Marshal(response{Version: protocolVersion, ID: id, Error: failure("response_limit")})
	}
	_, err = os.Stdout.Write(append(data, '\n'))
	return err
}

// Only fixed diagnostics cross IPC. Adapter/parser errors may contain credentials.
func failure(code string) *controlError {
	return &controlError{Code: code, Message: code}
}

func main() {
	// Upstream logs may contain addresses and transport secrets. They must never
	// share stdout with the protocol, or escape to diagnostic exports.
	logrus.SetOutput(io.Discard)
	stdlog.SetOutput(io.Discard)
	mierulog.SetOutput(io.Discard)
	// No adapter in this child may fall through to process/system DNS. Actual
	// resolvers are passed per path; globals are only a closed default boundary.
	blocked := &pathResolver{}
	resolver.DefaultResolver = blocked
	resolver.ProxyServerHostResolver = blocked
	resolver.DirectHostResolver = blocked
	resolver.SystemResolver = blocked
	resolver.DisableIPv6 = false
	if len(os.Args) != 2 || os.Args[1] != "--stdio" {
		fmt.Fprintln(os.Stderr, "qbutt-net requires --stdio and private parent pipes")
		os.Exit(2)
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "qbutt-net control channel terminated")
		os.Exit(1)
	}
}

func run() error {
	paths := make(map[string]*path)
	output := &controlWriter{}
	defer func() {
		for _, p := range paths {
			p.close()
		}
	}()
	hello := false
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), maxFrameBytes)
	for scanner.Scan() {
		var req request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			return err
		}
		reply := response{Version: protocolVersion, ID: req.ID}
		var activate *gatewayClient
		switch {
		case req.Version != protocolVersion:
			reply.Error = failure("protocol_mismatch")
		case req.ID == 0 || req.ID > 9007199254740991:
			reply.Error = failure("invalid_request_id")
		case req.Method == "hello":
			hello = true
			reply.Result = map[string]any{"protocol": protocolVersion, "name": "qbutt-net", "upstreamRevision": upstreamRevision, "maxFrameBytes": maxFrameBytes}
		case !hello:
			reply.Error = failure("hello_required")
		case req.Method == "list":
			proxies, err := readProxies(req.ConfigPath)
			if err != nil {
				reply.Error = err
				break
			}
			entries := make([]map[string]string, 0, len(proxies))
			for _, proxy := range proxies {
				entries = append(entries, map[string]string{"name": proxy["name"].(string), "type": proxy["type"].(string)})
			}
			reply.Result = map[string]any{"proxies": entries}
		case req.Method == "status":
			ids := make([]string, 0, len(paths))
			for id := range paths {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			entries := make([]pathStatus, 0, len(ids))
			for _, id := range ids {
				p := paths[id]
				entries = append(entries, pathStatus{PathID: id, Generation: p.generation, Wire: p.wire.snapshot()})
			}
			reply.Result = map[string]any{"paths": entries}
		case req.Method == "open":
			if !validLabel(req.PathID) || req.Generation == 0 || req.Generation > 9007199254740991 {
				reply.Error = failure("invalid_path")
				break
			}
			if _, exists := paths[req.PathID]; exists {
				reply.Error = failure("path_exists")
				break
			}
			if len(paths) >= 8 {
				reply.Error = failure("path_limit")
				break
			}
			p, err := openPath(req)
			if err != nil {
				reply.Error = err
				break
			}
			paths[req.PathID] = p
			reply.Result = p.endpoint(req)
		case req.Method == "resolve":
			p, exists := paths[req.PathID]
			if !exists {
				reply.Error = failure("path_not_found")
				break
			}
			if p.generation != req.Generation {
				reply.Error = failure("generation_mismatch")
				break
			}
			if !validFamily(req.Family) {
				reply.Error = failure("invalid_dns_family")
				break
			}
			addresses, err := p.resolver.lookup(p.ctx, req.Host, req.Family)
			if err != nil {
				reply.Error = failure("path_dns_failed")
				break
			}
			reply.Result = map[string]any{"addresses": addresses}
		case req.Method == "gateway.open":
			p, exists := paths[req.PathID]
			if !exists {
				reply.Error = failure("path_not_found")
				break
			}
			if p.generation != req.Generation {
				reply.Error = failure("generation_mismatch")
				break
			}
			if p.gatewayOccupied() {
				reply.Error = failure("gateway_exists")
				break
			}
			gateway, err := openGateway(p, req.PathID, req.Generation, req.Gateway, output)
			if err != nil {
				reply.Error = err
				break
			}
			if !p.installGateway(gateway) {
				gateway.close()
				reply.Error = failure("gateway_exists")
				break
			}
			reply.Result = gateway.endpoint()
			activate = gateway
		case req.Method == "gateway.renew":
			p, exists := paths[req.PathID]
			if !exists {
				reply.Error = failure("path_not_found")
				break
			}
			if p.generation != req.Generation {
				reply.Error = failure("generation_mismatch")
				break
			}
			gateway := p.currentGateway()
			if gateway == nil {
				reply.Error = failure("gateway_not_open")
				break
			}
			result, err := gateway.renew()
			if err != nil {
				reply.Error = err
				break
			}
			reply.Result = result
		case req.Method == "gateway.close":
			p, exists := paths[req.PathID]
			if !exists {
				reply.Error = failure("path_not_found")
				break
			}
			if p.generation != req.Generation {
				reply.Error = failure("generation_mismatch")
				break
			}
			gateway := p.currentGateway()
			if gateway == nil {
				reply.Error = failure("gateway_not_open")
				break
			}
			closeError := gateway.release()
			gateway.close()
			if closeError != nil {
				reply.Error = closeError
			} else {
				reply.Result = struct{}{}
			}
		case req.Method == "close":
			p, exists := paths[req.PathID]
			if !exists {
				reply.Error = failure("path_not_found")
				break
			}
			if p.generation != req.Generation {
				reply.Error = failure("generation_mismatch")
				break
			}
			p.close()
			delete(paths, req.PathID)
			reply.Result = struct{}{}
		case req.Method == "shutdown":
			for id, p := range paths {
				p.close()
				delete(paths, id)
			}
			reply.Result = struct{}{}
		default:
			reply.Error = failure("unknown_method")
		}
		if err := output.write(reply, req.ID); err != nil {
			return err
		}
		if activate != nil {
			activate.activate()
		}
		if req.Method == "shutdown" && reply.Error == nil {
			return nil
		}
	}
	return scanner.Err()
}
