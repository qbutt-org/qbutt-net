// qbutt-net exposes selected Mihomo adapters to its owning desktop process.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	stdlog "log"
	"os"

	mierulog "github.com/enfein/mieru/v3/pkg/log"
	"github.com/sirupsen/logrus"
)

const (
	protocolVersion  = 1
	maxFrameBytes    = 65536
	upstreamRevision = "d3ec342d441b086ec4318332f59dd05d8a2b5697"
)

type request struct {
	Version       int    `json:"v"`
	ID            uint64 `json:"id"`
	Method        string `json:"method"`
	ConfigPath    string `json:"configPath"`
	ProxyName     string `json:"proxyName"`
	PathID        string `json:"pathId"`
	Generation    uint64 `json:"generation"`
	InterfaceName string `json:"interfaceName"`
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
		data, err := json.Marshal(reply)
		if err != nil {
			return err
		}
		if len(data)+1 > maxFrameBytes {
			data, _ = json.Marshal(response{Version: protocolVersion, ID: req.ID, Error: failure("response_limit")})
		}
		if _, err := os.Stdout.Write(append(data, '\n')); err != nil {
			return err
		}
		if req.Method == "shutdown" && reply.Error == nil {
			return nil
		}
	}
	return scanner.Err()
}
