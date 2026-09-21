package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/metacubex/mihomo/common/structure"
	"gopkg.in/yaml.v3"
)

const maxConfigBytes = 2 * 1024 * 1024

func validLabel(value string) bool {
	return value != "" && len(value) <= 128 && strings.IndexFunc(value, unicode.IsControl) == -1
}

// Identity describes the configured server, not a probed egress. Different
// names, protocols, ports and credentials on that server remain one edge.
func configuredServerID(proxy map[string]any) string {
	host, ok := proxy["server"].(string)
	if !ok {
		return ""
	}
	var canonical string
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
			return ""
		}
		canonical = address.Unmap().String()
	} else {
		name, err := dnsName(host)
		if err != nil {
			return ""
		}
		canonical = strings.TrimSuffix(name, ".")
	}
	digest := sha256.Sum256([]byte("qbutt-configured-server-v1\x00" + canonical))
	return hex.EncodeToString(digest[:])
}

// This parses data only. In particular it never calls Mihomo config.Parse,
// executor.ApplyConfig, provider loaders, or any system listener/TUN setup.
func readProxies(filename string) ([]map[string]any, *controlError) {
	if !filepath.IsAbs(filename) || strings.HasPrefix(filepath.VolumeName(filename), `\\`) {
		return nil, failure("absolute_config_path_required")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, failure("config_unreadable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, failure("config_not_regular")
	}
	if info.Size() > maxConfigBytes {
		return nil, failure("config_limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return nil, failure("config_unreadable")
	}
	if len(data) > maxConfigBytes {
		return nil, failure("config_limit")
	}
	var document struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, failure("invalid_config")
	}
	if len(document.Proxies) == 0 {
		return nil, failure("no_proxies")
	}
	if len(document.Proxies) > 1024 {
		return nil, failure("proxy_limit")
	}
	names := make(map[string]bool)
	for _, proxy := range document.Proxies {
		name, _ := proxy["name"].(string)
		kind, _ := proxy["type"].(string)
		if !validLabel(name) || !validLabel(kind) || names[name] {
			return nil, failure("invalid_proxy_identity")
		}
		names[name] = true
	}
	return document.Proxies, nil
}

func selectedProxy(req request, proxies []map[string]any) (map[string]any, *controlError) {
	for _, proxy := range proxies {
		if proxy["name"] != req.ProxyName {
			continue
		}
		// Only standalone network adapters are imported. System integration,
		// recursive routing, direct bypass, and group/provider execution are absent.
		switch proxy["type"] {
		case "ss", "ssr", "socks5", "http", "vmess", "vless", "snell", "trojan", "hysteria", "hysteria2", "shadowquic", "gost-relay", "ssh", "mieru", "anytls", "sudoku", "masque", "trusttunnel":
		default:
			return nil, failure("unsupported_proxy_type")
		}
		if !inlineCredentials(proxy, proxy["type"] == "masque") {
			return nil, failure("external_credentials_not_supported")
		}
		if !pathDNSOptions(proxy) {
			return nil, failure("auxiliary_dns_not_supported")
		}
		for key, value := range proxy {
			// Match the upstream decoder's case-insensitive underscore aliases.
			switch strings.ToLower(strings.ReplaceAll(key, "_", "-")) {
			case "protocol", "obfs-protocol":
				if proxy["type"] == "hysteria" && value == "faketcp" {
					return nil, failure("unbound_transport_not_supported")
				}
			case "dialer-proxy":
				if value != "" {
					return nil, failure("proxy_chain_not_supported")
				}
				delete(proxy, key)
			case "interface-name", "routing-mark", "dns", "remote-dns-resolve":
				delete(proxy, key)
			}
		}
		// The parent owns physical binding. Subscription routing overrides are
		// never authoritative, while the adapter's protocol fields are preserved.
		proxy["interface-name"] = req.InterfaceName
		return proxy, nil
	}
	return nil, failure("proxy_not_found")
}

// Dynamic ECH and realm discovery have their own global/auxiliary DNS paths.
// Inline ECH remains usable; the selected adapter cannot import a second DNS
// policy or auxiliary TLS traffic generator behind the parent's path contract.
func pathDNSOptions(value any) bool {
	switch value := value.(type) {
	case map[string]any:
		for key, field := range value {
			normalized := strings.ToLower(strings.ReplaceAll(key, "_", "-"))
			switch normalized {
			case "ech-opts", "realm-opts":
				mapping, ok := field.(map[string]any)
				if !ok {
					return false
				}
				var option struct {
					Enable bool   `proxy:"enable"`
					Config string `proxy:"config"`
				}
				decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
				if decoder.Decode(mapping, &option) != nil {
					return false
				}
				if option.Enable && (normalized == "realm-opts" || option.Config == "") {
					return false
				}
			case "tlsmirror-opts":
				if mapping, ok := field.(map[string]any); !ok || len(mapping) != 0 {
					return false
				}
			}
			if !pathDNSOptions(field) {
				return false
			}
		}
	case []any:
		for _, field := range value {
			if !pathDNSOptions(field) {
				return false
			}
		}
	}
	return true
}

// Mihomo accepts certificate/private-key filenames and starts file watchers.
// Subscription data must not access another application's local credentials.
func inlineCredentials(value any, masque bool) bool {
	switch value := value.(type) {
	case map[string]any:
		for key, field := range value {
			normalized := strings.ToLower(strings.ReplaceAll(key, "_", "-"))
			if normalized == "certificate" || (normalized == "private-key" && !masque) {
				if field == nil || field == "" {
					continue
				}
				text, ok := field.(string)
				if !ok {
					return false
				}
				block, _ := pem.Decode([]byte(text))
				if block == nil {
					return false
				}
			}
			if !inlineCredentials(field, false) {
				return false
			}
		}
	case map[any]any:
		// Proxy option objects must have string keys; do not bypass validation
		// through the YAML decoder's mixed-key representation.
		return false
	case []any:
		for _, field := range value {
			if !inlineCredentials(field, false) {
				return false
			}
		}
	}
	return true
}
