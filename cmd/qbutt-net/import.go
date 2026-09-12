package main

import (
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

const maxConfigBytes = 2 * 1024 * 1024

func validLabel(value string) bool {
	return value != "" && len(value) <= 128 && strings.IndexFunc(value, unicode.IsControl) == -1
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

func selectedProxy(req request) (map[string]any, *controlError) {
	proxies, err := readProxies(req.ConfigPath)
	if err != nil {
		return nil, err
	}
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
		for key, value := range proxy {
			// Match the upstream decoder's case-insensitive underscore aliases.
			switch strings.ToLower(strings.ReplaceAll(key, "_", "-")) {
			case "dialer-proxy":
				if value != "" {
					return nil, failure("proxy_chain_not_supported")
				}
				delete(proxy, key)
			case "interface-name", "routing-mark":
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
