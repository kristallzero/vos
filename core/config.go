// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 VoS contributors.

// Package core provides the headless VoS engine for CLI and future platform hosts.
package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

type Config struct {
	Version  int         `json:"version"`
	Mode     string      `json:"mode"`
	IPMode   string      `json:"ip_mode,omitempty"`
	LogLevel string      `json:"log_level"`
	SSH      SSHConfig   `json:"ssh"`
	Proxy    ProxyConfig `json:"proxy"`
	TUN      TUNConfig   `json:"tun"`
	DNS      DNSConfig   `json:"dns"`
	Routes   RouteConfig `json:"routes"`
}
type SSHConfig struct {
	Server         string   `json:"server"`
	Port           uint16   `json:"port"`
	User           string   `json:"user"`
	PrivateKeyPath string   `json:"private_key_path"`
	PassphraseEnv  string   `json:"passphrase_env,omitempty"`
	HostKeys       []string `json:"host_keys"`
	Interface      string   `json:"interface,omitempty"`
	RelayPort      uint16   `json:"relay_port"`
}
type ProxyConfig struct {
	Enabled bool   `json:"enabled"`
	Listen  string `json:"listen"`
	Port    uint16 `json:"port"`
}
type TUNConfig struct {
	Name    string   `json:"name,omitempty"`
	Address []string `json:"address"`
	MTU     uint32   `json:"mtu"`
}
type DNSConfig struct {
	Direct     string `json:"direct"`
	Tunnel     string `json:"tunnel"`
	DirectPort uint16 `json:"direct_port"`
	TunnelPort uint16 `json:"tunnel_port"`
}
type RouteConfig struct {
	BypassPrivate      bool     `json:"bypass_private"`
	BypassRU           bool     `json:"bypass_ru"`
	ForceTunnelDomains []string `json:"force_tunnel_domains,omitempty"`
	ForceTunnelIPs     []string `json:"force_tunnel_ips,omitempty"`
	ForceDirectDomains []string `json:"force_direct_domains,omitempty"`
	ForceDirectIPs     []string `json:"force_direct_ips,omitempty"`
	RuleFile           string   `json:"rule_file,omitempty"`
}
type RelayConfig struct {
	Version  int    `json:"version"`
	Listen   string `json:"listen"`
	Port     uint16 `json:"port"`
	LogLevel string `json:"log_level"`
	DNS      string `json:"dns"`
}

func DefaultConfig() Config {
	return Config{Version: 1, Mode: "proxy", IPMode: "ipv4_only", LogLevel: "info",
		SSH:    SSHConfig{Port: 443, RelayPort: 10819, PassphraseEnv: "VOS_KEY_PASSPHRASE"},
		Proxy:  ProxyConfig{Enabled: true, Listen: "127.0.0.1", Port: 10818},
		TUN:    TUNConfig{Address: []string{"172.31.255.1/30", "fdfe:dcba:9876::1/126"}, MTU: 1400},
		DNS:    DNSConfig{Direct: "77.88.8.8", Tunnel: "1.1.1.1", DirectPort: 53, TunnelPort: 53},
		Routes: RouteConfig{BypassPrivate: true, BypassRU: true}}
}
func DefaultRelayConfig() RelayConfig {
	return RelayConfig{Version: 1, Listen: "127.0.0.1", Port: 10819, LogLevel: "info", DNS: "1.1.1.1"}
}
func DecodeStrict(data []byte, into any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(into); err != nil {
		return err
	}
	if err := d.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("expected one JSON document")
	}
	return nil
}
func LoadConfig(path string) (Config, error) {
	c := DefaultConfig()
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err = DecodeStrict(b, &c); err != nil {
		return c, err
	}
	c.SSH.PrivateKeyPath, err = expandPath(c.SSH.PrivateKeyPath, filepath.Dir(path))
	if err != nil {
		return c, err
	}
	if c.Routes.RuleFile != "" {
		c.Routes.RuleFile, err = expandPath(c.Routes.RuleFile, filepath.Dir(path))
		if err != nil {
			return c, err
		}
	}
	return c, c.Validate()
}
func LoadRelayConfig(path string) (RelayConfig, error) {
	c := DefaultRelayConfig()
	b, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	if e = DecodeStrict(b, &c); e != nil {
		return c, e
	}
	return c, c.Validate()
}
func expandPath(path, base string) (string, error) {
	if path == "" {
		return "", nil
	}
	if strings.HasPrefix(path, "~/") {
		home, e := os.UserHomeDir()
		if e != nil {
			return "", e
		}
		path = filepath.Join(home, path[2:])
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(base, path)
	}
	return filepath.Abs(path)
}
func validLevel(level string) bool {
	switch level {
	case "trace", "debug", "info", "warn", "error", "fatal":
		return true
	}
	return false
}
func loopback(s string) bool { a, e := netip.ParseAddr(s); return e == nil && a.IsLoopback() }
func (c Config) Validate() error {
	if c.Version != 1 {
		return errors.New("unsupported config version")
	}
	if c.Mode != "proxy" && c.Mode != "tun" {
		return errors.New("mode must be proxy or tun")
	}
	if c.IPMode != "" && c.IPMode != "ipv4_only" && c.IPMode != "dual_stack" {
		return errors.New("ip_mode must be ipv4_only or dual_stack")
	}
	if !validLevel(c.LogLevel) {
		return errors.New("invalid log_level")
	}
	if c.SSH.Server == "" || strings.ContainsAny(c.SSH.Server, " /\t\n") || c.SSH.User == "" || c.SSH.Port == 0 || c.SSH.RelayPort == 0 {
		return errors.New("SSH server, user, port and relay_port are required")
	}
	if c.SSH.PrivateKeyPath == "" {
		return errors.New("SSH private_key_path is required")
	}
	if len(c.SSH.HostKeys) == 0 {
		return errors.New("SSH host_keys must contain a trusted public server key")
	}
	for _, s := range c.SSH.HostKeys {
		if _, e := ParseHostKey(s); e != nil {
			return fmt.Errorf("invalid SSH host key: %w", e)
		}
	}
	if c.Mode == "proxy" && !c.Proxy.Enabled {
		return errors.New("proxy mode requires proxy.enabled")
	}
	if c.Proxy.Enabled && (!loopback(c.Proxy.Listen) || c.Proxy.Port == 0) {
		return errors.New("proxy must bind a loopback IP and nonzero port")
	}
	for _, a := range []string{c.DNS.Direct, c.DNS.Tunnel} {
		if _, e := netip.ParseAddr(a); e != nil {
			return errors.New("DNS servers must be IP literals")
		}
	}
	if c.DNS.DirectPort == 0 || c.DNS.TunnelPort == 0 {
		return errors.New("DNS ports must be nonzero")
	}
	if c.Mode == "tun" {
		if c.TUN.MTU < 1280 || c.TUN.MTU > 9000 {
			return errors.New("TUN MTU must be 1280..9000")
		}
		v4, v6 := false, false
		for _, p := range c.TUN.Address {
			a, e := netip.ParsePrefix(p)
			if e != nil {
				return e
			}
			if a.Addr().Is4() {
				v4 = true
			} else {
				v6 = true
			}
		}
		if !v4 || !v6 {
			return errors.New("TUN requires both IPv4 and IPv6 addresses")
		}
	}
	for _, list := range [][]string{c.Routes.ForceDirectDomains, c.Routes.ForceTunnelDomains} {
		for _, d := range list {
			if d == "" || strings.ContainsAny(d, " /:\t\n") {
				return fmt.Errorf("invalid domain suffix %q (use punycode for IDNs)", d)
			}
		}
	}
	for _, list := range [][]string{c.Routes.ForceDirectIPs, c.Routes.ForceTunnelIPs} {
		for _, p := range list {
			if _, e := netip.ParsePrefix(p); e != nil {
				return fmt.Errorf("invalid route prefix %q", p)
			}
		}
	}
	return nil
}
func (c RelayConfig) Validate() error {
	if c.Version != 1 || !loopback(c.Listen) || c.Port == 0 {
		return errors.New("relay requires version 1, a loopback IP and nonzero port")
	}
	if !validLevel(c.LogLevel) {
		return errors.New("invalid log_level")
	}
	if _, e := netip.ParseAddr(c.DNS); e != nil {
		return errors.New("relay DNS must be an IP literal")
	}
	return nil
}
func ParseHostKey(s string) (ssh.PublicKey, error) {
	k, _, _, rest, e := ssh.ParseAuthorizedKey([]byte(s))
	if e != nil {
		return nil, e
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected one public key per entry")
	}
	return k, nil
}

// pinnedHostKeyAlgorithms negotiates only algorithms for keys we actually trust.
// Otherwise a multi-key server may select ECDSA before a pinned Ed25519 key.
func pinnedHostKeyAlgorithms(keys []string) ([]string, error) {
	var algorithms []string
	seen := make(map[string]bool)
	for _, text := range keys {
		key, err := ParseHostKey(text)
		if err != nil {
			return nil, err
		}
		names := []string{key.Type()}
		if key.Type() == ssh.KeyAlgoRSA {
			// An RSA public key can authenticate using modern SHA-2 signatures.
			names = []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
		}
		for _, name := range names {
			if !seen[name] {
				seen[name] = true
				algorithms = append(algorithms, name)
			}
		}
	}
	return algorithms, nil
}

// ReadHostKeys reads a server .pub file or plain, exact-host known_hosts entries.
// Hashed/wildcard/CA known_hosts entries are intentionally not accepted by this importer.
func ReadHostKeys(path, host string, port uint16) ([]string, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var keys []string
	target := host
	if port != 22 {
		target = fmt.Sprintf("[%s]:%d", host, port)
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) > 0 && (strings.HasPrefix(f[0], "ssh-") || strings.HasPrefix(f[0], "ecdsa-") || strings.HasPrefix(f[0], "sk-")) {
			if k, e := ParseHostKey(line); e == nil {
				keys = append(keys, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))))
				continue
			}
		}
		if len(f) < 3 || strings.HasPrefix(f[0], "@") {
			continue
		}
		match := false
		for _, h := range strings.Split(f[0], ",") {
			if h == target {
				match = true
			}
		}
		if match {
			if k, e := ParseHostKey(strings.Join(f[1:], " ")); e == nil {
				keys = append(keys, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))))
			}
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("no trusted key for this host; supply the server public .pub file or an exact known_hosts entry")
	}
	return keys, nil
}
