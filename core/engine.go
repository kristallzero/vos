// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 VoS contributors.

package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/kristallzero/vos/internal/sshtransport"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/socks"
	sjson "github.com/sagernet/sing/common/json"
)

type object = map[string]any

func registryContext(ctx context.Context) context.Context {
	i, o := inbound.NewRegistry(), outbound.NewRegistry()
	d := dns.NewTransportRegistry()
	socks.RegisterInbound(i)
	registerTUNInbound(i)
	direct.RegisterOutbound(o)
	socks.RegisterOutbound(o)
	sshtransport.RegisterOutbound(o)
	transport.RegisterUDP(d)
	transport.RegisterTCP(d)
	return box.Context(ctx, i, o, endpoint.NewRegistry(), d, service.NewRegistry(), certificate.NewRegistry())
}
func newEngine(ctx context.Context, config object) (*box.Box, error) {
	ctx = registryContext(ctx)
	data, e := json.Marshal(config)
	if e != nil {
		return nil, e
	}
	options, e := sjson.UnmarshalExtendedContext[option.Options](ctx, data)
	if e != nil {
		return nil, e
	}
	return box.New(box.Options{Context: ctx, Options: options})
}

// NewClient constructs but does not start listeners or change system routes.
func NewClient(ctx context.Context, c Config) (*box.Box, error) {
	config, e := ClientOptions(c)
	if e != nil {
		return nil, e
	}
	if env := c.SSH.PassphraseEnv; env != "" {
		if p, ok := os.LookupEnv(env); ok {
			for _, v := range config["outbounds"].([]object) {
				if v["type"] == "ssh" {
					v["private_key_passphrase"] = p
				}
			}
		}
	}
	engine, e := newEngine(ctx, config)
	if e != nil {
		return nil, e
	}
	engine.Router().AppendTracker(tunCloseTracker{})
	return engine, nil
}
func NewRelay(ctx context.Context, c RelayConfig) (*box.Box, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	return newEngine(ctx, RelayOptions(c))
}

// ClientOptions exports engine options without reading or exporting private secrets.
func ClientOptions(c Config) (object, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	bundle, e := LoadRules(c.Routes.RuleFile)
	if e != nil {
		return nil, fmt.Errorf("routes: %w", e)
	}
	hostKeyAlgorithms, e := pinnedHostKeyAlgorithms(c.SSH.HostKeys)
	if e != nil {
		return nil, e
	}
	ins := []object{}
	if c.Proxy.Enabled {
		ins = append(ins, object{"type": "socks", "tag": "proxy", "listen": c.Proxy.Listen, "listen_port": c.Proxy.Port})
	}
	if c.Mode == "tun" {
		t := object{"type": "tun", "tag": "tun", "address": c.TUN.Address, "mtu": c.TUN.MTU, "auto_route": true, "strict_route": true, "stack": "gvisor", "dns_mode": "hijack"}
		if c.TUN.Name != "" {
			t["interface_name"] = c.TUN.Name
		}
		ins = append(ins, t)
	}
	outs := []object{{"type": "direct", "tag": "direct", "domain_resolver": "dns-direct"}}
	for _, tag := range []string{"ssh-tcp", "ssh-udp"} {
		s := object{"type": "ssh", "tag": tag, "server": c.SSH.Server, "server_port": c.SSH.Port, "user": c.SSH.User, "private_key_path": c.SSH.PrivateKeyPath, "host_key": c.SSH.HostKeys, "host_key_algorithms": hostKeyAlgorithms, "domain_resolver": "dns-direct", "connect_timeout": "15s"}
		if c.SSH.Interface != "" {
			s["bind_interface"] = c.SSH.Interface
		}
		outs = append(outs, s)
	}
	outs = append(outs, object{"type": "socks", "tag": "udp-relay", "server": "127.0.0.1", "server_port": c.SSH.RelayPort, "detour": "ssh-udp", "udp_over_tcp": object{"enabled": true, "version": 2}})
	strategy := "prefer_ipv4"
	rules := []object{}
	if c.IPMode != "dual_stack" {
		strategy = "ipv4_only"
		// Intercept DNS even when the OS uses an IPv6 resolver. Other IPv6
		// traffic must be rejected before sniffing or any direct/tunnel rule.
		// no_drop keeps bursts above sing-box's rejection limit from timing out.
		rules = append(rules,
			object{"inbound": "tun", "port": 53, "action": "hijack-dns"},
			object{"ip_version": 6, "action": "reject", "method": "default", "no_drop": true})
	}
	rules = append(rules, object{"action": "sniff", "timeout": "300ms"}, object{"inbound": "tun", "protocol": "dns", "action": "hijack-dns"}, object{"action": "resolve", "strategy": strategy})
	dnsRules := []object{}
	tunnel := matcher(c.Routes.ForceTunnelDomains, c.Routes.ForceTunnelIPs)
	directRule := matcher(c.Routes.ForceDirectDomains, c.Routes.ForceDirectIPs)
	if tunnel != nil {
		rules = appendTunnel(rules, tunnel)
	}
	if directRule != nil {
		rules = append(rules, routeAction(directRule, "direct"))
	}
	if len(c.Routes.ForceTunnelDomains) > 0 {
		dnsRules = append(dnsRules, object{"domain_suffix": c.Routes.ForceTunnelDomains, "action": "route", "server": "dns-tunnel"})
	}
	if len(c.Routes.ForceDirectDomains) > 0 {
		dnsRules = append(dnsRules, object{"domain_suffix": c.Routes.ForceDirectDomains, "action": "route", "server": "dns-direct"})
	}
	if c.Routes.BypassPrivate {
		rules = append(rules, object{"ip_is_private": true, "action": "route", "outbound": "direct"})
	}
	if c.Routes.BypassRU {
		rules = append(rules, object{"rule_set": "ru-domains", "action": "route", "outbound": "direct"})
		dnsRules = append(dnsRules, object{"rule_set": "ru-domains", "action": "route", "server": "dns-direct"})
	}
	if c.Routes.BypassRU {
		rules = append(rules, object{"rule_set": "ru-ip", "action": "route", "outbound": "direct"})
	}
	rules = append(rules, object{"network": "udp", "action": "route", "outbound": "udp-relay"})
	route := object{"rules": rules, "final": "ssh-tcp", "default_domain_resolver": "dns-direct", "rule_set": []object{{"type": "inline", "tag": "ru-domains", "rules": bundle.RUDomains}, {"type": "inline", "tag": "ru-ip", "rules": bundle.RUIP}}}
	if c.SSH.Interface != "" {
		route["default_interface"] = c.SSH.Interface
	} else if c.Mode == "tun" {
		route["auto_detect_interface"] = true
	}
	return object{"log": object{"level": c.LogLevel, "timestamp": true}, "inbounds": ins, "outbounds": outs, "route": route,
		"dns": object{"servers": []object{{"type": "udp", "tag": "dns-direct", "server": c.DNS.Direct, "server_port": c.DNS.DirectPort}, {"type": "tcp", "tag": "dns-tunnel", "server": c.DNS.Tunnel, "server_port": c.DNS.TunnelPort, "detour": "ssh-tcp"}}, "rules": dnsRules, "final": "dns-tunnel", "reverse_mapping": true, "strategy": strategy}}, nil
}
func matcher(domains, ips []string) object {
	rules := []object{}
	if len(domains) > 0 {
		rules = append(rules, object{"domain_suffix": domains})
	}
	if len(ips) > 0 {
		rules = append(rules, object{"ip_cidr": ips})
	}
	if len(rules) == 0 {
		return nil
	}
	if len(rules) == 1 {
		return rules[0]
	}
	return object{"type": "logical", "mode": "or", "rules": rules}
}
func routeAction(m object, out string) object {
	n := object{}
	for k, v := range m {
		n[k] = v
	}
	n["action"] = "route"
	n["outbound"] = out
	return n
}
func appendTunnel(rules []object, m object) []object {
	return append(rules, object{"type": "logical", "mode": "and", "rules": []object{m, {"network": "udp"}}, "action": "route", "outbound": "udp-relay"}, routeAction(m, "ssh-tcp"))
}
func RelayOptions(c RelayConfig) object {
	return object{"log": object{"level": c.LogLevel, "timestamp": true}, "inbounds": []object{{"type": "socks", "tag": "relay", "listen": c.Listen, "listen_port": c.Port}}, "outbounds": []object{{"type": "direct", "tag": "direct"}}, "route": object{"final": "direct", "default_domain_resolver": "relay-dns"}, "dns": object{"servers": []object{{"type": "udp", "tag": "relay-dns", "server": c.DNS}}}}
}
