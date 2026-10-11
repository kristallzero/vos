// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 VoS contributors.

package core

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/kristallzero/vos/internal/macosdns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/tun"
	singtun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/service"
)

func registerTUNInbound(registry *inbound.Registry) {
	inbound.Register[option.TunInboundOptions](registry, "tun", newDNSTUNInbound)
}

func newDNSTUNInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TunInboundOptions) (adapter.Inbound, error) {
	base, err := tun.NewInbound(ctx, router, logger, tag, options)
	if err != nil {
		return nil, err
	}
	// GUI network extensions configure DNS themselves. The standalone macOS
	// CLI in sing-tun 0.9.7 creates routes but does not install a resolver.
	if service.FromContext[adapter.PlatformInterface](ctx) != nil || !options.AutoRoute || options.DNSMode == singtun.DNSModeDisabled {
		return base, nil
	}
	servers, err := macOSTUNDNSServers(options)
	if err != nil {
		return nil, fmt.Errorf("macOS TUN DNS: %w", err)
	}
	// Embed the concrete inbound to preserve its network-change callbacks and
	// TCP/UDP handlers in addition to its lifecycle methods.
	return &dnsTUNInbound{Inbound: base.(*tun.Inbound), servers: servers, logger: logger}, nil
}

func macOSTUNDNSServers(options option.TunInboundOptions) ([]netip.Addr, error) {
	// Prefer IPv4 for compatibility with the default IPv4-only IP policy.
	// Like sing-tun, use the next address in the first prefix of each family.
	for _, ipv4 := range []bool{true, false} {
		for _, prefix := range options.Address {
			if prefix.Addr().Is4() != ipv4 {
				continue
			}
			if len(options.DNSAddress) > 0 {
				var servers []netip.Addr
				for _, address := range options.DNSAddress {
					if address.Is4() == ipv4 {
						servers = append(servers, address)
					}
				}
				if len(servers) > 0 {
					return servers, nil
				}
			} else if next := prefix.Addr().Next(); next.IsValid() && prefix.Contains(next) {
				return []netip.Addr{next}, nil
			}
			break
		}
	}
	return nil, fmt.Errorf("no usable DNS address in TUN prefixes %v", options.Address)
}

type dnsTUNInbound struct {
	*tun.Inbound
	servers []netip.Addr
	logger  log.ContextLogger
}

func (t *dnsTUNInbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if err := t.Inbound.Start(stage, scope); err != nil {
		return err
	}
	if stage != adapter.StartStatePostStart {
		return nil
	}
	resolver, err := macosdns.Start(scope.Context(), t.servers)
	if err != nil {
		return fmt.Errorf("configure macOS system DNS: %w", err)
	}
	// Scope closes in reverse order: restore DNS before removing the TUN.
	scope.Add(resolver.Close)
	t.logSystemDNS()
	go func() {
		<-resolver.Done()
		if !resolver.Closing() && scope.Context().Err() == nil {
			t.logger.Error("macOS system DNS session exited unexpectedly; restart VoS")
		}
	}()
	return nil
}

func (t *dnsTUNInbound) logSystemDNS() {
	// sing's logger accepts strings and Stringers, but panics on slices.
	t.logger.Info("system DNS routed through TUN: ", fmt.Sprint(t.servers))
}
