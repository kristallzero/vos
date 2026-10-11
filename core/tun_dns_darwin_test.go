// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 VoS contributors.

package core

import (
	"bytes"
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

func TestMacOSTUNDNSStartupLog(t *testing.T) {
	for _, tc := range []struct {
		name    string
		servers []netip.Addr
		want    string
	}{
		{"IPv4", []netip.Addr{netip.MustParseAddr("172.31.255.2")}, "[172.31.255.2]"},
		{"multiple", []netip.Addr{netip.MustParseAddr("172.31.255.2"), netip.MustParseAddr("fd00::2")}, "[172.31.255.2 fd00::2]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			factory := log.NewDefaultFactory(context.Background(), log.Formatter{
				DisableColors: true, DisableTimestamp: true,
			}, &output, "", nil, false)
			if err := factory.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { factory.Close() })
			inbound := &dnsTUNInbound{servers: tc.servers, logger: factory.NewLogger("inbound/tun[tun]")}
			// Use the actual startup logging path and sing-box formatter. A NOP
			// logger would hide the panic caused by passing []netip.Addr.
			inbound.logSystemDNS()
			if !strings.Contains(output.String(), "INFO inbound/tun[tun]: system DNS routed through TUN: "+tc.want) {
				t.Fatalf("missing DNS startup message: %s", output.String())
			}
		})
	}
}

// Embedding the upstream inbound must preserve network changes and handlers.
var (
	_ adapter.InterfaceUpdateListener = (*dnsTUNInbound)(nil)
	_ N.TCPConnectionHandlerEx        = (*dnsTUNInbound)(nil)
	_ N.UDPConnectionHandlerEx        = (*dnsTUNInbound)(nil)
)

func TestMacOSTUNDNSServers(t *testing.T) {
	for _, tc := range []struct {
		name      string
		prefixes  []string
		explicit  []string
		want      []string
		wantError bool
	}{
		{name: "default", prefixes: DefaultConfig().TUN.Address, want: []string{"172.31.255.2"}},
		{name: "custom", prefixes: []string{"10.99.0.5/30", "fd00::1/126"}, want: []string{"10.99.0.6"}},
		{name: "IPv6 only", prefixes: []string{"fd00::1/126"}, want: []string{"fd00::2"}},
		{name: "IPv6 fallback", prefixes: []string{"10.0.0.1/32", "fd00::1/126"}, want: []string{"fd00::2"}},
		{name: "explicit", prefixes: DefaultConfig().TUN.Address, explicit: []string{"fd00::53", "172.31.255.3"}, want: []string{"172.31.255.3"}},
		{name: "no next address", prefixes: []string{"10.0.0.1/32"}, wantError: true},
		{name: "no addresses", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var options option.TunInboundOptions
			for _, prefix := range tc.prefixes {
				options.Address = append(options.Address, netip.MustParsePrefix(prefix))
			}
			for _, address := range tc.explicit {
				options.DNSAddress = append(options.DNSAddress, netip.MustParseAddr(address))
			}
			servers, err := macOSTUNDNSServers(options)
			if (err != nil) != tc.wantError {
				t.Fatalf("servers=%v error=%v", servers, err)
			}
			var got []string
			for _, server := range servers {
				got = append(got, server.String())
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("servers=%v want=%v", got, tc.want)
			}
		})
	}
}
