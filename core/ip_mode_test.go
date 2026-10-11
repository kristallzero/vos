// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 VoS contributors.

package core

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func TestIPModeCompatibility(t *testing.T) {
	c, _ := fixture(t)
	if c.IPMode != "ipv4_only" {
		t.Fatal("new profiles must default to IPv4")
	}
	// An existing JSON profile has no ip_mode field. Core callers may also
	// construct Config directly without filling in newly added fields.
	c.IPMode = ""
	path := filepath.Join(t.TempDir(), "legacy.json")
	if err := WriteJSON(path, c, true); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(path)
	if err != nil || loaded.IPMode != "ipv4_only" {
		t.Fatalf("legacy profile default: mode=%q error=%v", loaded.IPMode, err)
	}
	for _, mode := range []string{"", "ipv4_only", "dual_stack"} {
		c.IPMode = mode
		if err := c.Validate(); err != nil {
			t.Fatalf("valid mode %q: %v", mode, err)
		}
	}
	c.IPMode = "prefer_ipv4"
	if err := c.Validate(); err == nil {
		t.Fatal("invalid IP policy accepted")
	}
}

func TestIPv4OnlyTUNRejectsBeforeSniffAndOverrides(t *testing.T) {
	c, server := fixture(t)
	c.IPMode = "" // Also exercise the default for direct users of the Go API.
	c.Routes.BypassPrivate, c.Routes.BypassRU = true, true
	c.Routes.ForceTunnelIPs = []string{"::/0"}
	c.Routes.ForceDirectIPs = []string{"::/0"}
	b := startTestEngine(t, c)
	source := netip.MustParseAddrPort("[fdfe:dcba:9876::1]:54321")
	for _, address := range []string{"[2606:4700::6812:572a]:443", "[2001:db8::1]:443", "[::1]:443"} {
		for _, protocol := range []uint8{6, 17, 58} { // TCP, UDP, ICMPv6.
			// Bursts must keep receiving a rejection, never turn into silent
			// drops after sing-box's default 50 rejections in 30 seconds.
			for i := 0; i < 70; i++ {
				verdict := adapter.JudgeFlow(b.Router(), "tun", "tun", protocol, source, netip.MustParseAddrPort(address), nil)
				if verdict.Action != tun.ActionReject {
					t.Fatalf("destination=%s protocol=%d request=%d verdict=%v", address, protocol, i, verdict.Action)
				}
			}
		}
	}
	// DNS carried over IPv6 is intercepted locally and answered using the
	// IPv4 DNS policy; it must not be rejected as ordinary IPv6 traffic.
	verdict := adapter.JudgeFlow(b.Router(), "tun", "tun", 17, source, netip.MustParseAddrPort("[2001:db8::53]:53"), nil)
	if verdict.Action != tun.ActionHijackDNS {
		t.Fatalf("IPv6 DNS was not intercepted: %v", verdict.Action)
	}
	if server.requests.Load() != 0 {
		t.Fatal("IPv6 rejection attempted SSH forwarding")
	}
	// Opting in to dual stack must restore the normal route through sniffing.
	c.IPMode, c.Proxy.Port = "dual_stack", port(t)
	b = startTestEngine(t, c)
	verdict = adapter.JudgeFlow(b.Router(), "tun", "tun", 6, source, netip.MustParseAddrPort("[2001:db8::1]:443"), nil)
	if verdict.Action != tun.ActionAccept {
		t.Fatalf("dual-stack IPv6 unexpectedly rejected: %v", verdict.Action)
	}
}

func TestIPv4OnlySOCKSRejectsIPv6WithoutSSH(t *testing.T) {
	c, server := fixture(t)
	s := startClient(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := s.DialContext(ctx, "tcp", M.ParseSocksaddr("[2606:4700::6812:572a]:443"))
	if err == nil {
		conn.Close()
		t.Fatal("SOCKS accepted an IPv6 destination")
	}
	if ctx.Err() != nil {
		t.Fatal("IPv6 rejection waited for a timeout")
	}
	if server.requests.Load() != 0 {
		t.Fatal("IPv6 destination reached the SSH server")
	}
	if err := httpVia(t, s, testHTTP(t).URL); err != nil {
		t.Fatal("IPv4 stopped working:", err)
	}
	if server.requests.Load() == 0 {
		t.Fatal("IPv4 did not traverse SSH")
	}
}

func startTestEngine(t *testing.T, c Config) *box.Box {
	t.Helper()
	b, err := NewClient(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Start(); err != nil {
		b.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return b
}

type dnsPacketResponse chan []byte

func (r dnsPacketResponse) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	defer buffer.Release()
	r <- append([]byte(nil), buffer.Bytes()...)
	return nil
}

func exchangeTUNDNS(t *testing.T, b *box.Box, name string, qtype uint16) *dns.Msg {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	data, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	response := make(dnsPacketResponse, 1)
	b.Router().HijackDNSPacket(ctx, data, response, adapter.InboundContext{
		Inbound: "tun", InboundType: "tun", Network: "udp",
		Source: M.ParseSocksaddr("[fdfe:dcba:9876::1]:54321"), Destination: M.ParseSocksaddr("[2001:db8::53]:53"),
	})
	select {
	case data := <-response:
		r := new(dns.Msg)
		if err = r.Unpack(data); err != nil {
			t.Fatal(err)
		}
		if r.Id != q.Id || r.Rcode != dns.RcodeSuccess {
			t.Fatalf("DNS response id=%d rcode=%d", r.Id, r.Rcode)
		}
		return r
	case <-ctx.Done():
		t.Fatal("TUN DNS response timed out")
		return nil
	}
}

func TestIPModeDNS(t *testing.T) {
	for _, mode := range []string{"ipv4_only", "dual_stack"} {
		t.Run(mode, func(t *testing.T) {
			c, server := fixture(t)
			c.IPMode, c.Routes.BypassRU = mode, true
			p, tcp, udp := startDNS(t)
			c.DNS = DNSConfig{Direct: "127.0.0.1", Tunnel: "127.0.0.1", DirectPort: p, TunnelPort: p}
			b := startTestEngine(t, c)
			for _, name := range []string{"service.ru", "foreign.test"} {
				r := exchangeTUNDNS(t, b, name, dns.TypeAAAA)
				if mode == "ipv4_only" && len(r.Answer) != 0 {
					t.Fatalf("AAAA must return NOERROR with no records: %v", r.Answer)
				}
				if mode == "dual_stack" && (len(r.Answer) != 1 || r.Answer[0].Header().Rrtype != dns.TypeAAAA) {
					t.Fatalf("dual-stack AAAA was filtered: %v", r.Answer)
				}
			}
			if mode == "ipv4_only" && (tcp.Load() != 0 || udp.Load() != 0 || server.requests.Load() != 0) {
				t.Fatal("AAAA filtering contacted upstream DNS or SSH")
			}
			for _, name := range []string{"service.ru", "foreign.test"} {
				r := exchangeTUNDNS(t, b, name, dns.TypeA)
				if len(r.Answer) != 1 {
					t.Fatalf("IPv4 DNS answer missing: %v", r.Answer)
				}
				a, ok := r.Answer[0].(*dns.A)
				if !ok || !a.A.Equal(net.ParseIP("127.0.0.1")) {
					t.Fatalf("wrong IPv4 answer: %v", r.Answer)
				}
				r = exchangeTUNDNS(t, b, name, dns.TypeHTTPS)
				if len(r.Answer) != 1 {
					t.Fatalf("HTTPS DNS answer missing: %v", r.Answer)
				}
				https, ok := r.Answer[0].(*dns.HTTPS)
				if !ok {
					t.Fatalf("wrong HTTPS answer: %v", r.Answer)
				}
				v4, v6 := false, false
				for _, hint := range https.Value {
					v4 = v4 || hint.Key() == dns.SVCB_IPV4HINT
					v6 = v6 || hint.Key() == dns.SVCB_IPV6HINT
				}
				if !v4 || v6 != (mode == "dual_stack") {
					t.Fatalf("HTTPS address hints: ipv4=%v ipv6=%v mode=%s", v4, v6, mode)
				}
			}
			if tcp.Load() == 0 || udp.Load() == 0 || server.requests.Load() == 0 {
				t.Fatal("direct/tunneled IPv4 DNS policy was not preserved")
			}
		})
	}
}
