// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 VoS contributors.

package core

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks"
)

// Probe verifies an HTTP request and a DNS response through the local SOCKS inlet.
// The selected addresses must be outside direct rules to prove the SSH transport.
func Probe(ctx context.Context, proxyAddr, url, dnsAddr string) (string, error) {
	client := socks.NewClient(socksDialer{}, M.ParseSocksaddr(proxyAddr), socks.Version5, "", "")
	h := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return client.DialContext(ctx, network, M.ParseSocksaddr(address))
	}}}
	defer h.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if e != nil {
		return "", e
	}
	res, e := h.Do(req)
	if e != nil {
		return "", fmt.Errorf("TCP probe: %w", e)
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	res.Body.Close()
	if readErr != nil {
		return "", readErr
	}
	u, e := client.DialContext(ctx, "udp", M.ParseSocksaddr(dnsAddr))
	if e != nil {
		return "", fmt.Errorf("UDP associate: %w", e)
	}
	defer u.Close()
	u.SetDeadline(time.Now().Add(15 * time.Second))
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	wire, e := q.Pack()
	if e != nil {
		return "", e
	}
	if _, e = u.Write(wire); e != nil {
		return "", e
	}
	buf := make([]byte, 65535)
	n, e := u.Read(buf)
	if e != nil {
		return "", fmt.Errorf("UDP DNS probe: %w", e)
	}
	a := new(dns.Msg)
	if e = a.Unpack(buf[:n]); e != nil {
		return "", e
	}
	if a.Id != q.Id || !a.Response || a.Rcode != dns.RcodeSuccess || len(a.Answer) == 0 {
		return "", fmt.Errorf("invalid UDP DNS answer: rcode=%d", a.Rcode)
	}
	return fmt.Sprintf("TCP HTTP %d; UDP DNS %d answers", res.StatusCode, len(a.Answer)), nil
}

type socksDialer struct{}

func (socksDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}
func (socksDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, "udp", "127.0.0.1:0")
}
