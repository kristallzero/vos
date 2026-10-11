// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 VoS contributors.

package core

import (
	"context"
	"errors"
	"net"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	tun "github.com/sagernet/sing-tun"
	N "github.com/sagernet/sing/common/network"
)

type tunCloseTracker struct{}

func (tunCloseTracker) RoutedConnection(_ context.Context, conn net.Conn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	if metadata.InboundType != "tun" {
		return conn
	}
	return &tunCloseConn{Conn: conn}
}

func (tunCloseTracker) RoutedPacketConnection(_ context.Context, conn N.PacketConn, _ adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	return conn
}

func (tunCloseTracker) RoutedFlow(context.Context, adapter.InboundContext, adapter.Rule, adapter.Outbound) tun.FlowTracker {
	return nil
}

type tunCloseConn struct{ net.Conn }

func (c *tunCloseConn) CloseRead() error { return N.CloseRead(c.Conn) }

func (c *tunCloseConn) CloseWrite() error {
	err := N.CloseWrite(c.Conn)
	var op *net.OpError
	// sing-tun's gVisor CloseWrite wraps Shutdown's ErrNotConnected in
	// errors.New instead of translating it to ENOTCONN. Restore its errno so
	// sing-box recognizes an expected closure. Keep the error non-nil: its
	// connection manager still needs to close both ends of this finished flow.
	if errors.As(err, &op) && op.Op == "close" && op.Net == "tcp" && op.Err != nil && op.Err.Error() == "endpoint not connected" {
		classified := *op
		classified.Err = syscall.ENOTCONN
		return &classified
	}
	return err
}

// Preserve read optimizations and upstream handshake discovery, while keeping
// sing-box's writer unwrapping from bypassing CloseWrite above.
func (c *tunCloseConn) Upstream() any           { return c.Conn }
func (c *tunCloseConn) ReaderReplaceable() bool { return true }
func (c *tunCloseConn) WriterReplaceable() bool { return false }
