// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 VoS contributors.

package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func gvisorCloseError(op, network, message string) error {
	return &net.OpError{Op: op, Net: network, Err: errors.New(message)}
}

type halfCloseConn struct {
	net.Conn
	err error
}

func (c *halfCloseConn) CloseWrite() error { return c.err }

func TestTUNCloseErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"gvisor shutdown", gvisorCloseError("close", "tcp", "endpoint not connected"), true},
		{"successful shutdown", nil, false},
		{"read error", gvisorCloseError("read", "tcp", "endpoint not connected"), false},
		{"write error", gvisorCloseError("write", "tcp", "endpoint not connected"), false},
		{"UDP error", gvisorCloseError("close", "udp", "endpoint not connected"), false},
		{"other shutdown error", gvisorCloseError("close", "tcp", "unexpected shutdown failure"), false},
		{"untyped error", errors.New("endpoint not connected"), false},
		{"native errno", &net.OpError{Op: "close", Net: "tcp", Err: syscall.ENOTCONN}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			original := &halfCloseConn{Conn: left, err: tc.err}
			conn := &tunCloseConn{Conn: original}
			err := N.CloseWrite(conn)
			if tc.want {
				if err == nil || !errors.Is(err, syscall.ENOTCONN) || !E.IsClosed(err) {
					t.Fatalf("shutdown must remain a non-nil, recognized close error: %v", err)
				}
				if errors.Is(tc.err, syscall.ENOTCONN) {
					t.Fatal("classification mutated the original error")
				}
			} else if err != tc.err {
				t.Fatalf("unrelated error changed: got %v, want %v", err, tc.err)
			}
			if N.UnwrapReader(conn) != original {
				t.Fatal("read optimizations cannot reach the original connection")
			}
			if N.UnwrapWriter(conn) != conn {
				t.Fatal("writer unwrapping bypassed shutdown classification")
			}
		})
	}
}

type downloadCloseLog chan log.Entry

func (l downloadCloseLog) WriteMessage(level log.Level, message string) {
	if strings.Contains(message, "connection download closed") {
		l <- log.Entry{Level: level, Message: message}
	}
}

// Exercise the real router, SSH forwarding, and connection manager without a
// privileged host TUN. The inlet reproduces sing-tun's TCP shutdown error.
func TestTUNCloseLogging(t *testing.T) {
	for _, tc := range []struct {
		name    string
		inbound string
		err     error
		level   log.Level
	}{
		{"TUN already closed", "tun", gvisorCloseError("close", "tcp", "endpoint not connected"), log.LevelTrace},
		{"TUN unexpected failure", "tun", gvisorCloseError("close", "tcp", "unexpected shutdown failure"), log.LevelError},
		{"SOCKS unchanged", "socks", gvisorCloseError("close", "tcp", "endpoint not connected"), log.LevelError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, server := fixture(t)
			engine := startTestEngine(t, c)
			logs := make(downloadCloseLog, 4)
			engine.LogFactory().AttachPlatformWriter(logs)
			h := testHTTP(t)
			application, inlet := net.Pipe()
			defer application.Close()
			defer inlet.Close()
			application.SetDeadline(time.Now().Add(5 * time.Second))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			closed := make(chan struct{})
			go engine.Router().RouteConnectionEx(ctx, &halfCloseConn{Conn: inlet, err: tc.err}, adapter.InboundContext{
				Inbound: tc.inbound, InboundType: tc.inbound,
				Source:      M.ParseSocksaddr("172.31.255.1:54321"),
				Destination: M.ParseSocksaddr(strings.TrimPrefix(h.URL, "http://")),
			}, func(error) { close(closed) })
			if _, err := fmt.Fprint(application, "GET / HTTP/1.0\r\nHost: example.test\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			response, err := io.ReadAll(application)
			if err != nil || !strings.HasSuffix(string(response), "vos-http-ok") {
				t.Fatalf("HTTP payload was not delivered: %q, %v", response, err)
			}
			if server.channels.Load() == 0 {
				t.Fatal("request did not traverse SSH")
			}
			select {
			case entry := <-logs:
				if entry.Level != tc.level {
					t.Fatalf("close log level=%s, want %s: %s", log.FormatLevel(entry.Level), log.FormatLevel(tc.level), entry.Message)
				}
			case <-ctx.Done():
				t.Fatal("missing download close log")
			}
			select {
			case <-closed:
			case <-ctx.Done():
				t.Fatal("connection cleanup did not finish")
			}
		})
	}
}

func TestTUNHalfClosePreservesResponse(t *testing.T) {
	for _, direct := range []bool{false, true} {
		t.Run(fmt.Sprintf("direct=%v", direct), func(t *testing.T) {
			testTUNHalfCloseResponse(t, direct)
		})
	}
}

func testTUNHalfCloseResponse(t *testing.T, direct bool) {
	t.Helper()
	c, server := fixture(t)
	c.Routes.BypassPrivate = direct
	engine := startTestEngine(t, c)
	// The destination sends its response only after receiving EOF. Closing the
	// upload half must keep the download half alive for direct and SSH routes.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	served := make(chan error, 1)
	go func() {
		conn, err := target.Accept()
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		request, err := io.ReadAll(conn)
		if err == nil && string(request) != "vos-upload" {
			err = fmt.Errorf("unexpected upload: %q", request)
		}
		if err == nil {
			_, err = io.WriteString(conn, "vos-download")
		}
		served <- err
	}()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	application, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer application.Close()
	inlet, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer inlet.Close()
	application.SetDeadline(time.Now().Add(5 * time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	closed := make(chan struct{})
	go engine.Router().RouteConnectionEx(ctx, inlet, adapter.InboundContext{
		Inbound: "tun", InboundType: "tun", Source: M.SocksaddrFromNet(inlet.RemoteAddr()),
		Destination: M.ParseSocksaddr(target.Addr().String()),
	}, func(error) { close(closed) })
	if _, err = io.WriteString(application, "vos-upload"); err != nil {
		t.Fatal(err)
	}
	if err = application.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(application)
	if err != nil || string(response) != "vos-download" {
		t.Fatalf("half-close lost the response: %q, %v", response, err)
	}
	if err = <-served; err != nil {
		t.Fatal(err)
	}
	if tunneled := server.channels.Load() > 0; tunneled == direct {
		t.Fatalf("wrong test route: direct=%v, SSH channels=%d", direct, server.channels.Load())
	}
	select {
	case <-closed:
	case <-ctx.Done():
		t.Fatal("half-closed connection was not cleaned up")
	}
}
