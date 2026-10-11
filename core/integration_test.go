// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 VoS contributors.

package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks"
	"golang.org/x/crypto/ssh"
)

type testSSH struct {
	listener    net.Listener
	config      *ssh.ServerConfig
	key         ssh.Signer
	connections atomic.Int64
	requests    atomic.Int64
	channels    atomic.Int64
	mu          sync.Mutex
	active      map[*ssh.ServerConn]bool
	stopping    bool
	wg          sync.WaitGroup
}

func keyPair(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := ssh.NewSignerFromKey(key)
	if e != nil {
		t.Fatal(e)
	}
	block, e := ssh.MarshalPrivateKey(key, "")
	if e != nil {
		t.Fatal(e)
	}
	return signer, pem.EncodeToMemory(block)
}
func startSSH(t *testing.T, client ssh.PublicKey) *testSSH {
	t.Helper()
	host, _ := keyPair(t)
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	s := &testSSH{listener: l, key: host, active: map[*ssh.ServerConn]bool{}}
	s.config = &ssh.ServerConfig{PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if c.User() == "vos-test" && bytes.Equal(k.Marshal(), client.Marshal()) {
			return nil, nil
		}
		return nil, fmt.Errorf("unauthorized")
	}}
	s.config.AddHostKey(host)
	// A real OpenSSH server offers multiple key types. Pinning Ed25519 must
	// negotiate Ed25519 even if the SSH library would prefer ECDSA by default.
	ecdsaKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ecdsaSigner, e := ssh.NewSignerFromKey(ecdsaKey)
	if e != nil {
		t.Fatal(e)
	}
	s.config.AddHostKey(ecdsaSigner)
	s.wg.Go(func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			s.wg.Go(func() {
				defer c.Close()
				conn, chans, reqs, e := ssh.NewServerConn(c, s.config)
				if e != nil {
					return
				}
				s.mu.Lock()
				if s.stopping {
					s.mu.Unlock()
					conn.Close()
					return
				}
				s.active[conn] = true
				s.mu.Unlock()
				s.connections.Add(1)
				defer func() { conn.Close(); s.mu.Lock(); delete(s.active, conn); s.mu.Unlock() }()
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					if ch.ChannelType() != "direct-tcpip" {
						ch.Reject(ssh.UnknownChannelType, "forwarding only")
						continue
					}
					s.requests.Add(1)
					var p struct {
						Host       string
						Port       uint32
						OriginHost string
						OriginPort uint32
					}
					if e := ssh.Unmarshal(ch.ExtraData(), &p); e != nil {
						ch.Reject(ssh.ConnectionFailed, "bad payload")
						continue
					}
					dst, e := net.DialTimeout("tcp", net.JoinHostPort(p.Host, fmt.Sprint(p.Port)), 3*time.Second)
					if e != nil {
						ch.Reject(ssh.ConnectionFailed, e.Error())
						continue
					}
					channel, r, e := ch.Accept()
					if e != nil {
						dst.Close()
						continue
					}
					s.channels.Add(1)
					go ssh.DiscardRequests(r)
					go func() {
						defer channel.Close()
						defer dst.Close()
						done := make(chan struct{})
						go func() { io.Copy(channel, dst); channel.CloseWrite(); close(done) }()
						io.Copy(dst, channel)
						if c, ok := dst.(*net.TCPConn); ok {
							c.CloseWrite()
						}
						<-done
					}()
				}
			})
		}
	})
	t.Cleanup(func() {
		s.mu.Lock()
		s.stopping = true
		for c := range s.active {
			c.Close()
		}
		s.mu.Unlock()
		l.Close()
		s.wg.Wait()
	})
	return s
}
func (s *testSSH) drop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.active {
		c.Close()
	}
}
func port(t *testing.T) uint16 {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := uint16(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	return p
}
func fixture(t *testing.T) (Config, *testSSH) {
	t.Helper()
	client, key := keyPair(t)
	sshServer := startSSH(t, client.PublicKey())
	path := filepath.Join(t.TempDir(), "client.key")
	if e := os.WriteFile(path, key, 0600); e != nil {
		t.Fatal(e)
	}
	c := DefaultConfig()
	c.LogLevel = "error"
	c.SSH.Server = "127.0.0.1"
	c.SSH.User = "vos-test"
	c.SSH.Port = uint16(sshServer.listener.Addr().(*net.TCPAddr).Port)
	c.SSH.HostKeys = []string{strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshServer.key.PublicKey())))}
	c.SSH.PrivateKeyPath = path
	c.SSH.RelayPort = port(t)
	c.Proxy.Port = port(t)
	c.Routes.BypassPrivate = false
	c.Routes.BypassRU = false
	r := DefaultRelayConfig()
	r.LogLevel = "error"
	r.Port = c.SSH.RelayPort
	b, e := NewRelay(context.Background(), r)
	if e != nil {
		t.Fatal(e)
	}
	if e = b.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { b.Close() })
	return c, sshServer
}
func startClient(t *testing.T, c Config) *socks.Client {
	t.Helper()
	b, e := NewClient(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	if e = b.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { b.Close() })
	return socks.NewClient(socksDialer{}, M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", c.Proxy.Port)), socks.Version5, "", "")
}
func httpVia(t *testing.T, s *socks.Client, url string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	transport := &http.Transport{DialContext: func(ctx context.Context, n, a string) (net.Conn, error) {
		return s.DialContext(ctx, n, M.ParseSocksaddr(a))
	}}
	defer transport.CloseIdleConnections()
	h := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	res, e := h.Do(req)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	b, e := io.ReadAll(res.Body)
	if e == nil && string(b) != "vos-http-ok" {
		return fmt.Errorf("wrong HTTP body %q", b)
	}
	return e
}
func udpVia(s *socks.Client, address string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, e := s.DialContext(ctx, "udp", M.ParseSocksaddr(address))
	if e != nil {
		return e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	msg := []byte("VoS UDP round trip")
	if _, e = c.Write(msg); e != nil {
		return e
	}
	b := make([]byte, 1024)
	n, e := c.Read(b)
	if e == nil && !bytes.Equal(b[:n], msg) {
		return fmt.Errorf("UDP mismatch")
	}
	return e
}
func startEcho(t *testing.T) string {
	t.Helper()
	c, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, e := c.ReadFrom(b)
			if e != nil {
				return
			}
			c.WriteTo(b[:n], a)
		}
	}()
	return c.LocalAddr().String()
}
func testHTTP(t *testing.T) *httptest.Server {
	t.Helper()
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "vos-http-ok") }))
	t.Cleanup(h.Close)
	return h
}
func TestSSHTCPUDPAndReconnect(t *testing.T) {
	c, server := fixture(t)
	s := startClient(t, c)
	h := testHTTP(t)
	udp := startEcho(t)
	if e := httpVia(t, s, h.URL); e != nil {
		t.Fatal(e)
	}
	if e := udpVia(s, udp); e != nil {
		t.Fatal(e)
	}
	if server.channels.Load() < 2 || server.connections.Load() != 2 {
		t.Fatalf("TCP and UDP must use separate SSH connections: connections=%d channels=%d", server.connections.Load(), server.channels.Load())
	}
	server.drop()
	deadline := time.Now().Add(6 * time.Second)
	var e error
	for time.Now().Before(deadline) {
		e = httpVia(t, s, h.URL)
		if e == nil {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if e != nil {
		t.Fatal("TCP reconnect:", e)
	}
	if e = udpVia(s, udp); e != nil {
		t.Fatal("UDP reconnect:", e)
	}
	if server.connections.Load() < 4 {
		t.Fatal("SSH connections were not re-created")
	}
}
func TestHostKeyMismatch(t *testing.T) {
	c, server := fixture(t)
	wrong, _ := keyPair(t)
	c.SSH.HostKeys = []string{strings.TrimSpace(string(ssh.MarshalAuthorizedKey(wrong.PublicKey())))}
	s := startClient(t, c)
	h := testHTTP(t)
	if e := httpVia(t, s, h.URL); e == nil {
		t.Fatal("wrong server key was accepted")
	}
	if server.channels.Load() != 0 {
		t.Fatal("untrusted SSH forwarded traffic")
	}
}

func TestRUIPAndIPOverrideForRUDomain(t *testing.T) {
	c, server := fixture(t)
	rules, e := LoadRules("")
	if e != nil {
		t.Fatal(e)
	}
	rules.RUIP = []Rule{{IPCIDR: []string{"127.0.0.0/8"}}}
	c.Routes.RuleFile = filepath.Join(t.TempDir(), "rules.json")
	if e = WriteJSON(c.Routes.RuleFile, rules, true); e != nil {
		t.Fatal(e)
	}
	c.Routes.BypassRU = true
	p, _, _ := startDNS(t)
	c.DNS = DNSConfig{Direct: "127.0.0.1", Tunnel: "127.0.0.1", DirectPort: p, TunnelPort: p}
	s := startClient(t, c)
	h := testHTTP(t)
	if e = httpVia(t, s, h.URL); e != nil {
		t.Fatal(e)
	}
	if server.channels.Load() != 0 {
		t.Fatal("RU IP bypass used SSH")
	}
	c.Proxy.Port = port(t)
	c.Routes.ForceTunnelIPs = []string{"127.0.0.0/8"}
	s = startClient(t, c)
	_, hp, _ := net.SplitHostPort(strings.TrimPrefix(h.URL, "http://"))
	if e = httpVia(t, s, "http://service.ru:"+hp); e != nil {
		t.Fatal(e)
	}
	if server.channels.Load() == 0 {
		t.Fatal("forced IP tunnel lost to RU domain")
	}
}
func TestDirectAndTunnelOverride(t *testing.T) {
	c, server := fixture(t)
	c.Routes.BypassPrivate = true
	s := startClient(t, c)
	h := testHTTP(t)
	if e := httpVia(t, s, h.URL); e != nil {
		t.Fatal(e)
	}
	if server.channels.Load() != 0 {
		t.Fatal("private bypass used SSH")
	}
	c.Proxy.Port = port(t)
	c.Routes.ForceTunnelIPs = []string{"127.0.0.0/8"}
	c.Routes.ForceDirectIPs = []string{"127.0.0.0/8"}
	s = startClient(t, c)
	if e := httpVia(t, s, h.URL); e != nil {
		t.Fatal(e)
	}
	if e := udpVia(s, startEcho(t)); e != nil {
		t.Fatal(e)
	}
	if server.channels.Load() < 2 {
		t.Fatal("forced tunnel did not take precedence")
	}
}
func startDNS(t *testing.T) (uint16, *atomic.Int64, *atomic.Int64) {
	t.Helper()
	p := port(t)
	tcp, e := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
	if e != nil {
		t.Fatal(e)
	}
	udp, e := net.ListenPacket("udp", tcp.Addr().String())
	if e != nil {
		tcp.Close()
		t.Fatal(e)
	}
	tc, uc := new(atomic.Int64), new(atomic.Int64)
	handler := func(count *atomic.Int64) dns.HandlerFunc {
		return func(w dns.ResponseWriter, q *dns.Msg) {
			count.Add(1)
			a := new(dns.Msg)
			a.SetReply(q)
			for _, v := range q.Question {
				switch v.Qtype {
				case dns.TypeA:
					a.Answer = append(a.Answer, &dns.A{Hdr: dns.RR_Header{Name: v.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("127.0.0.1")})
				case dns.TypeAAAA:
					a.Answer = append(a.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: v.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("::1")})
				case dns.TypeHTTPS:
					a.Answer = append(a.Answer, &dns.HTTPS{SVCB: dns.SVCB{
						Hdr: dns.RR_Header{Name: v.Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60}, Priority: 1, Target: ".",
						Value: []dns.SVCBKeyValue{&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("127.0.0.1")}}, &dns.SVCBIPv6Hint{Hint: []net.IP{net.ParseIP("::1")}}},
					}})
				}
			}
			w.WriteMsg(a)
		}
	}
	ts := &dns.Server{Listener: tcp, Handler: handler(tc)}
	us := &dns.Server{PacketConn: udp, Handler: handler(uc)}
	go ts.ActivateAndServe()
	go us.ActivateAndServe()
	t.Cleanup(func() { ts.Shutdown(); us.Shutdown() })
	return p, tc, uc
}
func TestRUDomainDNSAndUDPProbe(t *testing.T) {
	c, server := fixture(t)
	p, tc, uc := startDNS(t)
	c.DNS = DNSConfig{Direct: "127.0.0.1", Tunnel: "127.0.0.1", DirectPort: p, TunnelPort: p}
	c.Routes.BypassRU = true
	s := startClient(t, c)
	h := testHTTP(t)
	_, hp, _ := net.SplitHostPort(strings.TrimPrefix(h.URL, "http://"))
	if e := httpVia(t, s, "http://service.ru:"+hp); e != nil {
		t.Fatal(e)
	}
	if server.channels.Load() != 0 || uc.Load() == 0 {
		t.Fatal("RU domain or its DNS did not bypass SSH")
	}
	if e := httpVia(t, s, "http://foreign.test:"+hp); e != nil {
		t.Fatal(e)
	}
	if tc.Load() == 0 || server.channels.Load() < 2 {
		t.Fatal("foreign DNS/TCP did not use SSH")
	}
	before := server.channels.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, e := Probe(ctx, fmt.Sprintf("127.0.0.1:%d", c.Proxy.Port), h.URL, fmt.Sprintf("127.0.0.1:%d", p))
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(result, "UDP DNS") || server.channels.Load() < before+2 {
		t.Fatal("probe failed to exercise UDP UoT", result)
	}
}
