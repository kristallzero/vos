// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 VoS contributors.

package core

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSecurityValidation(t *testing.T) {
	c, _ := fixture(t)
	for _, change := range []func(*Config){func(c *Config) { c.SSH.HostKeys = nil }, func(c *Config) { c.Proxy.Listen = "0.0.0.0" }, func(c *Config) { c.Mode = "tun"; c.TUN.Address = []string{"172.31.255.1/30"} }, func(c *Config) { c.Routes.ForceTunnelIPs = []string{"bad"} }, func(c *Config) { c.DNS.Direct = "dns.example" }} {
		bad := c
		change(&bad)
		if e := bad.Validate(); e == nil {
			t.Fatal("invalid config accepted")
		}
	}
	r := DefaultRelayConfig()
	r.Listen = "0.0.0.0"
	if e := r.Validate(); e == nil {
		t.Fatal("public relay accepted")
	}
	var cfg Config
	if e := DecodeStrict([]byte(`{"unknown":true}`), &cfg); e == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestRulesUpdateKeepsPreviousBundleOnFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	old := []byte("old bundle stays intact\n")
	os.WriteFile(path, old, 0600)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "geoip") {
			w.Write([]byte(`{"version":3,"rules":[{"ip_cidr":["5.8.0.0/16"]}]}`))
		} else {
			w.Write([]byte(`{"version":3,"rules":[]}`))
		}
	}))
	defer s.Close()
	if e := updateRules(context.Background(), path, s.Client(), s.URL+"/"); e == nil {
		t.Fatal("empty domain set accepted")
	}
	data, _ := os.ReadFile(path)
	if !bytes.Equal(old, data) {
		t.Fatal("failed update overwrote old rules")
	}
}
func TestKnownHostsSelectsOnlyTarget(t *testing.T) {
	a, _ := keyPair(t)
	b, _ := keyPair(t)
	path := filepath.Join(t.TempDir(), "known_hosts")
	key := func(k ssh.Signer) string { return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k.PublicKey()))) }
	os.WriteFile(path, []byte("other.test "+key(a)+"\n[correct.test]:443 "+key(b)+"\n"), 0600)
	keys, e := ReadHostKeys(path, "correct.test", 443)
	if e != nil || len(keys) != 1 || keys[0] != key(b) {
		t.Fatalf("wrong known_hosts selection: %v %v", keys, e)
	}
	if _, e = ReadHostKeys(path, "missing.test", 443); e == nil {
		t.Fatal("unrelated key trusted")
	}
}
func TestOfflineRulesAndTUNOptions(t *testing.T) {
	r, e := LoadRules("")
	if e != nil {
		t.Fatal(e)
	}
	if len(r.RUIP[0].IPCIDR) < 1000 {
		t.Fatal("missing RU IP snapshot")
	}
	c, _ := fixture(t)
	c.Mode = "tun"
	b, e := NewClient(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	b.Close()
}
func TestLockRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.lock")
	release, e := Lock(path)
	if e != nil {
		t.Fatal(e)
	}
	if r, e := Lock(path); e == nil {
		r()
		t.Fatal("second process acquired lock")
	}
	release()
	r, e := Lock(path)
	if e != nil {
		t.Fatal(e)
	}
	r()
}
