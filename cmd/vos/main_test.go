// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 VoS contributors.

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/kristallzero/vos/core"
	"golang.org/x/crypto/ssh"
)

func TestInitValidateAndRefuseOverwrite(t *testing.T) {
	dir := t.TempDir()
	_, k, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := ssh.NewSignerFromKey(k)
	if e != nil {
		t.Fatal(e)
	}
	block, e := ssh.MarshalPrivateKey(k, "")
	if e != nil {
		t.Fatal(e)
	}
	private, public, config := filepath.Join(dir, "client.key"), filepath.Join(dir, "server.pub"), filepath.Join(dir, "config.json")
	os.WriteFile(private, pem.EncodeToMemory(block), 0600)
	os.WriteFile(public, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0600)
	args := []string{"init", "--config", config, "--server", "127.0.0.1", "--user", "vos-test", "--identity", private, "--host-key-file", public}
	if e = run(args); e != nil {
		t.Fatal(e)
	}
	if e = run(args); e == nil {
		t.Fatal("init overwrote existing config")
	}
	if e = run([]string{"validate", "--config", config}); e != nil {
		t.Fatal(e)
	}
	c, e := core.LoadConfig(config)
	if e != nil {
		t.Fatal(e)
	}
	if c.SSH.Port != 443 || !c.Routes.BypassRU || c.IPMode != "ipv4_only" {
		t.Fatal("wrong initialized defaults")
	}
	if e = run([]string{"init", "--port", "443junk"}); e == nil {
		t.Fatal("invalid port accepted")
	}
}
