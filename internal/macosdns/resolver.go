// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 VoS contributors.

// Package macosdns manages a temporary SystemConfiguration DNS resolver through
// scutil, keeping the CLI build independent of cgo and persistent Wi-Fi settings.
package macosdns

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Resolver struct {
	cmd      *exec.Cmd
	input    io.WriteCloser
	done     chan struct{}
	closing  atomic.Bool
	once     sync.Once
	exitErr  error // Read only after done is closed.
	closeErr error
}

func Start(ctx context.Context, servers []netip.Addr) (*Resolver, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return start(ctx, exec.Command("/usr/sbin/scutil", "-p"), servers)
}

func start(ctx context.Context, cmd *exec.Cmd, servers []netip.Addr) (*Resolver, error) {
	if len(servers) == 0 {
		return nil, errors.New("no TUN DNS server available")
	}
	addresses := make([]string, 0, len(servers))
	for _, address := range servers {
		if !address.IsValid() || address.IsUnspecified() || address.Zone() != "" {
			return nil, fmt.Errorf("invalid DNS address: %s", address)
		}
		addresses = append(addresses, address.String())
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		input.Close()
		return nil, err
	}
	cmd.Stderr = cmd.Stdout
	if err = cmd.Start(); err != nil {
		input.Close()
		output.Close()
		return nil, err
	}
	r := &Resolver{cmd: cmd, input: input, done: make(chan struct{})}
	id := rand.Text()
	key := "State:/Network/Service/VoS-" + id + "/DNS"
	ready := make(chan struct{})
	var diagnostic strings.Builder
	go func() {
		scanner := bufio.NewScanner(output)
		confirmed := false
		for scanner.Scan() {
			line := scanner.Text()
			if diagnostic.Len() < 4096 {
				diagnostic.WriteString(line)
				diagnostic.WriteByte('\n')
			}
			if !confirmed && strings.Contains(line, "VoSResolverID : "+id) {
				confirmed = true
				close(ready)
			}
		}
		r.exitErr = errors.Join(scanner.Err(), cmd.Wait())
		close(r.done)
	}()
	// A supplemental resolver with the empty match domain covers all names.
	// "add ... temporary" ties this key to scutil's dynamic-store session:
	// EOF (including parent death) removes it, restoring the prior resolvers.
	// Read back the actual key: scutil can report permission errors yet exit 0.
	script := fmt.Sprintf("d.init\nd.add ServerAddresses * %s\nd.add SupplementalMatchDomains * \"\"\nd.add SupplementalMatchDomainsNoSearch # 1\nd.add SearchOrder # 1\nd.add VoSResolverID %s\nadd %s temporary\nshow %s\n", strings.Join(addresses, " "), id, key, key)
	if _, err = io.WriteString(input, script); err != nil {
		r.Close()
		return nil, fmt.Errorf("send resolver settings to scutil: %w", err)
	}
	select {
	case <-ready:
		return r, nil
	case <-r.done:
		r.Close()
		return nil, fmt.Errorf("scutil did not install the temporary resolver: %s (exit: %v)", strings.TrimSpace(diagnostic.String()), r.exitErr)
	case <-ctx.Done():
		r.Close()
		return nil, fmt.Errorf("waiting for scutil resolver confirmation: %w (%s)", ctx.Err(), strings.TrimSpace(diagnostic.String()))
	}
}

func (r *Resolver) Done() <-chan struct{} { return r.done }
func (r *Resolver) Closing() bool         { return r.closing.Load() }

func (r *Resolver) Close() error {
	r.once.Do(func() {
		r.closing.Store(true)
		r.input.Close()
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		select {
		case <-r.done:
			r.closeErr = r.exitErr
		case <-timer.C:
			r.cmd.Process.Kill()
			<-r.done
			r.closeErr = errors.New("scutil did not exit after EOF; terminated DNS session")
		}
	})
	return r.closeErr
}
