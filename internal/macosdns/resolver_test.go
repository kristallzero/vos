// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 VoS contributors.

package macosdns

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A child process models scutil's independent lifetime and its unusual failure
// mode: rejected writes can print an error while the process still exits zero.
// No test changes the machine's SystemConfiguration state.
func TestSCUtilProcess(t *testing.T) {
	mode := os.Getenv("VOS_SCUTIL_TEST_MODE")
	if mode == "" {
		return
	}
	var transcript strings.Builder
	scanner := bufio.NewScanner(os.Stdin)
	marker := ""
	for scanner.Scan() {
		line := scanner.Text()
		transcript.WriteString(line + "\n")
		if strings.HasPrefix(line, "d.add VoSResolverID ") {
			marker = strings.TrimPrefix(line, "d.add VoSResolverID ")
		}
		if strings.HasPrefix(line, "show ") {
			switch mode {
			case "success":
				fmt.Printf("<dictionary> {\n  VoSResolverID : %s\n}\n", marker)
			case "denied":
				fmt.Println("SCError: Permission denied\nNo such key")
			case "zero-exit":
				fmt.Println("SCError: Permission denied\nNo such key")
				os.Exit(0)
			case "no-confirmation":
				// Remain alive until the parent cancels startup and closes stdin.
			}
		}
	}
	if err := os.WriteFile(os.Getenv("VOS_SCUTIL_TEST_TRANSCRIPT"), []byte(transcript.String()), 0600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func scutilProcess(t *testing.T, mode string) (*exec.Cmd, string) {
	t.Helper()
	transcript := filepath.Join(t.TempDir(), "scutil.txt")
	cmd := exec.Command(os.Args[0], "-test.run=^TestSCUtilProcess$")
	cmd.Env = append(os.Environ(), "VOS_SCUTIL_TEST_MODE="+mode, "VOS_SCUTIL_TEST_TRANSCRIPT="+transcript, "GORACE=atexit_sleep_ms=0")
	return cmd, transcript
}

func TestTemporaryResolverLifecycle(t *testing.T) {
	cmd, transcript := scutilProcess(t, "success")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := start(ctx, cmd, []netip.Addr{netip.MustParseAddr("172.31.255.2")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	select {
	case <-r.Done():
		t.Fatal("scutil exited while the resolver was still needed")
	default:
	}
	// Canceling the startup context must not remove a successfully installed
	// resolver. Its lifetime belongs to the inbound's cleanup scope instead.
	cancel()
	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() {
			if err := r.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if !r.Closing() {
		t.Fatal("intentional shutdown not recorded")
	}
	select {
	case <-r.Done():
	default:
		t.Fatal("Close returned before the DNS session exited")
	}
	data, err := os.ReadFile(transcript)
	if err != nil {
		t.Fatal("subprocess did not receive EOF:", err)
	}
	script := string(data)
	if !strings.Contains(script, "d.add ServerAddresses * 172.31.255.2\n") || !strings.Contains(script, "d.add SupplementalMatchDomains * \"\"\n") || !strings.Contains(script, "/DNS temporary\nshow State:/Network/Service/VoS-") {
		t.Fatalf("resolver must cover all domains and be temporary: %s", script)
	}
	if strings.Contains(script, "Setup:/") {
		t.Fatal("persistent network configuration was modified")
	}
}

func TestResolverRequiresReadback(t *testing.T) {
	for _, mode := range []string{"zero-exit", "denied", "no-confirmation"} {
		t.Run(mode, func(t *testing.T) {
			cmd, _ := scutilProcess(t, mode)
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			r, err := start(ctx, cmd, []netip.Addr{netip.MustParseAddr("172.31.255.2")})
			if err == nil || r != nil {
				t.Fatal("DNS setup succeeded without a readback confirmation")
			}
			if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
				t.Fatal("failed startup left a subprocess running")
			}
			if mode != "no-confirmation" && !strings.Contains(err.Error(), "Permission denied") {
				t.Fatalf("scutil diagnostic was lost: %v", err)
			}
			if mode == "no-confirmation" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("startup did not preserve cancellation: %v", err)
			}
		})
	}
}

func TestResolverEOFEndsSession(t *testing.T) {
	cmd, transcript := scutilProcess(t, "success")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := start(ctx, cmd, []netip.Addr{netip.MustParseAddr("172.31.255.2")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	// Simulate the pipe closing on parent death, without the normal Close path.
	r.input.Close()
	select {
	case <-r.Done():
	case <-ctx.Done():
		t.Fatal("scutil did not exit after its parent pipe closed")
	}
	if _, err := os.Stat(transcript); err != nil {
		t.Fatal("subprocess did not finish EOF cleanup:", err)
	}
	if r.Closing() {
		t.Fatal("unexpected exit was reported as intentional")
	}
}

func TestResolverRejectsInvalidSettings(t *testing.T) {
	for _, servers := range [][]netip.Addr{nil, {{}}, {netip.IPv4Unspecified()}, {netip.MustParseAddr("fe80::1%en0")}} {
		cmd, _ := scutilProcess(t, "success")
		if _, err := start(context.Background(), cmd, servers); err == nil || cmd.Process != nil {
			t.Fatal("invalid settings launched a subprocess")
		}
	}
	cmd, _ := scutilProcess(t, "success")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := start(ctx, cmd, []netip.Addr{netip.MustParseAddr("172.31.255.2")}); !errors.Is(err, context.Canceled) || cmd.Process != nil {
		t.Fatal("canceled startup launched a subprocess:", err)
	}
}
