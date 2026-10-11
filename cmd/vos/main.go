// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 VoS contributors.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kristallzero/vos/core"
)

const version = "0.1.0"

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "VoS:", e)
		os.Exit(1)
	}
}
func flags(name string, args []string, setup func(*flag.FlagSet)) error {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	setup(f)
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	return nil
}
func run(args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	switch args[0] {
	case "version":
		fmt.Printf("VoS %s (sing-box 1.14.3)\n", version)
		return nil
	case "init":
		c := core.DefaultConfig()
		path, hostFile := "config.json", ""
		e := flags("init", args[1:], func(f *flag.FlagSet) {
			f.StringVar(&path, "config", path, "output config (never overwrite)")
			f.StringVar(&c.SSH.Server, "server", "", "SSH server")
			f.StringVar(&c.SSH.User, "user", "", "SSH user")
			f.StringVar(&c.SSH.PrivateKeyPath, "identity", "", "client private key path")
			f.StringVar(&hostFile, "host-key-file", "", "trusted server .pub or plain known_hosts")
			f.Func("port", "SSH port", func(s string) error {
				n, e := strconv.ParseUint(s, 10, 16)
				if e != nil {
					return e
				}
				if n == 0 || n > 65535 {
					return errors.New("port out of range")
				}
				c.SSH.Port = uint16(n)
				return nil
			})
		})
		if e != nil {
			return e
		}
		if hostFile == "" {
			return errors.New("--host-key-file is required; obtain the public key over a trusted channel")
		}
		c.SSH.HostKeys, e = core.ReadHostKeys(hostFile, c.SSH.Server, c.SSH.Port)
		if e != nil {
			return e
		}
		if c.SSH.PrivateKeyPath != "" {
			if strings.HasPrefix(c.SSH.PrivateKeyPath, "~/") {
				home, err := os.UserHomeDir()
				if err != nil {
					return err
				}
				c.SSH.PrivateKeyPath = filepath.Join(home, c.SSH.PrivateKeyPath[2:])
			}
			c.SSH.PrivateKeyPath, e = filepath.Abs(c.SSH.PrivateKeyPath)
			if e != nil {
				return e
			}
		}
		if e = c.Validate(); e != nil {
			return e
		}
		if e = core.WriteJSON(path, c, true); e == nil {
			fmt.Println("Created", path)
		}
		return e
	case "run", "validate", "render":
		path := "config.json"
		if e := flags(args[0], args[1:], func(f *flag.FlagSet) { f.StringVar(&path, "config", path, "client config") }); e != nil {
			return e
		}
		c, e := core.LoadConfig(path)
		if e != nil {
			return e
		}
		if args[0] == "render" {
			v, e := core.ClientOptions(c)
			if e != nil {
				return e
			}
			b, e := json.MarshalIndent(v, "", "  ")
			if e == nil {
				fmt.Println(string(b))
			}
			return e
		}
		var unlock func()
		if args[0] == "run" {
			unlock, e = core.Lock(path + ".lock")
			if e != nil {
				return e
			}
			defer unlock()
		}
		engine, e := core.NewClient(ctx, c)
		if e != nil {
			return e
		}
		defer engine.Close()
		if args[0] == "validate" {
			fmt.Println("Client config and key are valid")
			return nil
		}
		if e = engine.Start(); e != nil {
			return e
		}
		fmt.Fprintf(os.Stderr, "VoS %s started in %s mode\n", version, c.Mode)
		<-ctx.Done()
		return nil
	case "relay":
		if len(args) < 2 {
			return errors.New("use relay init|validate|run")
		}
		action := args[1]
		path := "relay.json"
		lockPath := ""
		c := core.DefaultRelayConfig()
		if e := flags("relay", args[2:], func(f *flag.FlagSet) {
			f.StringVar(&path, "config", path, "relay config")
			f.StringVar(&lockPath, "lock-file", "", "runtime lock path (default config.lock)")
		}); e != nil {
			return e
		}
		if action == "init" {
			return core.WriteJSON(path, c, true)
		}
		if action != "run" && action != "validate" {
			return errors.New("unknown relay action")
		}
		var e error
		c, e = core.LoadRelayConfig(path)
		if e != nil {
			return e
		}
		var unlock func()
		if action == "run" {
			if lockPath == "" {
				lockPath = path + ".lock"
			}
			unlock, e = core.Lock(lockPath)
			if e != nil {
				return e
			}
			defer unlock()
		}
		engine, e := core.NewRelay(ctx, c)
		if e != nil {
			return e
		}
		defer engine.Close()
		if action == "validate" {
			fmt.Println("Relay config is valid")
			return nil
		}
		if e = engine.Start(); e != nil {
			return e
		}
		<-ctx.Done()
		return nil
	case "rules":
		if len(args) < 2 || args[1] != "update" {
			return errors.New("use rules update --output ./rules.json")
		}
		path := "rules.json"
		if e := flags("rules update", args[2:], func(f *flag.FlagSet) { f.StringVar(&path, "output", path, "atomic rule bundle destination") }); e != nil {
			return e
		}
		if e := core.UpdateRules(ctx, path); e != nil {
			return e
		}
		fmt.Println("Updated", path)
		return nil
	case "probe":
		proxy, url, dns := "127.0.0.1:10818", "https://example.com", "1.1.1.1:53"
		if e := flags("probe", args[1:], func(f *flag.FlagSet) {
			f.StringVar(&proxy, "proxy", proxy, "SOCKS address")
			f.StringVar(&url, "url", url, "HTTP/HTTPS test URL")
			f.StringVar(&dns, "dns", dns, "UDP DNS test address")
		}); e != nil {
			return e
		}
		ctx, c := context.WithTimeout(ctx, 35*time.Second)
		defer c()
		v, e := core.Probe(ctx, proxy, url, dns)
		if e == nil {
			fmt.Println(v)
		}
		return e
	case "help", "--help", "-h":
		usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
func usage() {
	fmt.Println("VoS headless SSH TCP/UDP client\nCommands: init, validate, run, render, probe, rules update, relay init|validate|run, version\nUse <command> --help for flags. Key passphrase: VOS_KEY_PASSPHRASE.")
}
