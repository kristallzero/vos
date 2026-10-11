# VoS architecture and roadmap

## Scope and status

VoS is an experimental SSH tunnel client with system TCP/UDP capture and split
routing. The repository contains the shared Go core, CLI, server installer,
routing data, tests, and documentation. The current release is a headless alpha;
planned graphical and mobile clients are not implemented.

The core embeds sing-box with pinned dependencies and is licensed under
GPL-3.0-or-later. Future shells are intended to reuse the Go library rather
than process packets in a UI runtime. Flutter/Dart is a candidate for a desktop
UI; mobile integration would use Kotlin/VpnService and Swift/NetworkExtension.

## Network architecture

On the client, TUN and the optional SOCKS5 proxy feed a single router. TCP chosen
for tunneling uses SSH `direct-tcpip`. UDP uses SOCKS/UoT v2 over SSH to a loopback
relay on the VPS. The relay reconstructs UDP datagrams and carries replies back
over the same transport. The server exposes only SSH TCP, on port 443 by default.
No external UDP port, IP forwarding, or server-side TUN interface is required.

TCP and UoT use separate SSH connections to reduce interference between traffic
classes. UDP over SSH still inherits head-of-line blocking from outer TCP.
Latency-sensitive calls and games need measurement on actual networks. ICMP
and other non-TCP/UDP IP protocols are outside the current scope.

SSH connections, direct sockets, and bootstrap DNS must use the physical network
rather than loop back into TUN. The core supports an explicit interface and
uses automatic physical-interface detection in TUN mode where available.

Connections require a trusted, pinned server host key. Private keys are loaded
from user-supplied files and must not be committed or included in diagnostics.
Key passphrases are read from an environment variable, never stored in profile
JSON, and omitted from rendered engine options.

## Routing and DNS

The top-level `ip_mode` defaults to `ipv4_only`, also when omitted by legacy
profiles. Before sniffing or evaluating route exceptions, the router rejects
IPv6 flows locally with an active TCP/ICMP rejection. Burst protection must not
turn these rejections into silent drops. TUN retains IPv6 capture to prevent
captured traffic from bypassing this policy. Port 53 DNS interception precedes
the IPv6 guard so an IPv6 resolver address can still be handled locally.
`dual_stack` explicitly restores IPv6 forwarding and requires IPv6 egress on
the VPS and on the local network for direct destinations.

Routing priority after domain resolution:

1. User force-tunnel domains or IP ranges.
2. User force-direct domains or IP ranges.
3. Private/local networks, if bypass is enabled.
4. Russian domains and their supporting resources, if RU bypass is enabled.
5. Russian IPv4/IPv6 ranges, if RU bypass is enabled.
6. Remaining TCP over SSH and remaining UDP over UoT over SSH.

The embedded snapshot combines MetaCubeX Russian IP and domain datasets with
the supplementary suffixes in `core/assets/manual-domains.json`. It includes
`.ru`, `.su`, and `.xn--p1ai`. Provenance, upstream hashes, and a snapshot date
are retained in `core/assets/rules.json`; see [THIRD_PARTY.md](THIRD_PARTY.md).

Rule updates are explicit CLI operations. They use HTTPS, validate size, schema,
and nonempty datasets, and replace both datasets in one atomic file operation.
A failed update preserves the previous bundle. Existing processes do not reload
rules automatically. Shared CDNs, application-specific DoH, and ECH limit the
accuracy of domain classification; user overrides address those cases.

DNS follows the domain policy: Russian and force-direct domains resolve directly;
other domains resolve through SSH. Bootstrap resolution of the SSH server is
direct. IP overrides apply after DNS and do not change the DNS policy for that
domain. In `ipv4_only`, core DNS and route resolution use IPv4 only: AAAA queries
receive a successful empty response without upstream traffic, and IPv6 address
hints are removed from HTTPS records. In `dual_stack`, DNS prefers IPv4 while
retaining AAAA answers. TUN intercepts DNS, while SOCKS treats DNS packets as
ordinary traffic; hostname resolution performed by the core follows `ip_mode`.
TUN is configured with both IPv4 and IPv6 addresses in either mode. IPv6-only
destinations are unavailable in `ipv4_only`; applications using cached IPv6
addresses or their own DNS still receive a local IPv6 rejection.

## Current headless client

- Shared Go core separated from the CLI, available at
  `github.com/kristallzero/vos/core`.
- CLI commands for profile creation, validation, client startup, engine option
  rendering, TCP/UDP probing, rule updates, and relay initialization/startup.
- Proxy mode without administrative privileges; TUN mode with the platform
  permissions needed for network interfaces and routes.
- Advisory locking to prevent concurrent runs of one profile.
- Normal SIGINT/SIGTERM shutdown closes listeners and transports. TUN cleanup
  on normal shutdown is supplied by sing-box.
- Lazy SSH dialing and reconnects for new requests after a disconnect; existing
  TCP sessions are not restored.

The installer targets Debian/Ubuntu with systemd. Dedicated mode adds a separate
SSH listener and an unprivileged loopback relay. It validates configuration
before startup and restores managed files and service state after failures.
The administrative SSH service and unrelated listeners are preserved.
`--reuse-ssh` installs the relay for an existing listener; that listener must
already allow TCP forwarding. The installer accepts a prebuilt Linux binary
and does not download executables.

## Verification and limitations

Go integration tests generate their own keys and use an in-process SSH server
to exercise TCP/UDP, pinned host keys, reconnects, DNS policy, direct/tunnel
overrides, and profile locking. CI also runs race detection, static checks,
vulnerability scanning, and cross-platform builds.

The Debian container tests use real OpenSSH and VoS but emulate service lifecycle
with a test `systemctl`. They cover install, upgrade, rollback, listener ownership,
loopback binding, SSH settings, and reuse. The optional privileged container test
creates a real Linux TUN interface and checks addresses, routes, and SIGTERM
cleanup. Neither test establishes real systemd boot or service sandbox behavior.

Before advertising stable system-wide VPN support, testing must cover:

- Real macOS, Windows, and Linux TUN traffic capture, including both IP families.
- Real systemd startup, restart, reboot, and service sandboxing on a VPS or VM.
- Process crashes and forced termination, with DNS and route restoration.
- Wi-Fi/network changes and sleep/wake recovery.
- Platform kill switches and leak behavior when the tunnel is unavailable.
- Latency and loss behavior for UDP workloads on real SSH links.

These are open roadmap items. TUN mode currently has no complete platform kill
switch and should be treated as experimental.

## Desktop roadmap

A desktop shell would add profiles, public-setting import, connect/disconnect,
proxy/TUN selection, route exceptions, traffic statistics, logs, tray integration,
and autostart. Packaging, updates, and recovery after network changes are also
required.

Linux and Windows should use a separate service with authenticated local IPC;
a privileged process must not accept arbitrary shell commands. macOS needs a
NetworkExtension and packaging design suitable for its distribution channel.
App Store extensions and Developer ID system extensions have different
requirements.

## Mobile roadmap

Android integration would use a foreground VpnService, TUN file descriptors,
`protect()` for external sockets, network transition handling, and Android
Keystore-backed secret storage.

iOS integration would use a Packet Tunnel Provider, entitlements, App Groups,
Keychain, On Demand rules, and careful extension lifecycle/resource handling.
Native included/excluded routes work by IP; domain exceptions and DNS require
platform testing under [Apple TN3120](https://developer.apple.com/documentation/technotes/tn3120-expected-use-cases-for-network-extension-packet-tunnel-providers).
Mobile clients should embed the core rather than invoke a desktop SSH process.

## Other future work

Linux/OpenWrt console builds may be possible when architecture, memory, and CPU
resources are suitable. Universal router support, existing TCP session recovery,
SSH camouflage as HTTPS, and ICMP transport are not part of the current release.
