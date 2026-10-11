# Security policy

## Project status and updates

VoS is an experimental alpha. Security fixes target the current development
branch and the latest release once releases are available. Older versions have
no separate maintenance commitment. Build with Go 1.26.9 or a newer supported
release with current security fixes, and keep dependencies current.

## Report a vulnerability privately

After the repository is published, use GitHub's **Report a vulnerability**
feature in the repository's Security tab:

<https://github.com/kristallzero/vos/security/advisories/new>

The maintainer must enable private vulnerability reporting when creating the
public repository. If the private report form is unavailable, open a public
issue asking for a private contact channel, without disclosing vulnerability
details or attaching a proof of concept.

Include the affected version or commit, OS and architecture, proxy/TUN mode,
impact, minimal reproduction steps, and relevant redacted logs. Never include
private keys, passphrases, tokens, complete connection profiles, or private
server details. Do not post undisclosed vulnerabilities in public issues.

## Security boundaries and current limitations

- Server host keys must be obtained over a trusted channel and pinned. VoS
  rejects missing or mismatched trusted keys; an unverified key scan is not
  sufficient to establish trust.
- Client SOCKS and server relay listeners are restricted to loopback. Local
  processes able to connect to those listeners can use them; loopback is not
  per-user authentication on a shared machine.
- Russian domains/IP ranges and private networks bypass the tunnel by default.
  Their traffic and DNS queries intentionally use direct connections. Review
  these defaults and your overrides for your use case.
- A complete platform kill switch is not implemented. Forced termination,
  network changes, sleep/wake, and crash recovery of DNS/routes need further
  platform testing. TUN must not be assumed to prevent all traffic leaks.
- Application-specific DoH, shared CDNs, and ECH can limit domain classification.
  SSH tunnels do not make applications anonymous or disguise SSH as HTTPS.
- The passphrase environment variable stays out of JSON and rendered options,
  but its confidentiality depends on the host and process environment. Keep
  key files and profiles private. Elevated TUN launches need access to the key
  and any required passphrase through the platform's privilege mechanism.
- `render` excludes key contents and passphrases, but includes server addresses,
  public host keys, and the private key's filesystem path. Redact that metadata
  before sharing diagnostics. Logs may contain destinations and network details.

See [SPEC.md](SPEC.md) for verification scope and outstanding platform work.
