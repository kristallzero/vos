# Contributing to VoS

VoS is an experimental alpha. Bug reports, documentation improvements, tests,
and focused pull requests are welcome. Discuss significant architecture or
routing-policy changes in an issue before implementing them.

## Development setup

Use Go 1.26.9 or a newer supported release with current security fixes. Bash is
needed for the build scripts; Docker is optional for isolated server tests.
The client itself does not need Python or an external sing-box executable.

```bash
git clone https://github.com/kristallzero/vos.git
cd vos
go mod download
bash scripts/build.sh
```

The networking core is in `core/`, the CLI in `cmd/vos/`, and the server installer
in `server/`. Read [SPEC.md](SPEC.md) for architecture, current guarantees, and
open platform work. Documentation and code comments should be in English.

## Before submitting a pull request

```bash
gofmt -w core cmd internal
go test -race -tags with_gvisor ./...
go vet -tags with_gvisor ./...
go mod verify
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 -tags with_gvisor ./...
bash -n server/install.sh scripts/build.sh tests/server/test.sh tests/server/tun-smoke.sh
```

For dependency changes, run `go mod tidy` and regenerate notices:

```bash
go mod download
go run scripts/collect-licenses.go
```

Use the installer and optional TUN container checks in [README.md](README.md)
when changing server setup, service lifecycle, or TUN behavior. Tests must use
temporary profiles and generated keys. Do not run the server installer on a
working production host as a substitute for isolated tests.

Keep changes focused. Describe the problem, resulting behavior, and checks run
in the pull request. Record unavailable platform checks explicitly. Add tests
for behavior changes and regressions, especially routing, DNS, host key trust,
shutdown, and rollback. Documentation-only changes need link and example review.

## Private information and security

Do not commit private keys, passphrases, tokens, real connection profiles,
personal paths, or private server details. `.gitignore` covers common names;
review the actual diff before submitting. Use reserved example addresses and
domains in examples. See [SECURITY.md](SECURITY.md) for private vulnerability
reporting. Avoid public issues for undisclosed security problems.

## License

By contributing, you agree that your original contribution is licensed under
GPL-3.0-or-later, as described in [LICENSE](LICENSE). Retain upstream copyright,
license, and attribution notices for third-party material and document its
source in [THIRD_PARTY.md](THIRD_PARTY.md).
