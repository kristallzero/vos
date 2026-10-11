# Third-party components and routing data

VoS is licensed under **GPL-3.0-or-later**; see [LICENSE](LICENSE). Third-party
components retain their own copyright and license notices.

## Networking components

VoS embeds [sing-box](https://github.com/SagerNet/sing-box/tree/v1.14.3) v1.14.3,
including its SSH, SOCKS/UoT, DNS, routing, and TUN implementations. sing-box is
licensed under GPL-3.0-or-later. Its original copyright, license, warranty, and
name/association notice is preserved in [licenses/sing-box-GPL.txt](licenses/sing-box-GPL.txt).
The full GNU GPL v3 text is included in the root [LICENSE](LICENSE).

`internal/sshtransport/outbound.go` is derived from
[sing-box v1.14.3's SSH adapter](https://github.com/SagerNet/sing-box/blob/v1.14.3/protocol/ssh/outbound.go)
under the same license. VoS adds TCP `CloseWrite` forwarding to preserve SSH
channel EOF without closing the response direction or releasing the stream.
Keep the local adapter aligned with upstream when updating sing-box, and remove
it when an upstream release provides this behavior.

The resolved Go dependency graph is pinned in `go.mod` and `go.sum`.
[THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt) contains the root license,
copying, copyright, and notice files from the direct and indirect modules pinned in `go.mod`,
including dependencies used on other supported platforms and source-archive
links for each module. Regenerate it after
dependency changes:

```bash
go mod download
go run scripts/collect-licenses.go
```

The generator reads downloaded module metadata and licensing files. It does not
include module cache paths in its output and fails if a module has no recognized
licensing file. Review license changes when updating dependencies.

## Bundled routing data

The embedded Russian routing snapshot comes from
[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat), branch
`sing`, snapshot commit `d9e3c4c09747d325d28e9bfe8829011135cfbbbf`:

- `geo/geoip/ru.json` and `geo/geosite/category-ru.json` provide the upstream
  IP and domain datasets.
- Source URLs and SHA256 hashes of the original documents, plus the snapshot
  date, are recorded in `core/assets/rules.json`.
- `core/assets/manual-domains.json` is the supplementary domain-suffix list
  distributed with VoS under GPL-3.0-or-later. It includes Russian suffixes and
  service domains and is reapplied by the rule updater.

MetaCubeX publishes the routing data repository under
[GNU GPL v3](https://github.com/MetaCubeX/meta-rules-dat/blob/master/LICENSE).
The full license text is included in [LICENSE](LICENSE). Preserve these source
references and snapshot metadata when redistributing the data.

## Binary redistribution

Include `LICENSE`, `THIRD_PARTY.md`, `THIRD_PARTY_NOTICES.txt`, and the `licenses/`
directory with distributed binaries. Provide access to the complete corresponding
source for the exact release, including the build/install scripts, pinned Go
dependencies, and routing data. State the source location alongside the binaries
and retain third-party attribution and warranty notices. A future tagged release
should link to its matching source rather than a moving development branch.

The build workflow prepares downloadable CI artifacts with the executable and
these notices; it does not create a GitHub Release or publish binaries.

## Technical references

- <https://sing-box.sagernet.org/configuration/outbound/ssh/>
- <https://sing-box.sagernet.org/configuration/outbound/socks/>
- <https://sing-box.sagernet.org/configuration/shared/udp-over-tcp/>
- <https://sing-box.sagernet.org/configuration/inbound/tun/>
- <https://developer.android.com/develop/connectivity/vpn>
- <https://developer.apple.com/documentation/technotes/tn3120-expected-use-cases-for-network-extension-packet-tunnel-providers>
