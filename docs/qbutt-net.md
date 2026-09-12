# qbutt-net

qbutt-net wraps existing public Mihomo adapters in a child process for [qbutt](https://github.com/qbutt-org/qbutt). It opens one authenticated loopback SOCKS listener per selected proxy entry. It does not run Mihomo's ordinary configuration executor, REST API, system TUN, provider loader or routing groups. Upstream protocol implementations and licenses remain intact.

## Build and integration

Verified on Windows amd64 with Go 1.27.1 and Bun 1.4.0, from this repository with that compiler on `PATH`:

```powershell
$env:CGO_ENABLED = '0'
$env:GOTOOLCHAIN = 'local'
go build -trimpath -o ../qbutt-build/qbutt-net.exe ./cmd/qbutt-net
go vet ./cmd/qbutt-net
bun scripts/qbutt-net-integration.ts ../qbutt-build/qbutt-net.exe
git diff --check
```

The Bun fixture creates a temporary local upstream SOCKS/echo endpoint and profile, then exercises real TCP and UDP payloads, authentication failures, generation guards, import limits, external credential rejection, close, EOF, shutdown and invalid frames. An optional second argument after the executable selects the loopback interface. The fixture never reads a live profile or edits another client's settings. Linux builds are supported by the source but remain unverified here.

The optional [manual component workflow](../.github/workflows/qbutt-net.yml) pins the official Windows amd64 [Go toolchain module archive](https://proxy.golang.org/golang.org/toolchain/@v/v0.0.1-go1.27.1.windows-amd64.zip) by SHA-256. That archive was verified through Go's `sum.golang.org` database before its hash was pinned; [Go documents this authenticated toolchain distribution](https://go.dev/doc/toolchain). Releases are built and verified locally, then uploaded. The workflow runs only when the user explicitly requests a manual Actions run; pushes and pull requests do not trigger CI.

## Release notices

After a clean build from the current source commit, collect notices for the exact executable:

```powershell
bun scripts/collect-notices.ts ../qbutt-build/qbutt-net.exe ../qbutt-build/net-notices
```

An optional third argument supplies the pinned Go executable when it is not on `PATH`. Include both generated `qbutt-net-notices.json` and `qbutt-net-notices.txt` in the portable package, alongside the Go toolchain license. The collector reads binary build metadata and `go list -deps -json`, requires matching source revisions and module versions, follows `Module.Replace`, and records exact source archive URLs and checksums. It copies LICENSE/COPYING/NOTICE/PATENTS/COPYRIGHT texts found inside each linked module. Missing notices stop collection; no aggregate license classification is inferred. The main component is identified by its Git commit, so shallow builds do not require an upstream-derived module pseudo-version.

## Private control channel

Launch `qbutt-net.exe --stdio` with private inherited stdin/stdout pipes, for example `QProcess` managed channels. This is the private parent-child equivalent of a current-user named pipe, with no externally connectable control endpoint. Do not forward these streams to a terminal, log, other process or TCP listener. The parent must close stdin when it no longer owns the child and enforce a shutdown timeout before killing an unresponsive child.

Each UTF-8 JSON object ends with LF. Maximum frame size including LF is 65,536 bytes. Malformed JSON and oversized frames close every path and exit nonzero. Requests execute in order; `id` and `generation` are positive integers at most 2^53−1. Responses echo the request ID. `hello` must precede every other method. Version mismatch is explicit; no version fallback is attempted.

```json
{"v":1,"id":1,"method":"hello"}
{"v":1,"id":1,"result":{"protocol":1,"name":"qbutt-net","upstreamRevision":"d3ec342d441b086ec4318332f59dd05d8a2b5697","maxFrameBytes":65536}}
```

Requests use these fields at the top level:

| Method | Additional fields | Result |
|---|---|---|
| `hello` | none | Protocol/build base and frame limit |
| `list` | `configPath` | `proxies: [{name,type}]` |
| `open` | `configPath`, `proxyName`, `pathId`, `generation`, `interfaceName` | Bound listener, private credentials and source capabilities |
| `close` | `pathId`, `generation` | `{}` after tracked I/O stops |
| `shutdown` | none | `{}`, then process exit |

`configPath` is an absolute local regular YAML/JSON file, capped at 2 MiB. UNC/device paths are rejected. The parent downloads any subscription into its own private cache; this process imports only its `proxies` sequence, capped at 1,024 entries. Names must be unique, nonempty, free from control characters and at most 128 UTF-8 bytes. `list` returns explicit `response_limit` if its complete response would exceed the frame limit; it never silently truncates the subscription.

`proxyName` selects exactly one concrete adapter. Direct bypass, routing groups, recursive dialer dependencies and system adapters are rejected. Case/underscore aliases cannot bypass routing-field checks. All other transport parameters are retained. File-backed `certificate`/`private-key` fields are rejected recursively; inline PEM credentials remain available. MASQUE's scalar private key is an inline protocol parameter.

The parent supplies the physical interface by the Go/Windows friendly interface name, such as the Qt `humanReadableName()`. It must exist and be up at open time. The supplied value replaces every imported interface override; imported routing marks are discarded. Adapter connection errors remain errors, without a direct fallback.

An `open` result has this shape (credentials below are illustrative):

```json
{"v":1,"id":3,"result":{"pathId":"path-1","generation":1,"interfaceName":"Ethernet","host":"127.0.0.1","port":50000,"socksUsername":"example","socksPassword":"example","capabilities":{"tcp":"supported","udp":"source-supported","dns":"system-unverified","publicTcp":"unknown","publicUdp":"unknown","measurement":"not-probed"}}}
```

UDP is `source-supported` or `source-unsupported` according to the adapter's `SupportUDP()`. TCP availability describes the source adapter API. DNS is reported as `system-unverified`. Neither means a successful connection or verified egress. No health state, public port, latency or loss is invented. The parent detects child process failure; no asynchronous health event exists in v1.

Failures use fixed codes and no raw adapter/parser data:

```json
{"v":1,"id":4,"error":{"code":"generation_mismatch","message":"generation_mismatch"}}
```

Codes include `protocol_mismatch`, `hello_required`, `invalid_request_id`, `unknown_method`, `absolute_config_path_required`, `config_unreadable`, `config_not_regular`, `config_limit`, `invalid_config`, `no_proxies`, `proxy_limit`, `invalid_proxy_identity`, `proxy_not_found`, `unsupported_proxy_type`, `proxy_chain_not_supported`, `external_credentials_not_supported`, `invalid_path`, `path_exists`, `path_not_found`, `path_limit`, `generation_mismatch`, `interface_required`, `interface_unavailable`, `adapter_rejected`, `listener_failed`, `credentials_failed` and `response_limit`.

## Payload and lifecycle

Listeners bind to IPv4 loopback on ephemeral ports with independent cryptographically random username/password pairs. SOCKS5 requires username/password authentication; CONNECT succeeds only after the selected adapter dials. BIND is unsupported. UDP ASSOCIATE requires an authenticated TCP association, gets its own ephemeral loopback UDP socket, and accepts only the associated loopback IP and UDP source port. When the client initially supplies port zero, the first valid datagram establishes that port, as in ordinary SOCKS5. The private endpoint and association are not a security boundary against malicious code already running as the same user.

At most eight paths and 512 tracked socket handles per path exist. Handshakes and adapter creation for a connection have deadlines; relay buffers are fixed. Close cancels in-progress dials, closes listeners and accepted TCP/UDP resources, closes the adapter and waits for its handlers. Generation must match before close. Restart creates new ports and credentials. Raw upstream logs are discarded; stderr contains only a fixed terminal control error when necessary.

## Current boundaries

This is one explicit outbound proxy path. Public inbound, independent remote egress, transport-specific live throughput, UDP mapping stability and full DNS/discovery policy are not established by local fixture success. Existing system DNS/bootstrap behavior is retained. In particular, physical interface binding does not prove DNS isolation or bypass of another system TUN. Do not label this prototype “Tunnels only”. TUIC is currently rejected because the pinned upstream adapter does not implement deterministic close of its QUIC pool; enabling it requires fixing and probing that lifecycle first.
