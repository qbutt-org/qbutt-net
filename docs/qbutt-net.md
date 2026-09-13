# qbutt-net

qbutt-net wraps existing public Mihomo adapters in a child process for [qbutt](https://github.com/qbutt-org/qbutt). It opens one authenticated loopback SOCKS listener per selected proxy entry. It does not run Mihomo's ordinary configuration executor, REST API, system TUN, provider loader or routing groups. Upstream protocol implementations and licenses remain intact.

## Build and integration

Verified on Windows amd64 with Go 1.27.1 and Bun 1.4.0, from this repository with that compiler on `PATH`:

```powershell
$env:CGO_ENABLED = '0'
$env:GOTOOLCHAIN = 'local'
go build -trimpath -o ../qbutt-build/qbutt-net.exe ./cmd/qbutt-net
go build -trimpath -o ../qbutt-build/qbutt-gateway.exe ./cmd/qbutt-gateway
go build -trimpath -o ../qbutt-build/qbutt-gateway-lab.exe ./scripts/gateway-lab
go build -trimpath -o ../qbutt-build/qbutt-gateway-client-lab.exe ./scripts/gateway-client-lab
go vet ./cmd/qbutt-net ./cmd/qbutt-gateway ./component/gateway ./scripts/gateway-lab ./scripts/gateway-client-lab
bun scripts/qbutt-net-integration.ts ../qbutt-build/qbutt-net.exe
bun scripts/qbutt-net-dns-integration.ts ../qbutt-build/qbutt-net.exe
bun scripts/qbutt-gateway-integration.ts ../qbutt-build/qbutt-gateway.exe ../qbutt-build/qbutt-gateway-lab.exe
bun scripts/qbutt-net-gateway-client-integration.ts ../qbutt-build/qbutt-net.exe ../qbutt-build/qbutt-gateway.exe ../qbutt-build/qbutt-gateway-client-lab.exe
git diff --check
```

The Bun fixture creates a temporary local upstream SOCKS/echo endpoint and profile, then exercises real TCP and UDP payloads, authentication failures, generation guards, import limits, external credential rejection, close, EOF, shutdown and invalid frames. An optional second argument after the executable selects the loopback interface. The fixture never reads a live profile or edits another client's settings. Linux builds are supported by the source but remain unverified here.

The DNS fixture uses two local TLS SOCKS adapters and a separate bootstrap DNS endpoint. It verifies independent A/AAAA results for the same name, preserved TLS server names, numeric IPv4/IPv6 destinations in real TCP/UDP relays, CNAME traversal, TTL caching and expiry, malformed responses, close cancellation and generation isolation. A local GOST endpoint that accepts TCP without answering verifies handshake timeout and pending TCP/UDP close. The fixture also verifies that `localhost` uses the selected path and that an imported rogue DNS endpoint receives no connections. It does not modify the machine's DNS settings or claim to intercept an actual system resolver. Public resolver reachability, physical-interface routing and external IPv6 connectivity need separate live probes.

The gateway fixture launches and restarts the actual gateway process with generated certificates. It verifies the exact allowed client certificate across control, work and QUIC, the one-tenant limit, listener and connection quotas, TCP backpressure isolation, lease renewal/expiry/replacement, QUIC carrier failure, 1,200-, 1,500- and 65,507-byte UDP datagrams, reordered and duplicate fragments, incomplete-fragment expiry and bounds, aggregate rate limits, reflection rejection and bounded diagnostics. Its listeners are loopback fixtures; it does not claim public reachability through a real firewall or NAT.

The gateway-client fixture launches qbutt-net, qbutt-gateway and a generated selected SOCKS adapter as separate processes. It verifies that TLS control, independent TCP work connections and QUIC datagrams all traverse that adapter; then it transfers TCP and fragmented UDP payloads through the leased loopback endpoint, validates the original peer endpoint, four bounded UDP associations, authenticated local relay, counters, renewal and generation advancement. Fault cases cover lease expiry, carrier loss, exact terminal events, stale generation rejection, explicit-close suppression, fail-closed UDP, path cleanup, shutdown and parent EOF. This remains a loopback endpoint test and does not claim Internet reachability.

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
{"v":4,"id":1,"method":"hello"}
{"v":4,"id":1,"result":{"protocol":4,"name":"qbutt-net","upstreamRevision":"d3ec342d441b086ec4318332f59dd05d8a2b5697","maxFrameBytes":65536}}
```

Requests use these fields at the top level:

| Method | Additional fields | Result |
|---|---|---|
| `hello` | none | Protocol/build base and frame limit |
| `list` | `configPath` | `proxies: [{name,type}]` |
| `status` | none | Active `paths: [{pathId,generation,wire}]`, ordered by path ID |
| `open` | `configPath`, `proxyName`, `pathId`, `generation`, `interfaceName`, `dns` | Bound listener, private credentials and source capabilities |
| `resolve` | `pathId`, `generation`, `host`, `family` | `addresses: [numeric IP]`, at most 64 |
| `gateway.open` | `pathId`, `generation`, `gateway` | Verified lease and stable local relay endpoint |
| `gateway.renew` | `pathId`, `generation` | Same lease endpoint and relay with a later expiry |
| `gateway.close` | `pathId`, `generation` | `{}` after lease and relay retirement |
| `close` | `pathId`, `generation` | `{}` after tracked I/O stops |
| `shutdown` | none | `{}`, then process exit |

`configPath` is an absolute local regular YAML/JSON file, capped at 2 MiB. UNC/device paths are rejected. The parent downloads any subscription into its own private cache; this process imports only its `proxies` sequence, capped at 1,024 entries. Names must be unique, nonempty, free from control characters and at most 128 UTF-8 bytes. `list` returns explicit `response_limit` if its complete response would exceed the frame limit; it never silently truncates the subscription.

`proxyName` selects exactly one concrete adapter. Direct bypass, routing groups, recursive dialer dependencies and system adapters are rejected. Case/underscore aliases cannot bypass routing-field checks. All other transport parameters are retained. File-backed `certificate`/`private-key` fields are rejected recursively; inline PEM credentials remain available. MASQUE's scalar private key is an inline protocol parameter.

The parent supplies the physical interface by the Go/Windows friendly interface name, such as the Qt `humanReadableName()`. It must exist and be up at open time. The supplied value replaces every imported interface override; imported routing marks are discarded. Adapter connection errors remain errors, without a direct fallback.

Protocol 4 requires an explicit parent-owned DNS policy on every open, path status counters, optional gateway methods and serialized events; older protocols are rejected. A basic configurable public-resolver default can be supplied by the desktop client:

```json
{"dns":{"server":"1.1.1.1:53","bootstrapServer":"1.1.1.1:53","family":"dual"}}
```

Both endpoints must be numeric IP:port addresses. Torrent A/AAAA queries use DNS-over-TCP through the selected adapter to `server`. `family` is `ipv4`, `ipv6` or `dual` and constrains torrent resolution, including numeric payload destinations. Bootstrap independently permits both address families and uses DNS-over-TCP to `bootstrapServer`, physically bound to `interfaceName` with fallback binding disabled. Only the selected proxy's server hostname (and DNS CNAMEs needed to resolve it) may use bootstrap. The original server field is retained for TLS/SNI. Numeric proxy servers need no bootstrap query. A SOCKS server's domain-form UDP relay response is rejected; unspecified UDP relay IPs resolve the original server through its bootstrap resolver.

Both TCP destinations and every UDP datagram are resolved to numeric metadata before the adapter sees them. Each generation owns a 128-entry positive DNS cache, bounded by the received TTL and 60 seconds; TTL zero is never reused. A/AAAA results are limited to 64 addresses, CNAME traversal to eight names, and each resolution to five seconds. There is no OS resolver, hosts-file or subscription DNS fallback. The child's process-global resolver entrypoints are closed defaults; active resolver objects are passed only through their path's dialer. DNS connections are tracked and cancelled on path close. An in-flight serial `resolve` can delay the next control operation or EOF processing by at most the five-second resolution bound.

Dynamic ECH discovery, Hysteria2 realm discovery and TLSMirror auxiliary traffic options are rejected explicitly; inline ECH configuration remains supported. Hysteria's raw `faketcp` transport is rejected because it bypasses the physical dialer. Adapter-local `dns` and `remote-dns-resolve` values are discarded in favor of the parent policy. Existing ordinary Mihomo resolver behavior is preserved outside qbutt-net.

An `open` result has this shape (credentials below are illustrative):

```json
{"v":4,"id":3,"result":{"pathId":"path-1","generation":1,"interfaceName":"Ethernet","host":"127.0.0.1","port":50000,"socksUsername":"example","socksPassword":"example","capabilities":{"tcp":"supported","udp":"source-supported","dns":"path-tcp","publicTcp":"unknown","publicUdp":"unknown","measurement":"not-probed"}}}
```

UDP is `source-supported` or `source-unsupported` according to the adapter's `SupportUDP()`. TCP availability describes the source adapter API. DNS `path-tcp` describes the configured resolver ownership and transport. These fields do not mean a successful connection or verified egress. No health state, public port, latency or loss is invented. The parent detects child process failure; `gatewayClosed` reports only terminal retirement of an installed gateway.

`status` exposes real traffic counters for each active exact path generation. `wire` has exactly `relayDownloadBytes`, `relayUploadBytes`, `carrierDownloadBytes`, `carrierUploadBytes`, `carrierDownloadPackets`, `carrierUploadPackets` and `relayDownloadCopies`. They are unsigned JSON-safe integers: each starts at zero, increases monotonically, saturates at 2^53−1, and disappears when the path closes. A snapshot reads independently updated counters and can straddle concurrent I/O. Download is toward the local SOCKS or inbound-relay client; upload is away from it. Relay byte counters contain payload bytes accepted by the next local socket or carrier API, not end-to-end remote delivery. UDP download bytes are summed across successful local fanout copies, and `relayDownloadCopies` counts those copies. Carrier counters cover only gateway control, work and QUIC connections at the selected adapter's TCP or packet API; they stay zero when no gateway connection has been attempted. They include TLS or QUIC framing visible there but cannot include encapsulation hidden below that API. Carrier packet counters count only successful packet-API reads and writes because TCP packet boundaries are unavailable. These values are traffic diagnostics, not verified payload or reachability measurements, and contain no adapter name, endpoint, error or credential.

Failures use fixed codes and no raw adapter/parser data:

```json
{"v":4,"id":4,"error":{"code":"generation_mismatch","message":"generation_mismatch"}}
```

Codes include `protocol_mismatch`, `hello_required`, `invalid_request_id`, `unknown_method`, `absolute_config_path_required`, `config_unreadable`, `config_not_regular`, `config_limit`, `invalid_config`, `no_proxies`, `proxy_limit`, `invalid_proxy_identity`, `proxy_not_found`, `unsupported_proxy_type`, `proxy_chain_not_supported`, `external_credentials_not_supported`, `invalid_path`, `path_exists`, `path_not_found`, `path_limit`, `generation_mismatch`, `interface_required`, `interface_unavailable`, `adapter_rejected`, `listener_failed`, `credentials_failed` and `response_limit`.

DNS-specific failures are `dns_policy_required`, `invalid_dns_policy`, `invalid_dns_family`, `path_dns_failed`, `auxiliary_dns_not_supported` and `unbound_transport_not_supported`. None includes the hostname, subscription URL or upstream error text.

Gateway failures use `invalid_gateway`, `gateway_credentials_unreadable`, `gateway_credentials_invalid`, `gateway_relay_failed`, `gateway_connect_failed`, `gateway_authentication_failed`, `gateway_protocol_error`, `gateway_datagrams_failed`, `gateway_lease_rejected`, `gateway_exists`, `gateway_not_open`, `gateway_renew_failed` and `gateway_close_failed`. qbutt-net never returns the remote gateway's raw error.

## Payload and lifecycle

Listeners bind to IPv4 loopback on ephemeral ports with independent cryptographically random username/password pairs. SOCKS5 requires username/password authentication; CONNECT succeeds only after the selected adapter dials. BIND is unsupported. UDP ASSOCIATE requires an authenticated TCP association, gets its own ephemeral loopback UDP socket, and accepts only the associated loopback IP and UDP source port. When the client initially supplies port zero, the first valid datagram establishes that port, as in ordinary SOCKS5. The private endpoint and association are not a security boundary against malicious code already running as the same user.

At most eight paths and 512 tracked socket handles per path exist. Handshakes and adapter creation for a connection have deadlines; relay buffers are fixed. Close cancels in-progress dials, closes listeners and accepted TCP/UDP resources, closes the adapter and waits for its handlers. Generation must match before close. Restart creates new ports and credentials. Raw upstream logs are discarded; stderr contains only a fixed terminal control error when necessary.

## Optional inbound gateway

`qbutt-gateway` is a separately deployed reverse-listener service. Its server-owned JSON configuration names a TLS certificate/private key, a client CA and the lowercase or uppercase 64-hex `clientCertificateSHA256` of the one allowed client leaf certificate. Normal CA validation still runs first. The fingerprint is then compared exactly for control, TCP work and QUIC handshakes. The first release requires `maxClients: 1`; another CA-signed certificate is rejected during TLS rather than being admitted as a second tenant.

The remaining bounded settings are `controlAddress`, `datagramAddress`, numeric `listenerIP` and `advertiseIP`, `allowedPorts`, `maxLeases`, `maxTCPPerLease`, `maxTCP`, `maxTTLSeconds`, `maxUDPPacketsPerSecond` and `maxUDPBytesPerSecond`. Defaults supplied by the executable are one client, eight leases, 32 TCP peers per lease, 256 TCP peers total, a 120-second maximum lease, 512 original UDP datagrams per second and 32 MiB of original UDP payload per second. A configured UDP byte rate must permit one maximum 65,507-byte UDP payload. Opening more leases does not multiply the shared tenant rate budget.

Control frames are length-prefixed JSON over TLS 1.3. TCP peers are announced to the control session and joined to a separately authenticated TLS work connection. UDP payload uses QUIC DATAGRAM frames. One original UDP datagram is split into at most 64 fragments of at most 1,024 payload bytes and reassembled before the gateway writes exactly one UDP datagram to the public socket. Fragment identity includes lease, generation and a nonzero message number; endpoint, total size and fragment count must agree. Reassembly accepts reordered fragments, suppresses fragment and completed-message duplicates, and bounds incomplete state to 32 datagrams and 2,096,224 declared bytes for two seconds. Queues hold at most 16 complete outgoing datagrams.

An authenticated control client can request `stats`. The result contains only aggregate payload, fragment, expiry and drop counters; it contains no certificate identity, lease token or remote endpoint. Rate, queue, policy and reassembly pressure have distinct counters. These are process-lifetime diagnostics, reset on an actual gateway process restart.

qbutt-net accepts `gateway.open` only for an existing exact path generation. Its `gateway` object contains `controlAddress`, `datagramAddress`, `serverName`, absolute `caPath`, `certificatePath`, `privateKeyPath`, `port`, `tcp`, `udp` and `ttlSeconds`. It resolves gateway hostnames with that path's resolver, carries TLS control and every TCP work connection through the selected adapter, and carries QUIC through the adapter's packet API. No direct network fallback exists. UDP can be requested only when that adapter reports UDP support.

Successful open and renew responses contain exactly `pathId`, `generation`, `publicEndpoint`, `tcp`, `udp`, `expiresUnixMilli`, `relayHost` and `relayPort`. Renewal must preserve the gateway lease, public endpoint, transport flags and one stable loopback relay. A replacement requires a later path generation. Closing the gateway retires the public lease, all work connections, pending tickets, QUIC and the relay; closing the path or parent pipe also performs that cleanup.

Unexpected control, carrier or lease retirement of a published gateway emits exactly one serialized terminal event after internal retirement: `{"v":4,"id":0,"event":"gatewayClosed","pathId":"path-1","generation":1,"reason":"gateway_closed"}`. These are its only six fields, and `gateway_closed` is the only reason value. No `incomingTcp` or successful `gateway.open` or `gateway.renew` response for that generation follows the terminal event. An explicit parent `gateway.close`, path `close`, `shutdown` or parent-pipe EOF emits no such event; shutdown and EOF suppress events for every path before cleanup begins. The parent retires descriptors only when both path ID and generation match its active state; stale or duplicate events have no effect.

Each accepted public TCP peer uses one authenticated work connection. Once work authentication succeeds, qbutt-net writes one serialized parent event with `v:4`, `id:0`, `event:"incomingTcp"`, the exact `pathId`, `generation`, numeric `remote`, `publicEndpoint`, `relayHost:"127.0.0.1"`, `relayPort` and a 64-character lowercase `relayToken`. The parent has five seconds to connect to the relay and write 37 bytes: ASCII `QBIN`, byte `1`, then the 32 raw token bytes. Tickets are single-use; at most 64 wait and at most 32 relay handshakes run concurrently.

For UDP, one path generation owns one public gateway carrier shared by at most four authenticated local SOCKS UDP associations. Outbound payloads from every association use that carrier. Each valid public reply is returned to every active association as an ordinary SOCKS UDP response with the original source endpoint; the application layer owns any protocol demultiplexing. A fifth simultaneous association is rejected. The effective payload limit at this SOCKS boundary is 65,485 bytes, leaving room for the largest numeric IPv6 source envelope inside one legal UDP datagram. An oversized local payload retires only its sending association; an oversized public reply retires every association because none can encode it at this boundary. The gateway carrier itself retains its 65,507-byte transport limit. Starting a UDP gateway retires existing direct UDP associations. Gateway expiry or carrier failure retires all its associations and rejects replacements until the parent advances the path generation, so a lease failure cannot change routes in place. A TCP-only gateway leaves ordinary adapter UDP unchanged. Reflection, rate, replay and reassembly policy stays owned by qbutt-gateway.

## Current boundaries

The qbutt-net child is one explicit outbound proxy path. The optional gateway implements authenticated reverse TCP and UDP listeners, but the local fixture does not establish public reachability, firewall/NAT policy, independent remote egress, transport-specific live throughput, UDP mapping stability or application-wide discovery policy. In particular, physical interface binding does not prove bypass of another system TUN. Do not label the outbound prototype “Tunnels only”. TUIC is currently rejected because the pinned upstream adapter does not implement deterministic close of its QUIC pool; enabling it requires fixing and probing that lifecycle first.
