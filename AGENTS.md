# qbutt-net

This independent public fork owns qbutt-net, a separate payload transport process for the native [qbutt desktop client](https://github.com/qbutt-org/qbutt). Read that repository's architecture and implementation contracts before changing the cross-process boundary. Its public Mihomo base is `d3ec342d441b086ec4318332f59dd05d8a2b5697`. Preserve upstream source layout, Go module path, licenses and notices; do not import private fork history or service APIs.

## Ownership

- `cmd/qbutt-net/` owns bounded control IPC, selected-node import, authenticated loopback SOCKS and child lifecycle. `docs/qbutt-net.md` specifies the protocol and current limitations.
- Existing Mihomo adapters own transport protocols and physical socket binding. Reuse them; do not invent another transport stack or route through implicit groups.
- qbutt owns torrent state, path selection and UI. This process never knows pieces, file paths, storage policy or torrent session state.
- Import a selected proxy entry as data. Never execute subscription DNS, routing, provider, listener, TUN or system integration settings. Reject implicit dialer chains and external credential files, including aliases and nested options. Unknown capability stays unknown until measured.
- Control uses inherited private parent pipes; stdout contains only versioned JSONL. Credentials cross that channel only. Keep raw upstream logs and errors out of diagnostics.
- Parent EOF, shutdown and close must drain tracked TCP/UDP resources. Opening a SOCKS listener does not prove transport health, public inbound, DNS isolation or coexistence with a system VPN.

## Changes and verification

Keep the final code simple across ownership boundaries. Review every diff, preserve unrelated changes and remove obsolete state, wrappers, fallbacks and abandoned hypotheses. After a working result, perform an ablation pass and rerun applicable integration checks.

Do not write unit tests. The generated legal integration fixture is `scripts/qbutt-net-integration.ts`; run the documented Go build, vet and Bun integration commands. Use Bun/TypeScript for new tooling. Keep binaries, local profiles, subscription URLs and temporary artifacts outside tracked source.

The repository is public. Never commit or publish secrets, private profiles, dumps, keys or private dependency history; never print their values. Review the complete outgoing diff, stage explicit paths, and verify published commit and visibility through GitHub.

## Maintaining instructions

Если пользователь в ходе работы даёт новые устойчивые правила по стилю кода, структуре или процессу, то их надо кратко и по делу сразу добавлять в этот файл `AGENTS.md`, если это реально полезно будущим агентам.

Правила в `AGENTS.md` добавлять только если пользователь явно просит сохранить что-то универсальное и долговременное; не заносить туда ситуативные договорённости текущей задачи.

"Работает" недостаточно. После того как довел до рабочего состояния, убедись, что решение встроено в код красиво и без временных подпорок. Если по пути пришлось оставить костыль или фоллбэк, потом обязательно добейся его удаления, даже если для этого надо явно попросить пользователя сделать связанное изменение.
