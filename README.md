# bark-server-rs

A drop-in Rust rewrite of [bark-server](https://github.com/Finb/bark-server):
accepts HTTP push requests, delivers them to Apple devices via APNs, and —
beyond upstream — **mirrors every push over SSE** to Realtime Clients, so the
same reminder reaches your Windows/macOS machines and Android phone that
today reaches your iPhone through the official Bark App.

The official Bark iOS App connects unchanged: same routes, same JSON
envelopes, same APNs delivery. Cross-platform delivery is served by the
versioned realtime API under `/realtime/v1` (SSE), whose client contract is
[`docs/protocol.md`](docs/protocol.md).

## Features

- **Upstream-compatible surface** (ADR-0003): `POST /register` (+ legacy GET
  variants), `POST /push` with JSON, legacy path-style Compat Routes,
  `device_keys` batch pushes, `/ping` `/healthz` `/info`, Basic Auth with
  upstream's exemptions and 418 teapot, the `{code, message, data, timestamp}`
  envelope and `Server: Bark` header, 22-char shortuuid-style device keys,
  watchOS topic routing, self-healing registry (invalid APNs tokens blanked
  automatically).
- **SSE realtime mirroring** (ADR-0001/0006): every push fans out to every
  Realtime Stream on the target Device; per-client revocable Stream Tokens
  (`st_…`), token-less **Stream Devices** for non-Apple users, `: connected`
  handshake, keepalives, at-least-once delivery with per-device monotonic
  message ids.
- **Store-and-forward replay** (ADR-0002): reconnect with the standard SSE
  `Last-Event-ID` header and receive exactly what you missed; per-device
  retention (default 72 h TTL, 1000 messages, both configurable).
- **MCP tool server**: `/mcp` and `/mcp/{device_key}` expose the `notify`
  tool for AI agents (Claude Desktop, Cherry Studio, …), wire-compatible with
  upstream.
- **Single binary, embedded storage**: SQLite (bundled, WAL) in one file
  `bark.db` under the data dir — zero external services (ADR-0005).
- **TLS termination** in the server via `--cert`/`--key`, like upstream.

## Quickstart

### Docker

The container runs as a non-root user (uid/gid 1000); make the data
directory writable for it first (on a typical Linux box your user is already
1000 — see [`deploy/docker-compose.yaml`](deploy/docker-compose.yaml) for the
alternatives):

```sh
mkdir -p data && chown 1000:1000 data
docker run -d --name bark-server \
     -p 8080:8080 \
     -v "$(pwd)/data:/data" \
     bark-server-rs:latest
```

(or build it first from this repo: `docker build -f deploy/Dockerfile -t bark-server-rs:latest .`)

Then:

```sh
curl "http://127.0.0.1:8080/ping"
# {"code":200,"message":"pong","timestamp":1760000000}
```

A compose sample lives at [`deploy/docker-compose.yaml`](deploy/docker-compose.yaml):

```sh
cd deploy
mkdir -p data && [ "$(id -u)" = 1000 ] || chown 1000:1000 data
docker compose up -d --build
```

### Binary

```sh
cargo build --release
./target/release/bark-server --addr 0.0.0.0:8080 --data ./data
```

```sh
curl "http://127.0.0.1:8080/ping"
```

Then point the official Bark iOS App at `http://your-server:8080` (it
registers itself and shows you its Device Key), or create a Stream Device
for a non-Apple client:

```sh
curl -X POST "http://127.0.0.1:8080/register" \
     -H 'Content-Type: application/json' -d '{"device_type": "stream"}'
```

Full client-facing contract — every endpoint, SSE event shape, replay
semantics, error codes — is [`docs/protocol.md`](docs/protocol.md).

## Configuration

Every flag has a `BARK_SERVER_*` environment variable; defaults mirror
upstream exactly. Single-dash long flags (`-addr`) are accepted like
upstream's urfave/cli. TLS: set both `--cert` and `--key`.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--addr` | `BARK_SERVER_ADDRESS` | `0.0.0.0:8080` | Listen address |
| `--unix-socket` | `BARK_SERVER_UNIX_SOCKET` | `""` | Listen on a Unix socket instead |
| `--url-prefix` | `BARK_SERVER_URL_PREFIX` | `/` | Serve under a URL prefix |
| `--data` | `BARK_SERVER_DATA_DIR` | `/data` | Data directory (SQLite file `bark.db`) |
| `--cert` / `--key` | `BARK_SERVER_CERT` / `BARK_SERVER_KEY` | `""` | TLS certificate/key (both set → HTTPS) |
| `--case-sensitive` | `BARK_SERVER_CASE_SENSITIVE` | `false` | Case-sensitive routing (default is fiber-compatible tolerant) |
| `--strict-routing` | `BARK_SERVER_STRICT_ROUTING` | `false` | Trailing slashes stop being ignored |
| `--reduce-memory-usage` | `BARK_SERVER_REDUCE_MEMORY_USAGE` | `false` | Accepted for parity (no-op) |
| `--user` / `--password` | `BARK_SERVER_BASIC_AUTH_USER` / `BARK_SERVER_BASIC_AUTH_PASSWORD` | `""` | Basic Auth (either alone enables; 418 on failure) |
| `--proxy-header` | `BARK_SERVER_PROXY_HEADER` | `""` | Header carrying the client IP behind a reverse proxy |
| `--max-batch-push-count` | `BARK_SERVER_MAX_BATCH_PUSH_COUNT` | `-1` | Batch push cap (`-1` = unlimited) |
| `--max-apns-client-count` | `BARK_SERVER_MAX_APNS_CLIENT_COUNT` | `1` | APNs HTTP/2 client connections |
| `--apns-endpoint` | `BARK_SERVER_APNS_ENDPOINT` | `https://api.push.apple.com` | APNs base URL (additive; stub injection for tests) |
| `--apns-insecure-skip-tls-verify` | `BARK_SERVER_APNS_INSECURE_SKIP_TLS_VERIFY` | `false` | Skip APNs TLS verification (additive; for self-signed stubs) |
| `--sse-keepalive-secs` | `BARK_SERVER_SSE_KEEPALIVE_SECS` | `15` | Seconds between SSE `: keep-alive` comments (`0` disables) |
| `--sse-message-ttl-secs` | `BARK_SERVER_SSE_MESSAGE_TTL_SECS` | `259200` | Replay-store retention TTL in seconds (default 72 h; `0` disables pruning) |
| `--sse-message-cap` | `BARK_SERVER_SSE_MESSAGE_CAP` | `1000` | Retained pushes per Device, oldest dropped first (`0` disables) |

Hidden parity knobs (accepted, upstream-compatible): `--concurrency`,
`--read-timeout`, `--write-timeout`, `--idle-timeout`, and the additive
`--mcp-session-idle-ttl` (default `10m`). Upstream's MySQL/serverless flags
belong to backends this project deliberately dropped (ADR-0005).

## Attribution

This project is a Rust rewrite of [Finb/bark-server](https://github.com/Finb/bark-server)
(MIT, Copyright (c) 2018 Feng); upstream compatibility — routes, envelopes,
embedded APNs credentials, flag surface — is its design, and this
repository's MIT license carries both copyright lines. The reference Go
implementation lives outside this repository.

## Development

```sh
cargo test        # the whole suite drives a real server over HTTP (the one seam)
cargo fmt
cargo clippy --all-targets
```

Contributors: start with [`GLOSSARY.md`](GLOSSARY.md) (the vocabulary
authority) and the ADRs in [`docs/adr/`](docs/adr/) — they explain the why
behind every non-obvious decision (SSE-first realtime, store-and-forward,
upstream compat, APNs credential reuse, SQLite, the stream bridge model).
The client contract in [`docs/protocol.md`](docs/protocol.md) must always
match shipped behavior.

## License

[MIT](LICENSE) — Copyright (c) 2026 bark-server-rs contributors;
Copyright (c) 2018 Feng (bark-server).
