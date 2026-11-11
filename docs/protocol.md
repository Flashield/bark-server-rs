# bark-server protocol

The client-facing contract of bark-server-rs: everything a client implementer
(official Bark iOS App, scripts, and the Windows/macOS/Android reminder
software) needs to talk to the server. Hand-written and example-driven; every
example below was captured from a running server. Vocabulary follows
[`GLOSSARY.md`](../GLOSSARY.md): **Device** (addressed by its **Device Key**),
**Device Token** (APNs, Apple devices only), **Push**, **Ext Params**,
**Realtime Client**, **Realtime Stream**, **Stream Token**, **Stream Device**.

Design rationale lives in the ADRs (`docs/adr/`): SSE-first realtime
(ADR-0001), store-and-forward replay (ADR-0002), upstream compatibility
(ADR-0003), the bridge model (ADR-0006).

## Contents

1. [Conventions](#1-conventions)
2. [Compat API — the upstream bark-server surface](#2-compat-api--the-upstream-bark-server-surface)
3. [Realtime API v1 — `/realtime/v1`](#3-realtime-api-v1--realtimev1)
4. [MCP — the `notify` tool](#4-mcp--the-notify-tool)
5. [Error reference](#5-error-reference)
6. [Client implementation checklist](#6-client-implementation-checklist)

## 1. Conventions

### 1.1 The response envelope

Every JSON response from the compat and realtime APIs (and every error) uses
upstream's envelope:

```json
{"code": 200, "message": "success", "data": {"...": "..."}, "timestamp": 1760000000}
```

- `code` mirrors the HTTP status code.
- `data` is present only when the endpoint returns a payload (omitted
  otherwise, exactly like upstream's `omitempty`).
- `timestamp` is the server's Unix time in **seconds** (integer).

Every response (JSON or plain text) carries the `Server: Bark` header, like
upstream.

### 1.2 Route matching tolerance

Route matching mirrors upstream's fiber defaults: static path segments match
case-insensitively (`/PING` works) and trailing slashes are ignored
(`/ping/` works). Clients SHOULD still use the canonical spellings below —
only static segments are tolerant; Device Keys inside path parameters keep
their original casing and are matched byte-exact.

### 1.3 Timestamps

All timestamps on the wire are integer Unix seconds: the envelope's
`timestamp`, token `created_at`, and SSE event `created_at`.

### 1.4 Basic Auth (operator-level)

When the operator sets `--user`/`--password` (either one alone enables it),
every path under the URL prefix except `/ping`, `/register` and `/healthz`
requires HTTP Basic Auth. Failed or missing credentials answer
`418 I'm a teapot` with the plain-text body `I'm a teapot` — not 401, no
`WWW-Authenticate` challenge, exactly like upstream. The exemptions are byte
prefix matches on the raw request path, so requests carrying wrong
credentials still proceed on exempt paths. Basic Auth wraps *everything*
including `/realtime/v1` and `/mcp`: a Realtime Client behind Basic Auth must
send the `Authorization` header alongside its `X-Stream-Token`.

## 2. Compat API — the upstream bark-server surface

This section is the drop-in compatibility promise (ADR-0003): the official
Bark iOS App and existing scripts keep working unchanged. Semantics are
upstream bark-server v2.4.0's, audited route by route; every example below
was captured from a running server.

### 2.1 Register a Device

`POST /register` — body is bound per Content-Type: JSON (`application/json`,
including vendor-specific `application/vnd.x+json`), form
(`application/x-www-form-urlencoded`), or XML (`application/xml` or
`text/xml`). Field names match case-insensitively; unknown fields are
ignored. `multipart/form-data` is rejected (upstream clients do not use it
for registration).

| Field | Required | Meaning |
|---|---|---|
| `device_token` | yes for `ios`/`watchos` | The APNs token of the Bark App installation (≤160 bytes) |
| `device_key` | no | An **already registered** Device Key to update in place; empty or unknown → a new Device Key is minted |
| `device_type` | no | `ios` (default), `watchos`, or `stream` (this server's extension, §3.1) |
| `key` | no | Legacy alias for `device_key` (old requests) |
| `devicetoken` | no | Legacy alias for `device_token` (old requests) |

```sh
curl -X POST "http://127.0.0.1:8080/register" \
     -H 'Content-Type: application/json' \
     -d '{"device_token": "AAPLTOKEN123456", "device_type": "ios"}'
```

```json
{"code":200,"message":"success","data":{"key":"sPpZNe2sDTzsKMqyaiw85i","device_key":"sPpZNe2sDTzsKMqyaiw85i","device_token":"AAPLTOKEN123456","device_type":"ios"},"timestamp":1760000000}
```

- `key` and `device_key` are the same 22-char Device Key (both spellings kept
  for old clients). Store it — it is both the push address and the push
  credential (§3.1).
- Registering again with a known `device_key` updates that Device's record
  (renewed token, type). Registering with an empty or *unknown* key mints a
  fresh Device Key; a caller-provided but unregistered key is **not** stored.
- `watchos` Devices are pushed with the `me.fin.bark.watch` APNs topic
  instead of `me.fin.bark`.

Legacy compat registration: `GET /register` with query parameters (same
field names, `key`/`devicetoken` aliases, body ignored):

```sh
curl "http://127.0.0.1:8080/register?key=old-key&devicetoken=TOKENXYZ"
```

Existence check: `GET /register/{device_key}` answers the plain success
envelope when the Device exists **and** has a Device Token; a Stream Device
(token-less by design) answers `400 device token invalid` — the check is
token-based, like upstream.

Errors: missing token → `400 device token is empty`; token over 160 bytes →
`400 device token is invalid`; unknown type → `400 invalid device type: {as-provided}`;
unparseable body → `400 request bind failed2: …` (the `2` is upstream's).

### 2.2 Push (V2, JSON)

`POST /push` with `Content-Type: application/json` — the V2 route. A push is
one notification request for one Device.

```sh
curl -X POST "http://127.0.0.1:8080/push" \
     -H 'Content-Type: application/json; charset=utf-8' \
     -d '{
  "device_key": "sPpZNe2sDTzsKMqyaiw85i",
  "title": "Flight",
  "subtitle": "SFO",
  "body": "Gate 7",
  "id": "flight-87",
  "group": "trips",
  "url": "https://example.com/boarding",
  "sound": "minuet",
  "badge": 1,
  "icon": "https://day.app/assets/images/avatar.jpg",
  "level": "timeSensitive",
  "ciphertext": "BASE64CIPHER",
  "iv": "BASE64IV"
}'
```

```json
{"code":200,"message":"success","timestamp":1760000000}
```

Recognized string parameters (the rest become Ext Params, below):

| Parameter | Meaning |
|---|---|
| `device_key` | Target Device. Required; empty → `400 device key is empty` |
| `title` / `subtitle` / `body` | Notification text; `body` is the content |
| `id` | Dual-written: APNs collapse-id **and** a custom payload key, so grouped notifications replace each other |
| `group` | Notification group (thread-id + custom payload key) |
| `sound` | Sound name; `.caf` is appended unless already suffixed; default `1107` |
| `ciphertext` / `iv` | End-to-end encrypted push payloads, passed through untouched (decrypted in the Bark App) |
| `delete` | `"1"` switches the APNs push type to silent background (removes the notification) |

All other parameters are **Ext Params**: string values are passed through as
custom payload keys with the key lowercased; JSON numbers/booleans/arrays as
values are stringified the way Go renders them (`3` → `"3"`, `true` →
`"true"`, `[1 a]` for arrays); JSON object values are **merged** entry-by-entry
into Ext Params. This is what keeps Bark App features (`icon`, `url`, `level`,
`call`, `copy`, `badge`, `isArchive`, `autoCopy`, …) working unchanged.

Parameter precedence (highest wins): path params (compat routes, §2.4) >
query args (keys lowercased, values become strings) > JSON body.

Behavioral guarantees:

- All alert fields empty → `body` is replaced with `"Empty Message"` (APNs
  silently discards empty notifications, which would break encrypted pushes).
- Delivery to Apple Devices goes through APNs; a delivered push also fans out
  to the Device's Realtime Streams (§3.4) and is persisted for replay (§3.6)
  — one `POST /push` reaches iPhone and desktop with zero push-side changes.
- Unknown `device_key` → `400 failed to get device token: failed to get
  [key] device token from database`. A Device whose token APNs reported
  invalid (`410`, or `400 BadDeviceToken`) is blanked automatically
  (self-healing registry); pushes to it then answer `400 failed to get
  device token: device token invalid`.
- APNs rejections surface as the APNs status code with the APNs reason
  string in `message` (an APNs `413 PayloadTooLarge` answers
  `{"code":413,"message":"PayloadTooLarge",...}`); transport-level failures
  answer `500 push failed: {detail}`.
- A JSON `null` body combined with query args or path parameters answers
  `500 assignment to entry in nil map` (upstream panics assigning into the
  nil map its `json.Unmarshal` produces); a bare `null` body without
  query/path reaches the ordinary empty-key error.

A non-JSON Content-Type on `POST /push` selects the V1 collection (§2.4).

### 2.3 Misc routes

| Route | Response |
|---|---|
| `GET /` | plain text `ok` |
| `GET /ping` | `{"code":200,"message":"pong","timestamp":1760000000}` |
| `GET /healthz` | plain text `ok` — for load balancers |
| `GET /info` | bare JSON map (below) |

`GET /info` — build info plus live statistics (the realtime stats are this
server's additive extension; the first four fields match upstream):

```json
{"version":"0.1.0","build":"unknown","arch":"linux/amd64","commit":"3cb5465","devices":2,"streams":2,"active_streams":1,"pending_messages":3}
```

| Field | Meaning |
|---|---|
| `version` / `build` / `arch` / `commit` | Server build identification |
| `devices` | Registered Devices (all types) |
| `streams` | Stream Tokens minted, revoked included |
| `active_streams` | SSE connections currently open |
| `pending_messages` | Stored Pushes replay could return (retention-aware) |

### 2.4 Compat Routes (path-style, V1)

The legacy URL shapes — byte-compatible with old scripts, iOS Shortcuts and
one-liners. Both `GET` and `POST` work on each shape:

| Shape | Binds |
|---|---|
| `/:device_key` | — |
| `/:device_key/:body` | body |
| `/:device_key/:title/:body` | title, body |
| `/:device_key/:title/:subtitle/:body` | title, subtitle, body |

```sh
curl "http://127.0.0.1:8080/sPpZNe2sDTzsKMqyaiw85i/Flight/Gate%207"
```

Rules (upstream v2.4.0, verified against the shipped server):

- Path parameters have the highest precedence, then query args, then the
  collected body (V1 collection, below).
- `body`/`title`/`subtitle` segments are URL-unescaped with Go's
  `url.QueryUnescape` semantics (`%XX` sequences and `+` → space); the
  `device_key` segment stays raw — percent-escapes and casing preserved. A
  segment with a malformed escape answers
  `400 url path parse failed: invalid URL escape "%zz"` (quoting the bad
  escape).
- More than four path segments never match → the enveloped 404 with the
  verbatim path (`Cannot GET /{device_key}/a/b/c/d`).
- `GET /push` resolves as a Compat Route with `device_key = "push"` (there is
  no canonical GET on `/push`). The same fall-through applies to any
  canonical route's unhandled method — e.g. `POST /register/{key}` pushes
  with `device_key = "register"`.
- A non-JSON Content-Type on `POST /push` — and every compat-route request —
  uses the V1 collection, in upstream order: query args (keys lowercased) →
  form POST args (parsed only when the raw content type starts with
  `application/x-www-form-urlencoded`, any method; keys lowercased) →
  multipart form values (only for a parseable `multipart/form-data`
  boundary; keys keep their case, first value wins) → path params highest.
- `device_keys` is **not** expanded on the V1 path — it rides along as an
  Ext Param like any unrecognized parameter (upstream parity; batch only
  exists on the V2 JSON route, §2.5).

### 2.5 Batch push

`device_keys` on `POST /push` fans one Push out to several Devices:

- A comma-separated **string** (`"key1,key2"`) splits on `,` — an empty
  string splits into one empty key, which runs as a one-item batch whose
  `data` carries that key's failure item (Go `strings.Split` semantics).
- A JSON **array** (`["key1","key2"]`) stringifies each element (`123` →
  `"123"`).
- Any other type → `400 invalid type for device_keys`.
- No `device_keys` parameter at all → ordinary single push.
- More keys than `--max-batch-push-count` (default `-1` = unlimited) →
  `400 batch push count exceeds the maximum limit: {N}`.

The response is HTTP 200 (even when every item failed) with `data` = one
result object per target, in request order; `message` appears only on
failure:

```json
{"code":200,"message":"success","timestamp":1760000000,"data":[
  {"code":200,"device_key":"sPpZNe2sDTzsKMqyaiw85i"},
  {"code":400,"device_key":"nosuchkey","message":"failed to get device token: failed to get [nosuchkey] device token from database"}
]}
```

Targets are pushed concurrently; each result carries that target's own
outcome. Realtime mirroring and replay apply per target as usual (§3.4).

## 3. Realtime API v1 — `/realtime/v1`

The realtime mirror for non-Apple clients. Everything in this section is
this server's own additive surface, versioned under `/realtime/v1`:
**additive-only evolution is the promise** — new fields and endpoints may
appear; existing routes, headers, statuses and JSON shapes will not break.
A future incompatible revision will live under `/realtime/v2`. WebSocket
delivery is deliberately deferred (ADR-0001); SSE is the only realtime
transport today.

Client-facing model (ADR-0006, the bridge model):

- A **Stream Device** is a Device without a Device Token, registered like any
  Device but with `device_type: "stream"` — this is how Windows/Android/Linux
  users get an addressable Device without the Bark App.
- A Push addressed to a Device Key fans out to **every** Realtime Stream on
  that Device, and to APNs when the Device has a Device Token. `ios`,
  `watchos` and `stream` Devices all support streams.
- Reading is separately authorized: the Device Key authorizes *pushing*
  (and minting read credentials); a **Stream Token** authorizes *reading*.
  One Stream Token per Realtime Client, revocable per client.

The two credentials, and where each is presented:

| Credential | Presented in | Authorizes |
|---|---|---|
| Device Key | `X-Device-Key` header (must equal the path's `{device_key}`) | Mint / list / revoke the Device's Stream Tokens; pushing (§2.2) |
| Stream Token | `X-Stream-Token` header | Holding one SSE Realtime Stream (§3.4) |

Both are dedicated headers on purpose: no `Authorization` scheme parsing, no
query parameters (tokens in URLs leak into logs and proxies), consistent
one-header-per-credential shape.

### 3.1 Register a Stream Device

```sh
curl -X POST "http://127.0.0.1:8080/register" \
     -H 'Content-Type: application/json' \
     -d '{"device_type": "stream"}'
```

```json
{"code":200,"message":"success","data":{"key":"itu4irzixECYJ5Ftd9UygK","device_key":"itu4irzixECYJ5Ftd9UygK","device_token":"","device_type":"stream"},"timestamp":1760000000}
```

`device_type` matches case-insensitively. Any `device_token` sent alongside
`stream` is ignored and stored empty — Stream Devices have none by invariant.
An operator-side client (e.g. a setup wizard) may also register a Stream
Device under an existing known key to refresh it in place.

### 3.2 Stream Token lifecycle

Token format: `st_` + 43 unpadded base64url characters (256 bits of OS
CSPRNG entropy). The `st_` prefix is recognition only. The full secret
appears in a response **exactly once** — at mint time; the server never
returns it again. List/revoke instead identify tokens by the public
`token_id` (16 lowercase hex chars) and carry a `token_hint` (first 12
characters of the secret + `...`) so a user can match a stored token to a
list entry without the server re-exposing the secret.

#### Mint — `POST /realtime/v1/devices/{device_key}/streams`

Auth: `X-Device-Key` header, byte-exact against the path Device Key.
Body: a JSON object (parsed regardless of Content-Type; **send at least
`{}`** — an empty body is a bind error). Unknown fields ignored.

```sh
curl -X POST "http://127.0.0.1:8080/realtime/v1/devices/itu4irzixECYJ5Ftd9UygK/streams" \
     -H "X-Device-Key: itu4irzixECYJ5Ftd9UygK" \
     -H 'Content-Type: application/json' \
     -d '{"client_label": "macbook-reminder"}'
```

```json
{"code":200,"message":"success","data":{"token_id":"e9351ee91c837988","device_key":"itu4irzixECYJ5Ftd9UygK","client_label":"macbook-reminder","created_at":1760000000,"revoked":false,"token_hint":"st_31gpMA4Iq...","token":"st_31gpMA4IqFoXza0fRcAvSmavSvCuM-xsWVv0ISFGJp8"},"timestamp":1760000000}
```

`client_label` is optional free-form text naming the Realtime Client (absent
or `null` → empty string; must be a string of at most 256 bytes) — one
revocable token per client machine. Mint as many tokens as you have clients;
each is independent.

#### List — `GET /realtime/v1/devices/{device_key}/streams`

```sh
curl "http://127.0.0.1:8080/realtime/v1/devices/itu4irzixECYJ5Ftd9UygK/streams" \
     -H "X-Device-Key: itu4irzixECYJ5Ftd9UygK"
```

```json
{"code":200,"message":"success","data":[{"token_id":"e9351ee91c837988","device_key":"itu4irzixECYJ5Ftd9UygK","client_label":"macbook-reminder","created_at":1760000000,"revoked":false,"token_hint":"st_31gpMA4Iq..."},{"token_id":"4ec22c61d6e73de0","device_key":"itu4irzixECYJ5Ftd9UygK","client_label":"android-phone","created_at":1760000000,"revoked":false,"token_hint":"st_zkL1JumxN..."}],"timestamp":1760000000}
```

Creation order; never contains the secret.

#### Revoke — `DELETE /realtime/v1/devices/{device_key}/streams/{token_id}`

```sh
curl -X DELETE "http://127.0.0.1:8080/realtime/v1/devices/itu4irzixECYJ5Ftd9UygK/streams/4ec22c61d6e73de0" \
     -H "X-Device-Key: itu4irzixECYJ5Ftd9UygK"
```

```json
{"code":200,"message":"success","data":{"token_id":"4ec22c61d6e73de0","device_key":"itu4irzixECYJ5Ftd9UygK","client_label":"android-phone","created_at":1760000000,"revoked":true,"token_hint":"st_zkL1JumxN..."},"timestamp":1760000000}
```

Revocation is persistent and takes effect immediately: the revoked token's
SSE connections and future connect attempts fail auth (§3.4). Revoking an
already-revoked token is refused with `409 stream token already revoked`
(deliberately not idempotent, so a scripted revoke loop notices when the
target is already gone). Token ids are Device-scoped: an id belonging to
another Device answers `404 stream token not found` like an unknown id.

Auth errors are ordered so a request failing earlier never reveals later
facts: missing `X-Device-Key` → `401 device key required`; header ≠ path →
`401 device key mismatch`; unknown Device → `404 device not found`.

### 3.3 SSE endpoint

`GET /realtime/v1/stream` — hold a Realtime Stream. Server-Sent Events;
one open HTTP connection per Realtime Client, bound to the token's Device
for the life of the connection. Any number of concurrent streams per Device
is allowed (one per client machine is the intended shape).

Auth: `X-Stream-Token` header carrying the full secret, byte-exact. Absent →
`401 stream token required`; unknown **or revoked** → `401 stream token
invalid` (the endpoint does not distinguish the two — a rejection never
becomes a token-validity oracle). Only `GET` is served (`HEAD` answers an
empty success, per HTTP semantics); every other method answers
`405 Method Not Allowed` in the envelope.

Handshake: the **first body bytes are a `: connected` comment**. Once a
client has read that comment it is guaranteed every push published
afterwards — the subscription is registered before the comment is written —
plus everything retained before it when `Last-Event-ID` was presented (§3.5).

```sh
curl -N "http://127.0.0.1:8080/realtime/v1/stream" \
     -H "X-Stream-Token: st_31gpMA4IqFoXza0fRcAvSmavSvCuM-xsWVv0ISFGJp8"
```

### 3.4 Event format

Each Push arrives as one SSE event:

```text
: connected

event: message
id: 1
data: {"id":1,"title":"Flight","subtitle":"SFO","body":"Gate 7","ext_params":{"id":"flight-87","group":"trips","url":"https://example.com/boarding"},"device_key":"itu4irzixECYJ5Ftd9UygK","created_at":1760000000}

```

- `event:` is always `message` (explicit, so future event types can coexist
  on one stream — ignore events with other names until you know them).
- `id:` is the **per-Device monotonic message id** (decimal integer). It is
  the reconnect cursor (§3.5) and the dedup key (§3.7).
- `data:` is one line of JSON — the full Push:

| Field | Type | Meaning |
|---|---|---|
| `id` | integer | Per-Device monotonic message id — equals the SSE `id:` line |
| `title` / `subtitle` / `body` | string | Notification text; absent fields are `""` |
| `ext_params` | object | Ext Params at fan-out time: unrecognized string params (keys lowercased, string values), merged entries of JSON object values (keys as provided), and non-string params (keys as provided, values as JSON). The user-supplied `id`/`group`/… parameters ride here |
| `device_key` | string | The target Device Key |
| `created_at` | integer | Unix seconds, assigned by the server at persistence |

Replayed and live events are indistinguishable on the wire — same shape, same
`id:` semantics. Delivery order per Device equals the monotonic id order.

While idle the server emits `: keep-alive` comment lines every
`--sse-keepalive-secs` (default 15 s; `0` disables). They are SSE comments —
ignore everything that is not `event:`/`id:`/`data:`.

If a stream falls more than 256 events behind (slow reader), the server
closes the stream instead of skipping silently: reconnect with
`Last-Event-ID` and replay heals the gap (§3.5).

### 3.5 Replay — the `Last-Event-ID` header

The server stores each Device's pushes (store-and-forward, ADR-0002), so a
client that reconnects after a gap does not miss reminders. Present the
standard SSE `Last-Event-ID` request header with the last message id you
processed; the server first replays every retained message with id > cursor
(ascending id order), then hands off seamlessly to live delivery — the
handoff happens under one lock, so a push published during replay lands in
exactly one of the two (no gap, no duplicate). There is deliberately **no
`last_event_id` query parameter**.

The header is honored on **every** connect — there is no first-connect vs
reconnect distinction server-side; a first connect may carry it (a client
restoring its cursor from local storage) and is answered the same way.
Cursor parsing, pinned:

| `Last-Event-ID` | Behavior |
|---|---|
| absent or empty | Fresh subscription — no replay (live events only, from the `: connected` handshake on) |
| non-numeric (or beyond 64-bit range) | Treated as absent — fresh subscription; failing the connect would break auto-reconnect cycles for no benefit |
| numeric, older than every retained id | Replays from the **oldest retained** message (the retention window is the floor, not an error) |
| numeric, before the newest id | Replays exactly the retained ids > cursor, then goes live |
| numeric, ≥ newest id (e.g. `999`) | Replays nothing; goes live |

To bootstrap history on a first connect, use a low numeric cursor such as
`0` — cursor `0` replays everything currently retained.

```sh
curl -N "http://127.0.0.1:8080/realtime/v1/stream" \
     -H "X-Stream-Token: st_31gpMA4IqFoXza0fRcAvSmavSvCuM-xsWVv0ISFGJp8" \
     -H "Last-Event-ID: 1"
```

```text
: connected

event: message
id: 2
data: {"id":2,"title":"","subtitle":"","body":"second","ext_params":{},"device_key":"itu4irzixECYJ5Ftd9UygK","created_at":1760000000}

```

### 3.6 Retention

How much replay history a Device keeps (configurable by the operator):

- **TTL**: a Push stays replayable for `--sse-message-ttl-secs` seconds
  (default `259200` = 72 h; `0` disables TTL pruning).
- **Cap**: at most `--sse-message-cap` Pushes per Device are retained
  (default `1000`; `0` disables the cap), oldest dropped first.
- Pruning is lazy (at insert time); TTL-expired rows are never replayed and
  never counted in `/info`'s `pending_messages`, even before pruning ran.
- Ids come from a dedicated per-Device counter: they never repeat or regress,
  but after a server crash they may **skip** a value. Clients must treat ids
  as opaque monotonically increasing numbers, not as gap-free sequence
  numbers.

Retention bounds what replay can return — a cursor older than the window
clamps to the oldest retained message. At-least-once delivery (§3.7) means
the client, not the server, owns exactly-once.

### 3.7 Delivery semantics

- **At-least-once**: a push persisted server-side is guaranteed to reach each
  connected-or-reconnecting stream, possibly more than once (e.g. a replay
  that overlaps an event the client already consumed before an unclean
  disconnect). There is **no explicit ack** — clients deduplicate by
  `id` (ADR-0002).
- **Per-Device ordering**: one Device's streams observe its pushes in
  monotonic id order, always. Different Devices are independent.
- **Fan-out isolation**: streams are per-Device; a stream never sees another
  Device's pushes. Multiple streams on one Device each get every event.
- **Stream Devices**: pushes to a `stream` Device succeed (`200`) with APNs
  skipped — the realtime stream is that Device's only delivery path. A push
  to a `stream` Device with no live stream is still persisted and replayed
  later.
- **Lag**: >256 events unread on a stream → server closes it; the client
  reconnects with `Last-Event-ID` (§3.4).

## 4. MCP — the `notify` tool

For AI agents (Claude Desktop, Cherry Studio, …): two Streamable-HTTP MCP
endpoints exposing a single `notify` tool, wire-compatible with upstream
bark-server's MCP server.

| Endpoint | Description |
|---|---|
| `/mcp` | Generic — `device_key` must be provided in the tool arguments |
| `/mcp/{device_key}` | Path-bound — the Device Key is fixed by the URL; the agent doesn't need to know it (and any `device_key` argument is overwritten) |

Both endpoints accept every HTTP method (the method dispatch is part of the
protocol); sessions, tool schema and result texts mirror upstream exactly.

### 4.1 Session lifecycle

1. `POST` an `initialize` request (`Content-Type: application/json`,
   JSON-RPC 2.0). The response carries the session in the
   `Mcp-Session-Id` header:

```sh
curl -D - -X POST "http://127.0.0.1:8080/mcp" \
     -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"0"}}}'
```

```text
mcp-session-id: mcp-session-f8643a2d-8857-4a47-80a6-c74f91a28d85

{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"Bark MCP Server","version":"0.1.0"}}}
```

2. Every subsequent POST must echo that header; a missing, malformed, or
   expired session answers a plain-text `404 Invalid session ID` (a
   DELETE-terminated one: `404 Session terminated`).
3. Sessions expire after 10 minutes idle (`--mcp-session-idle-ttl`; a
   well-behaved MCP client re-initializes on the 404). `DELETE` with the
   header terminates the session (`200`). GET answers
   `405 Streaming is disabled on this server` (non-streaming server);
   responses to JSON-RPC notifications (no `id`) are `202 Accepted`.

### 4.2 The `notify` tool

`tools/list` returns the tool (parameters exactly upstream's):

```json
{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"notify","description":"Send a notification to a device via Bark","inputSchema":{"type":"object","properties":{"badge":{"type":"number","description":"Badge number"},"body":{"type":"string","description":"Notification content"},"call":{"type":"string","description":"Set to '1' to repeat the notification ringtone"},"copy":{"type":"string","description":"Text to copy on copy action"},"device_key":{"type":"string","description":"Device Key"},"group":{"type":"string","description":"Notification group"},"icon":{"type":"string","description":"Notification icon URL"},"image":{"type":"string","description":"Notification image URL"},"isArchive":{"type":"string","description":"Set to '1' to save the notification or any other value to skip saving"},"level":{"type":"string","description":"Notification level","enum":["critical","active","timeSensitive","passive"]},"markdown":{"type":"string","description":"Basic Markdown notification content. Overrides body."},"sound":{"type":"string","description":"Notification sound"},"subtitle":{"type":"string","description":"Notification subtitle"},"title":{"type":"string","description":"Notification title"},"ttl":{"type":"number","description":"Time to live in seconds for archived messages; expired items are automatically deleted"},"url":{"type":"string","description":"Click action URL"},"volume":{"type":"number","description":"Alert volume for important notification","default":5,"minimum":0,"maximum":10}},"required":["device_key"]},"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":true}}]}}
```

(`device_key` is present in the schema only on the generic `/mcp` endpoint,
where it is required.)

`tools/call` routes through the exact same push core as HTTP pushes —
Ext Params rules, Empty Message fallback, realtime fan-out and replay all
apply:

```sh
curl -X POST "http://127.0.0.1:8080/mcp" \
     -H 'Content-Type: application/json' \
     -H "Mcp-Session-Id: mcp-session-f8643a2d-8857-4a47-80a6-c74f91a28d85" \
     -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"notify","arguments":{"device_key":"itu4irzixECYJ5Ftd9UygK","title":"From MCP","body":"Claude says hi"}}}'
```

```json
{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"Notification sent successfully"}]}}
```

Failures are tool errors with upstream's text:
`{"content":[{"type":"text","text":"Failed to send notification: {message} (code {code})"}],"isError":true}`;
missing device key → `device_key is required`; unknown tool → JSON-RPC
`-32602 tool '<name>' not found: tool not found`; unknown method →
`-32601 Method <name> not found`; unparseable body → HTTP 400 JSON-RPC
`-32700 request body is not valid json`.

## 5. Error reference

All errors use the envelope (§1.1) with `code` = HTTP status, except where
noted (Basic Auth's plain-text 418, MCP's plain-text 404/405). The
compat/realtime table:

| Status | `message` | When |
|---|---|---|
| 400 | `device key is empty` | Push without a Device Key |
| 400 | `failed to get device token: failed to get [{key}] device token from database` | Push to an unknown Device Key |
| 400 | `failed to get device token: device token invalid` | Push to a Device whose token APNs blanked |
| 400 | `invalid type for device_keys` | Batch `device_keys` neither string nor array |
| 400 | `batch push count exceeds the maximum limit: {N}` | Batch over `--max-batch-push-count` |
| 400 | `url path parse failed: invalid URL escape "{escape}"` | Compat Route segment fails URL-unescaping |
| 400 | `request bind failed: {detail}` | Push body/query binding failed |
| 400 | `request bind failed2: {detail}` | Register body binding failed (the `2` is upstream's) |
| 400 | `device token is empty` / `device token is invalid` | Register validation |
| 400 | `invalid device type: {as-provided}` | Register with unknown type |
| 400 | `failed to get [{key}] device token from database` | Register existence check on unknown key |
| 401 | `device key required` / `device key mismatch` | Credential-plane `X-Device-Key` absent / not equal to path |
| 401 | `stream token required` / `stream token invalid` | SSE without token / unknown-or-revoked token |
| 404 | `Cannot {METHOD} {path}` | Unmatched path (fiber's 404, path HTML-escaped) |
| 404 | `device not found` | Credential plane on unknown Device |
| 404 | `stream token not found` | Unknown token_id (or another Device's) |
| 405 | `Method Not Allowed` | Path exists, method wrong |
| 409 | `stream token already revoked` | Revoking twice |
| 418 | plain text `I'm a teapot` | Basic Auth failure (§1.4) |
| 500 | `push failed: {detail}` | APNs transport failure |
| 500 | `assignment to entry in nil map` | V2 push with a JSON `null` body plus query args or path params (upstream panic parity) |
| 500 | `message store failed: {detail}` | Replay-store write failed on push |
| 500 | `stream token storage failed: {detail}` / `stream token lookup failed: {detail}` | Store failure on the realtime plane |

## 6. Client implementation checklist

For the Windows/macOS/Android reminder software — the minimum a robust
Realtime Client does:

1. **Registration (once)**: `POST /register` with `device_type: "stream"`
   (§3.1); store the returned Device Key durably — re-registering with an
   unknown key mints a *different* key, so persist it before anything else.
2. **Token per client machine (once per machine)**: mint a Stream Token
   (§3.2) with a `client_label` naming the machine; store the full secret in
   OS-protected storage (credential vault/keychain), never in plain config
   files or URLs. Store the `token_id` alongside for later revocation.
3. **Connect**: `GET /realtime/v1/stream` with `X-Stream-Token`; treat
   reading the `: connected` comment as the liveness handshake.
4. **Dedup**: keep the highest processed message id; drop events with
   `id <= cursor`. Ids are per-Device — scope the cursor to the Device.
5. **Reconnect with replay**: on any disconnect (including server-initiated
   closes after lag), reconnect with `Last-Event-ID: {cursor}`. Never send a
   non-numeric cursor expecting replay — it means "fresh". Expect the replay
   to arrive before live events, in id order, with no gap against the live
   tail.
6. **Backoff**: reconnect with jittered exponential backoff; the server
   closes idle streams only on lag, and keepalives (15 s) keep proxies alive.
7. **Heartbeat/monitoring**: surface `/info`'s `active_streams` and
   `pending_messages` in diagnostics; `pending_messages > 0` while connected
   suggests the client is behind (or another stream is).
8. **Token hygiene**: on suspicion of leakage or when decommissioning a
   machine, revoke its token (§3.2) — other machines' tokens keep working.
   Handle `401 stream token invalid` by prompting re-registration (the token
   may have been revoked elsewhere); do not retry the same token in a loop.
9. **Push-side simplicity**: desktop reminders arrive by mirroring — no
   special push endpoint is needed. Point existing scripts at the Device Key
   (§2.2) and iPhone (APNs) plus every desktop client receive the same Push.
