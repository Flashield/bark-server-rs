# Store-and-forward delivery semantics with reconnect replay

This is reminder software: a notification missed by an offline client is a lost reminder, which is unacceptable. Unlike upstream bark's fire-and-forget relay, the server keeps per-device pending messages and **replays them on stream reconnect**; a client may acknowledge (or fetch-with-cleanup) to drain them. Storage is designed so a later upgrade to full ack + retry + backoff queues does not require a schema rewrite, but that upgrade itself is out of scope for now.

Mechanism (refined during grilling, 2026-11-10): replay keys off SSE `Last-Event-ID` against a server-side per-device monotonic message id; retention is a per-device TTL (default 72h) with a 1000-message cap, both configurable, expired entries pruned lazily. There is **no explicit ack** — delivery is at-least-once and clients deduplicate by message id.

## Considered options

- **Fire-and-forget (upstream behavior)**: rejected — offline clients silently lose reminders.
- **Full message queue with ack/retry/backoff now**: rejected — complexity not yet justified; the store schema reserves room for it (see ADR-0001's event-bus seam).
