# SSE-first real-time channel, WebSocket later on a shared event bus

Cross-platform clients (Windows/macOS/Android) subscribe to push delivery as a one-way server→client stream, so we chose **SSE** as the first real-time transport: built-in reconnection, proxy/CDN friendliness, and a simpler server implementation. WebSocket is deliberately deferred: it only earns its cost when clients need a reverse channel (delivery receipts, live control commands). The server sits on a transport-agnostic event bus, so a future WebSocket endpoint subscribes to the same bus without touching delivery semantics. (ADR-0002 defines those semantics.)

## Considered options

- **WebSocket first**: rejected — bidirectional power is unneeded for pure notification delivery today; SSE reconnection and proxy traversal are strictly simpler.
- **Long-polling only**: rejected as the primary channel — worse latency and higher overhead; kept implicitly as a fallback semantics target for replay.
