# Upstream bark-server API and APNs compatibility is in scope, fully

"Implement all current features" is interpreted at maximum depth: the existing official Bark iOS App must connect to this Rust server **unchanged** — same HTTP paths, request/response shapes, device-key model, config surface, and a working APNs delivery path (JWT token auth, payload construction matching upstream). This keeps the whole upstream ecosystem (iOS App, community scripts, curl one-liners) as a working client base and covers iOS with zero client-side project work. Compatibility is a promise, so deviations must be additive (new endpoints/versioned paths), never breaking changes to upstream behavior.

## Consequences

- APNs delivery is a first-class server feature, not a stub.
- Any new real-time (SSE/WS) API lives beside the upstream surface under its own documented contract (`docs/protocol.md`), versioned independently.
