# Upstream bark-server API and APNs compatibility is in scope, fully

"Implement all current features" is interpreted at maximum depth: the existing official Bark iOS App must connect to this Rust server **unchanged** — same HTTP paths, request/response shapes, device-key model, config surface, and a working APNs delivery path (JWT token auth, payload construction matching upstream). This keeps the whole upstream ecosystem (iOS App, community scripts, curl one-liners) as a working client base and covers iOS with zero client-side project work. Compatibility is a promise, so deviations must be additive (new endpoints/versioned paths), never breaking changes to upstream behavior.

## Consequences

- APNs delivery is a first-class server feature, not a stub.
- Any new real-time (SSE/WS) API lives beside the upstream surface under its own documented contract (`docs/protocol.md`), versioned independently.

## Documented deviations (accepted)

The additive-only rule above governs surface evolution. Three deliberate deviations from upstream *behavior* shipped during the build, each recorded here and at its implementation site, and each pinned by tests:

1. **APNs rejections surface the actual status + reason** instead of upstream's blanket `500 "push failed: <reason>"` mapping (`route_push.go` wraps every APNs error). An APNs `413 PayloadTooLarge` answers `{"code":413,"message":"PayloadTooLarge",…}`; transport-level failures keep upstream's `500 "push failed: {detail}"` shape. (`src/api/push.rs`; pinned by `tests/push_seam.rs` `apns_non_200_other_statuses_surface_without_cleanup`, `apns_410_blanks_device_token_and_next_push_fails`, and `transport_failure_maps_to_500_push_failed`.)
2. **`multipart/form-data` registration is not bound** — no known Bark client registers via multipart (the app posts JSON; scripts use query or form), so such requests get fiber's bind-failure answer `400 "request bind failed2: Unprocessable Entity"` instead of binding the multipart body. (`src/api/register.rs`; pinned by `tests/register_seam.rs` `post_unsupported_content_type_is_upstream_bind_failure`.)
3. **A new Device Key is minted when the presented key is unknown**, not only when it is empty: upstream's `SaveDeviceTokenByKey` mints only for an empty key, while this server follows the bbolt-flavored semantics of its own stores — an empty *or unregistered* key counts as a new registration, so a caller-provided key is never silently adopted without a prior registration. (`src/store/*`; pinned by `tests/register_seam.rs` `post_json_field_names_match_case_insensitively` and `get_compat_legacy_aliases_create_new_device_when_unknown`.)
