# Realtime streams attach to Devices (bridge model) with separate read credentials

SSE streams bind to an existing Device, not to a separate subscription namespace: a push addressed to a Device Key fans out to APNs (when a Device Token exists) **and** to every live Realtime Stream on that Device. Existing push-side scripts (curl, iOS Shortcuts, cron) therefore need zero changes to reach desktop/Android clients — the core reminder scenario. Reading is separately authorized: stream registration (authenticated by the Device Key) issues per-client, revocable Stream Tokens as the read credential. A new token-less device type (`stream`) lets non-Apple users create an addressable Device without the Bark App (an additive extension under ADR-0003).

## Security properties

- The **Device Key authorizes pushing and stream-token minting**: it is a shared management secret in the upstream bark model (it appears in push URLs and doubles as the push credential), so whoever can push to a Device can also mint themselves a Stream Token for it. The credential split below is about *storage exposure on client machines*, not about splitting authority between two independent secrets.
- **Stream Tokens give clients a revocable, per-client read credential**, so the long-lived Device Key never has to be stored on client machines: each machine holds only its own token.
- **A leaked or compromised token can be revoked without rotating the Device Key** — revocation is per-token, persistent, and immediate; the Device Key and every other token keep working.

## Considered options

- **Separate subscription-key namespace**: rejected — pushes would need explicit addressing, breaking zero-change push scripts; revisit only if a genuine need appears.
- **Bridge + namespaces together now**: rejected as YAGNI; the protocol doc reserves version headroom instead.
