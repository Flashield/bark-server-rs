# Realtime streams attach to Devices (bridge model) with separate read credentials

SSE streams bind to an existing Device, not to a separate subscription namespace: a push addressed to a Device Key fans out to APNs (when a Device Token exists) **and** to every live Realtime Stream on that Device. Existing push-side scripts (curl, iOS Shortcuts, cron) therefore need zero changes to reach desktop/Android clients — the core reminder scenario. Reading is separately authorized: stream registration (authenticated once by Device Key) issues per-client, revocable Stream Tokens, so holders of the push key cannot read notification contents. A new token-less device type (`stream`) lets non-Apple users create an addressable Device without the Bark App (an additive extension under ADR-0003).

## Considered options

- **Separate subscription-key namespace**: rejected — pushes would need explicit addressing, breaking zero-change push scripts; revisit only if a genuine need appears.
- **Bridge + namespaces together now**: rejected as YAGNI; the protocol doc reserves version headroom instead.
