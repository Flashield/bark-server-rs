//! Device Key generation mirroring upstream's `shortuuid.New()`
//! (lithammer/shortuuid v3): a UUIDv4 encoded base57 over the default
//! alphabet, least significant digit first, padded to 22 characters.
//!
//! Upstream pads only to `ceil(ln25/ln57 * 16)` = 13, so ~2% of its keys are
//! 21 characters (and pathological UUIDs shorter still); the device-key
//! contract here is a fixed 22-char key (ticket acceptance criterion), which
//! is also the natural maximum width for a 128-bit value in base57. Keys from
//! either implementation decode identically.

/// `shortuuid.DefaultAlphabet` — deduped and sorted by `newAlphabet`; the
/// default alphabet is already in byte-sorted order.
const BASE57: &[u8; 57] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Generate a new Device Key: a fresh UUIDv4, base57-encoded, 22 characters.
pub fn new_device_key() -> String {
    encode(new_uuid_v4())
}

/// Encode a UUID (16 bytes) exactly like shortuuid's `base57.numToString`:
/// digits are extracted least-significant first and appended in that order,
/// then the string is padded with `alphabet[0]` to 22 characters.
pub fn encode(uuid: [u8; 16]) -> String {
    let mut n = u128::from_be_bytes(uuid);
    let mut digits = Vec::with_capacity(22);
    while n > 0 {
        digits.push(BASE57[(n % 57) as usize]);
        n /= 57;
    }
    while digits.len() < 22 {
        digits.push(BASE57[0]);
    }
    // digits are LSB-first as appended; that is shortuuid's wire order.
    String::from_utf8(digits).expect("alphabet is ASCII")
}

/// A random UUIDv4 (version nibble `4`, RFC 4122 variant bits `10xx`),
/// sourced from the OS CSPRNG. Hand-rolled to stay dependency-light; mirrors
/// what the `uuid` crate would produce for `Uuid::new_v4()`.
pub(crate) fn new_uuid_v4() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    crate::random::fill(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}

/// A random UUIDv4 in canonical lowercase hex form (`8-4-4-4-4-12` with
/// hyphens) — what the `uuid` crate renders for `Uuid::new_v4()`. The MCP
/// session ids (`mcp-session-<uuid>`) mint theirs here.
pub fn new_uuid_v4_string() -> String {
    let bytes = new_uuid_v4();
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}
