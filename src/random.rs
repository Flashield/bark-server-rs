//! OS CSPRNG reads shared by everything that mints secrets: Device Keys
//! ([`crate::shortuuid`]) and Stream Tokens ([`crate::api::realtime`]).
//! Hand-rolled from `/dev/urandom` to stay dependency-light, like the rest
//! of the secret-generating code.

/// Fill `buf` with cryptographically random bytes from the OS CSPRNG.
pub fn fill(buf: &mut [u8]) {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").expect("open /dev/urandom");
    f.read_exact(buf).expect("read full entropy buffer");
}
