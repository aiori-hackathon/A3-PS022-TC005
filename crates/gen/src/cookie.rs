//! SipHash-2-4 and RFC 9018 server-cookie construction, so the prober can present valid cookies.

use std::net::IpAddr;

/// SipHash-2-4 over `data` with a 16-byte key.
pub fn siphash24(key: &[u8; 16], data: &[u8]) -> u64 {
    let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());
    let mut v0 = 0x736f6d6570736575u64 ^ k0;
    let mut v1 = 0x646f72616e646f6du64 ^ k1;
    let mut v2 = 0x6c7967656e657261u64 ^ k0;
    let mut v3 = 0x7465646279746573u64 ^ k1;

    macro_rules! round {
        () => {
            v0 = v0.wrapping_add(v1);
            v1 = v1.rotate_left(13);
            v1 ^= v0;
            v0 = v0.rotate_left(32);
            v2 = v2.wrapping_add(v3);
            v3 = v3.rotate_left(16);
            v3 ^= v2;
            v0 = v0.wrapping_add(v3);
            v3 = v3.rotate_left(21);
            v3 ^= v0;
            v2 = v2.wrapping_add(v1);
            v1 = v1.rotate_left(17);
            v1 ^= v2;
            v2 = v2.rotate_left(32);
        };
    }

    let n = data.len();
    let end = n & !7;
    let mut off = 0;
    while off < end {
        let m = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        v3 ^= m;
        round!();
        round!();
        v0 ^= m;
        off += 8;
    }
    let mut b = (n as u64 & 0xff) << 56;
    for (i, &byte) in data[end..].iter().enumerate() {
        b |= (byte as u64) << (8 * i);
    }
    v3 ^= b;
    round!();
    round!();
    v0 ^= b;
    v2 ^= 0xff;
    round!();
    round!();
    round!();
    round!();
    v0 ^ v1 ^ v2 ^ v3
}

/// Builds a 24-byte client+server cookie valid for `client_ip` under `secret` (RFC 9018).
pub fn build_cookie(
    secret: &[u8; 16],
    client_ip: IpAddr,
    client_cookie: [u8; 8],
    ts: u32,
) -> [u8; 24] {
    let mut out = [0u8; 24];
    out[0..8].copy_from_slice(&client_cookie);
    out[8] = 1; // version
    // reserved out[9..12] stay 0
    out[12..16].copy_from_slice(&ts.to_be_bytes());
    // message = client-cookie(8) | version(1) | reserved(3) | timestamp(4) | client-ip
    let mut msg = Vec::with_capacity(32);
    msg.extend_from_slice(&out[0..16]);
    match client_ip {
        IpAddr::V4(v4) => msg.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => msg.extend_from_slice(&v6.octets()),
    }
    let h = siphash24(secret, &msg);
    out[16..24].copy_from_slice(&h.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_reference_vectors() {
        let mut k = [0u8; 16];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        let input: Vec<u8> = (0..15u8).collect();
        assert_eq!(siphash24(&k, &input), 0xa129ca6149be45e5);
        assert_eq!(siphash24(&k, &[]), 0x726fdb47dd0e0e31);
    }

    #[test]
    fn cookie_has_version_and_hash() {
        let c = build_cookie(
            &[7u8; 16],
            "10.80.0.2".parse().unwrap(),
            [1, 2, 3, 4, 5, 6, 7, 8],
            1000,
        );
        assert_eq!(c[8], 1);
        assert_eq!(&c[0..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        // Hash bytes are not all zero.
        assert!(c[16..24].iter().any(|&b| b != 0));
    }
}
