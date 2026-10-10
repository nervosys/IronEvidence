//! Name-based UUIDs (RFC 4122 version 5), so that the same statement gets the
//! same identifier in every run without a hand-kept list.
//!
//! Version 5 is defined over SHA-1. It is used here only to derive
//! identifiers from public names; it is not a security function, and nothing
//! depends on SHA-1 resisting collisions.

/// The namespace every IronEvidence identifier is derived under.
pub const NAMESPACE: [u8; 16] = [
    0x1d, 0x6e, 0x0f, 0x5a, 0x3c, 0x41, 0x4b, 0x7e, 0x9a, 0x52, 0x7b, 0x0e, 0x61, 0xc3, 0x2f, 0x84,
];

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut state: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for block in message.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = state;
        for (i, word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let next = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next;
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d, e]) {
            *s = s.wrapping_add(v);
        }
    }
    let mut out = [0u8; 20];
    for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        *chunk = word.to_be_bytes();
    }
    out
}

/// The version 5 UUID of `name` in `namespace`, as lowercase text.
pub fn uuid5(namespace: &[u8; 16], name: &str) -> String {
    let mut input = namespace.to_vec();
    input.extend_from_slice(name.as_bytes());
    let digest = sha1(&input);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// The identifier IronEvidence gives `name`.
pub fn id(name: &str) -> String {
    uuid5(&NAMESPACE, name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_matches_the_rfc_3174_vectors() {
        let hex = |d: [u8; 20]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(
            hex(sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(hex(sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn uuid5_matches_a_published_example() {
        // uuid.uuid5(uuid.NAMESPACE_DNS, "python.org") in Python's documentation.
        let dns = [
            0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4,
            0x30, 0xc8,
        ];
        assert_eq!(
            uuid5(&dns, "python.org"),
            "886313e1-3b8a-5372-9b90-0c9aee199e5d"
        );
        // Stable, distinct, and of the version and variant OSCAL requires.
        let (a, b) = (
            id("ironcrypto/sp800-53/sc-13"),
            id("ironcrypto/sp800-53/sc-12"),
        );
        assert_eq!(a, id("ironcrypto/sp800-53/sc-13"));
        assert_ne!(a, b);
        assert_eq!(a.as_bytes()[14], b'5');
        assert!(matches!(a.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
    }
}
