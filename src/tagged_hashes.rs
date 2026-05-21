//! This module holds declarations for computing
//! [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)-style
//! tagged hashes.
//!
//! A tagged hash is a SHA256 hash which has been prefixed with two copies of
//! the SHA256 hash of a given fixed constant byte string. This has the effect
//! of namespacing the hash to reduce the possibility of collisions.
//!
//! You probably won't need to use these hashes yourself, but if you want to
//! produce a tagged hash, simply clone one of the lazily allocated hash engines
//! declared as statics in this module. This will give you an instance of
//! `sha2::Sha256`.
//!
//! ```
//! use musig2::tagged_hashes;
//! use sha2::Sha256;
//! use sha2::Digest as _; // Brings trait methods into scope
//!
//! let hash = tagged_hashes::KEYAGG_LIST_TAG_HASHER
//!     .clone()
//!     .chain_update(b"SomeData")
//!     .finalize();
//!
//! let expected = {
//!     let tag_digest = Sha256::digest("KeyAgg list");
//!     Sha256::new()
//!         .chain_update(&tag_digest)
//!         .chain_update(&tag_digest)
//!         .chain_update(b"SomeData")
//!         .finalize()
//! };
//!
//! assert_eq!(hash, expected);
//! ```

use sha2::Sha256;
use std::sync::LazyLock;

use sha2::Digest as _;

fn with_tag_hash_prefix(tag_hash: [u8; 32]) -> Sha256 {
    Sha256::new().chain_update(tag_hash).chain_update(tag_hash)
}

/// sha256(b"KeyAgg list")
const KEYAGG_LIST_TAG_DIGEST: [u8; 32] = [
    0x48, 0x1C, 0x97, 0x1C, 0x3C, 0x0B, 0x46, 0xD7, 0xF0, 0xB2, 0x75, 0xAE, 0x59, 0x8D, 0x4E, 0x2C,
    0x7E, 0xD7, 0x31, 0x9C, 0x59, 0x4A, 0x5C, 0x6E, 0xC7, 0x9E, 0xA0, 0xD4, 0x99, 0x02, 0x94, 0xF0,
];

/// sha256(b"KeyAgg coefficient")
const KEYAGG_COEFF_TAG_DIGEST: [u8; 32] = [
    0xBF, 0xC9, 0x04, 0x03, 0x4D, 0x1C, 0x88, 0xE8, 0xC8, 0x0E, 0x22, 0xE5, 0x3D, 0x24, 0x56, 0x6D,
    0x64, 0x82, 0x4E, 0xD6, 0x42, 0x72, 0x81, 0xC0, 0x91, 0x00, 0xF9, 0x4D, 0xCD, 0x52, 0xC9, 0x81,
];

/// sha256(b"MuSig/aux")
const MUSIG_AUX_TAG_DIGEST: [u8; 32] = [
    0x40, 0x8F, 0x8C, 0x1F, 0x29, 0x24, 0x21, 0xB5, 0x56, 0x9E, 0xBC, 0x6C, 0xB5, 0xF2, 0xE2, 0x0C,
    0xF1, 0xE3, 0x84, 0x1B, 0x47, 0x43, 0x9F, 0xCC, 0x58, 0x7D, 0x20, 0xE3, 0xC1, 0x7F, 0x08, 0x37,
];

/// sha256(b"MuSig/nonce")
const MUSIG_NONCE_TAG_DIGEST: [u8; 32] = [
    0xF8, 0xC1, 0x0C, 0xBC, 0x61, 0x4E, 0xD1, 0xA0, 0x84, 0xB4, 0x37, 0x05, 0x2B, 0x5D, 0x2C, 0x4B,
    0x50, 0x1A, 0x9D, 0xE7, 0xAA, 0xFB, 0xE3, 0x48, 0xAC, 0xE8, 0x02, 0x6C, 0xA7, 0xFC, 0xB1, 0x7B,
];

/// sha256(b"MuSig/noncecoef")
const MUSIG_NONCECOEF_TAG_DIGEST: [u8; 32] = [
    0x5A, 0x6D, 0x45, 0xF6, 0xDA, 0x29, 0xE6, 0x51, 0xCB, 0x1B, 0xA2, 0xB8, 0xAC, 0x2C, 0xDD, 0x4E,
    0xBC, 0x15, 0xC2, 0xFB, 0xB2, 0x89, 0xF0, 0xCC, 0x82, 0x1B, 0xBF, 0x0A, 0x34, 0x09, 0x5F, 0x32,
];

/// sha256(b"BIP0340/aux")
const BIP0340_AUX_TAG_DIGEST: [u8; 32] = [
    0xF1, 0xEF, 0x4E, 0x5E, 0xC0, 0x63, 0xCA, 0xDA, 0x6D, 0x94, 0xCA, 0xFA, 0x9D, 0x98, 0x7E, 0xA0,
    0x69, 0x26, 0x58, 0x39, 0xEC, 0xC1, 0x1F, 0x97, 0x2D, 0x77, 0xA5, 0x2E, 0xD8, 0xC1, 0xCC, 0x90,
];

/// sha256(b"BIP0340/nonce")
const BIP0340_NONCE_TAG_DIGEST: [u8; 32] = [
    0x07, 0x49, 0x77, 0x34, 0xA7, 0x9B, 0xCB, 0x35, 0x5B, 0x9B, 0x8C, 0x7D, 0x03, 0x4F, 0x12, 0x1C,
    0xF4, 0x34, 0xD7, 0x3E, 0xF7, 0x2D, 0xDA, 0x19, 0x87, 0x00, 0x61, 0xFB, 0x52, 0xBF, 0xEB, 0x2F,
];

/// sha256(b"BIP0340/challenge")
const BIP0340_CHALLENGE_TAG_DIGEST: [u8; 32] = [
    0x7B, 0xB5, 0x2D, 0x7A, 0x9F, 0xEF, 0x58, 0x32, 0x3E, 0xB1, 0xBF, 0x7A, 0x40, 0x7D, 0xB3, 0x82,
    0xD2, 0xF3, 0xF2, 0xD8, 0x1B, 0xB1, 0x22, 0x4F, 0x49, 0xFE, 0x51, 0x8F, 0x6D, 0x48, 0xD3, 0x7C,
];

/// sha256(b"BIP0340/batch")
const BIP0340_BATCH_TAG_DIGEST: [u8; 32] = [
    0x77, 0x06, 0x39, 0x59, 0x84, 0x1F, 0xFA, 0x7B, 0x06, 0x15, 0x4E, 0xE0, 0x47, 0x50, 0x19, 0x40,
    0x36, 0x48, 0x7A, 0xB8, 0x91, 0x96, 0xD0, 0x6E, 0xC7, 0x3E, 0x75, 0x82, 0x90, 0x98, 0x41, 0xB5,
];

/// sha256(b"TapTweak")
const TAPROOT_TWEAK_TAG_DIGEST: [u8; 32] = [
    0xe8, 0x0f, 0xe1, 0x63, 0x9c, 0x9c, 0xa0, 0x50, 0xe3, 0xaf, 0x1b, 0x39, 0xc1, 0x43, 0xc6, 0x3e,
    0x42, 0x9c, 0xbc, 0xeb, 0x15, 0xd9, 0x40, 0xfb, 0xb5, 0xc5, 0xa1, 0xf4, 0xaf, 0x57, 0xc5, 0xe9,
];

/// A `sha2::Sha256` hash engine with its state initialized to:
///
/// ```notrust
/// sha256(b"KeyAgg list") || sha256(b"KeyAgg list")
/// ```
pub static KEYAGG_LIST_TAG_HASHER: LazyLock<Sha256> =
    LazyLock::new(|| with_tag_hash_prefix(KEYAGG_LIST_TAG_DIGEST));

/// A `sha2::Sha256` hash engine with its state initialized to:
///
/// ```notrust
/// sha256(b"KeyAgg coefficient") || sha256(b"KeyAgg coefficient")
/// ```
pub static KEYAGG_COEFF_TAG_HASHER: LazyLock<Sha256> =
    LazyLock::new(|| with_tag_hash_prefix(KEYAGG_COEFF_TAG_DIGEST));

/// A `sha2::Sha256` hash engine with its state initialized to:
///
/// ```notrust
/// sha256(b"MuSig/aux") || sha256(b"MuSig/aux")
/// ```
pub static MUSIG_AUX_TAG_HASHER: LazyLock<Sha256> =
    LazyLock::new(|| with_tag_hash_prefix(MUSIG_AUX_TAG_DIGEST));

/// A `sha2::Sha256` hash engine with its state initialized to:
///
/// ```notrust
/// sha256(b"MuSig/nonce") || sha256(b"MuSig/nonce")
/// ```
pub static MUSIG_NONCE_TAG_HASHER: LazyLock<Sha256> =
    LazyLock::new(|| with_tag_hash_prefix(MUSIG_NONCE_TAG_DIGEST));

/// A `sha2::Sha256` hash engine with its state initialized to:
///
/// ```notrust
/// sha256(b"MuSig/noncecoef") || sha256(b"MuSig/noncecoef")
/// ```
pub static MUSIG_NONCECOEF_TAG_HASHER: LazyLock<Sha256> =
    LazyLock::new(|| with_tag_hash_prefix(MUSIG_NONCECOEF_TAG_DIGEST));

/// A `sha2::Sha256` hash engine with its state initialized to:
///
/// ```notrust
/// sha256(b"BIP0340/aux") || sha256(b"BIP0340/aux")
/// ```
pub static BIP0340_AUX_TAG_HASHER: LazyLock<Sha256> =
    LazyLock::new(|| with_tag_hash_prefix(BIP0340_AUX_TAG_DIGEST));

/// A `sha2::Sha256` hash engine with its state initialized to:
///
/// ```notrust
/// sha256(b"BIP0340/nonce") || sha256(b"BIP0340/nonce")
/// ```
pub static BIP0340_NONCE_TAG_HASHER: LazyLock<Sha256> =
    LazyLock::new(|| with_tag_hash_prefix(BIP0340_NONCE_TAG_DIGEST));

/// A `sha2::Sha256` hash engine with its state initialized to:
///
/// ```notrust
/// sha256(b"BIP0340/challenge") || sha256(b"BIP0340/challenge")
/// ```
pub static BIP0340_CHALLENGE_TAG_HASHER: LazyLock<Sha256> =
    LazyLock::new(|| with_tag_hash_prefix(BIP0340_CHALLENGE_TAG_DIGEST));

/// A `sha2::Sha256` hash engine with its state initialized to:
///
/// ```notrust
/// sha256(b"BIP0340/batch") || sha256(b"BIP0340/batch")
/// ```
pub static BIP0340_BATCH_TAG_HASHER: LazyLock<Sha256> =
    LazyLock::new(|| with_tag_hash_prefix(BIP0340_BATCH_TAG_DIGEST));

/// A `sha2::Sha256` hash engine with its state initialized to:
///
/// ```notrust
/// sha256(b"TapTweak") || sha256(b"TapTweak")
/// ```
pub static TAPROOT_TWEAK_TAG_HASHER: LazyLock<Sha256> =
    LazyLock::new(|| with_tag_hash_prefix(TAPROOT_TWEAK_TAG_DIGEST));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tagged_hash() {
        let test_cases = [
            ("KeyAgg list", KEYAGG_LIST_TAG_DIGEST),
            ("KeyAgg coefficient", KEYAGG_COEFF_TAG_DIGEST),
            ("MuSig/aux", MUSIG_AUX_TAG_DIGEST),
            ("MuSig/nonce", MUSIG_NONCE_TAG_DIGEST),
            ("MuSig/noncecoef", MUSIG_NONCECOEF_TAG_DIGEST),
            ("BIP0340/aux", BIP0340_AUX_TAG_DIGEST),
            ("BIP0340/nonce", BIP0340_NONCE_TAG_DIGEST),
            ("BIP0340/challenge", BIP0340_CHALLENGE_TAG_DIGEST),
            ("BIP0340/batch", BIP0340_BATCH_TAG_DIGEST), // custom
            ("TapTweak", TAPROOT_TWEAK_TAG_DIGEST),
        ];
        for (tag, declared_hash) in test_cases {
            let actual_hash = <[u8; 32]>::from(sha2::Sha256::digest(tag));
            assert_eq!(declared_hash, actual_hash);
        }
    }
}
