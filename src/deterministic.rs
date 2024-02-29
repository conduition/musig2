//! This module provides determinstic BIP340-compatible single-signer logic using
//! [RFC6979](https://www.rfc-editor.org/rfc/rfc6979).
//!
//! This approach produces a synthetic nonce by deriving it from a
//! chained hash of the private key and and the message to be signed.
//! Generating nonces in this way makes signatatures deterministic.
//!
//! Technically RFC6979 is not part of the BIP340 spec, but it is entirely valid
//! to use deterministic nonce generation, provided you can guarantee that the
//! `(seckey, message)` pair are never used for other deterministic signatures
//! outside of BIP340.
//!
//! This is safe in a single-signer environment only (not for MuSig).
//! For deterministic nonces in a multi-signer environment, you will need
//! zero-knowledge proofs. See [this paper for details](https://eprint.iacr.org/2020/1057.pdf).
use secp::{MaybePoint, Scalar};

use crate::{AdaptorSignature, LiftedSignature};

use hmac::digest::FixedOutput as _;
use hmac::Mac as _;
use sha2::Digest as _;

fn hmac_sha256(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    hmac::Hmac::<sha2::Sha256>::new_from_slice(key.as_ref())
        .expect("Hmac::new_from_slice never fails")
        .chain_update(msg)
        .finalize_fixed()
        .into()
}

/// Derive a nonce from a given `(seckey, message)` pair. Follows the procedure
/// laid out in [this section of the RFC](https://www.rfc-editor.org/rfc/rfc6979#section-3.2).
pub fn derive_nonce_rfc6979(seckey: impl Into<Scalar>, message: impl AsRef<[u8]>) -> Scalar {
    let seckey = seckey.into();

    let h1 = sha2::Sha256::new()
        .chain_update(message.as_ref())
        .finalize();

    let mut V = [1u8; 32];
    let mut K = [0u8; 32];

    // Step D:
    //  K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
    let mut buf = vec![0u8; 32 + 1 + 32 + 32];
    buf[..32].copy_from_slice(&V);
    buf[32] = 0;
    buf[33..65].copy_from_slice(&seckey.serialize());
    buf[65..].copy_from_slice(&h1);
    K = hmac_sha256(&K, &buf);

    // Step E:
    //  V = HMAC_K(V)
    V = hmac_sha256(&K, &V);

    // Step F:
    //  K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
    buf[..32].copy_from_slice(&V);
    buf[32] = 1;
    K = hmac_sha256(&K, &buf);

    // Step G:
    //  V = HMAC_K(V)
    V = hmac_sha256(&K, &V);

    loop {
        // Step H2:
        //  V = HMAC_K(V)
        V = hmac_sha256(&K, &V);

        // Step H3:
        //  k = bits2int(V)
        if let Ok(k) = Scalar::from_slice(&V) {
            return k;
        }

        buf[..32].copy_from_slice(&V);
        buf[32] = 0;
        K = hmac_sha256(&K, &buf[..33]);
        V = hmac_sha256(&K, &V);
    }
}

/// This module provides a determinstic flavor of adaptor signature creation for single-signer contexts.
pub mod adaptor {
    use super::*;

    /// This is the same as [`adaptor::sign_solo`][crate::adaptor::sign_solo] except using
    /// deterministic nonce generation.
    pub fn sign_solo(
        seckey: impl Into<Scalar>,
        message: impl AsRef<[u8]>,
        adaptor_point: impl Into<MaybePoint>,
    ) -> AdaptorSignature {
        let seckey = seckey.into();
        let aux = derive_nonce_rfc6979(seckey, &message).serialize();
        crate::adaptor::sign_solo(seckey, message, aux, adaptor_point)
    }
}

/// This is the same as [`sign_solo`][crate::sign_solo] except using deterministic nonce generation.
pub fn sign_solo<T>(seckey: impl Into<Scalar>, message: impl AsRef<[u8]>) -> T
where
    T: From<LiftedSignature>,
{
    let seckey = seckey.into();
    let aux = derive_nonce_rfc6979(seckey, &message).serialize();
    crate::sign_solo(seckey, message, aux)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc6979_nonces() {
        struct TestVector {
            seckey: Scalar,
            message: &'static str,
            expected_nonce: &'static str,
        }

        let test_vectors = [
            // from https://www.rfc-editor.org/rfc/rfc6979#appendix-A.2.5
            TestVector {
                seckey: "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
                    .parse()
                    .unwrap(),
                message: "sample",
                expected_nonce: "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60",
            },
            TestVector {
                seckey: "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
                    .parse()
                    .unwrap(),
                message: "test",
                expected_nonce: "D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0",
            },
        ];

        for test in test_vectors {
            let nonce = derive_nonce_rfc6979(test.seckey, test.message);
            assert_eq!(format!("{:X}", nonce), test.expected_nonce);
        }
    }
}
