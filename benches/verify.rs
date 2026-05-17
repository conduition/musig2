#![feature(test)]
use secp::Scalar;

extern crate test;

#[bench]
fn bip340_verify_single(b: &mut test::Bencher) {
    let seckey: Scalar = "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9"
        .parse()
        .unwrap();
    let pubkey = seckey.base_point_mul();
    let message = b"hey there";
    let signature: [u8; 64] = musig2::deterministic::sign_solo(seckey, message);
    b.iter(|| {
        let _ = musig2::verify_single(pubkey, signature, message);
    })
}

/// For comparison to libsecp256k1
#[cfg(feature = "secp256k1")]
#[bench]
fn bip340_verify_single_libsecp256k1(b: &mut test::Bencher) {
    let seckey: Scalar = "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9"
        .parse()
        .unwrap();
    let ctx = secp256k1::Secp256k1::new();
    let message = b"hey there";
    let signature: [u8; 64] = musig2::deterministic::sign_solo(seckey, message);
    let pubkey_bytes = seckey.base_point_mul().serialize_xonly();
    b.iter(|| {
        let pubkey = secp256k1::XOnlyPublicKey::from_byte_array(pubkey_bytes).unwrap();
        pubkey.verify(
            &ctx,
            message,
            &secp256k1::schnorr::Signature::from_byte_array(signature),
        )
    })
}
