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
