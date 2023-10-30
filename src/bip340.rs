use crate::errors::VerifyError;
use crate::{
    compute_challenge_hash_tweak, tagged_hashes, xor_bytes, CompactSignature, LiftedSignature,
    NonceSeed,
};

use secp::{MaybeScalar, Point, Scalar, G};

#[cfg(feature = "rand")]
use secp::MaybePoint;

#[cfg(feature = "rand")]
use rand::SeedableRng as _;

use sha2::Digest as _;
use subtle::ConstantTimeEq as _;

/// Create a [BIP340-compatible](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
/// Schnorr signature on the given message with a single private key.
///
/// This is provided in case MuSig implementations may wish to make use of
/// signatures to non-interactively prove the origin of a message. For example,
/// if all messages between co-signers are signed, then peers can assign blame
/// to any dishonest signers by sharing a copy of their dishonest message, which
/// will bear their signature.
pub fn sign_solo<S, N, T>(seckey: S, message: impl AsRef<[u8]>, nonce_seed: N) -> T
where
    Scalar: From<S>,
    NonceSeed: From<N>,
    T: From<LiftedSignature>,
{
    let seckey = Scalar::from(seckey);
    let pubkey = seckey.base_point_mul();
    let d = seckey.negate_if(pubkey.parity());

    let h: [u8; 32] = tagged_hashes::BIP0340_AUX_TAG_HASHER
        .clone()
        .chain_update(&NonceSeed::from(nonce_seed).0)
        .finalize()
        .into();

    let t = xor_bytes(&h, &d.serialize());

    let rand: [u8; 32] = tagged_hashes::BIP0340_NONCE_TAG_HASHER
        .clone()
        .chain_update(&t)
        .chain_update(&pubkey.serialize_xonly())
        .chain_update(message.as_ref())
        .finalize()
        .into();

    // BIP340 says to fail if we get a nonce reducing to zero, but this is so
    // unlikely that the failure condition is not worth it. Default to 1 instead.
    let prenonce = match MaybeScalar::reduce_from(&rand) {
        MaybeScalar::Zero => Scalar::one(),
        MaybeScalar::Valid(k) => k,
    };

    let R = prenonce * G;
    let k = prenonce.negate_if(R.parity());
    let nonce_x_bytes = R.serialize_xonly();

    let e = compute_challenge_hash_tweak(&nonce_x_bytes, &pubkey, message);

    let s = k + e * d;

    T::from(LiftedSignature::new(R, s))
}

/// Verifies a [BIP340-compatible](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
/// Schnorr signature, which could be aggregated or from a single-signer.
///
/// The `signature` argument is parsed as a [`CompactSignature`]. You may pass any
/// type which converts fallibly to a [`CompactSignature`], including `&[u8]`, `[u8; 64]`,
/// `LiftedSignature`, and so on.
///
/// Returns an error if the signature is invalid.
pub fn verify_single<P, T>(
    pubkey: P,
    signature: T,
    message: impl AsRef<[u8]>,
) -> Result<(), VerifyError>
where
    Point: From<P>,
    CompactSignature: TryFrom<T>,
{
    use VerifyError::BadSignature;

    let pubkey = Point::from(pubkey).to_even_y(); // lift_x(x(P))
    let CompactSignature { rx, s } =
        CompactSignature::try_from(signature).map_err(|_| BadSignature)?;
    let e = compute_challenge_hash_tweak(&rx, &pubkey, message);

    // Instead of the usual sG = R + eD schnorr equation, we swap things around
    // slightly, thus avoiding the need to lift the x-only nonce.
    //
    // sG = R + eD
    // R = sG - eD
    let verification_point = (s * G - e * pubkey).not_inf().map_err(|_| BadSignature)?;
    if verification_point.has_odd_y() {
        return Err(BadSignature);
    }

    let valid = verification_point.serialize_xonly().ct_eq(&rx);
    if bool::from(valid) {
        Ok(())
    } else {
        Err(BadSignature)
    }
}

/// Runs [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
/// batch verification on a collection of schnorr signatures.
///
/// Batch verification checks a table of pubkeys, messages, and
/// signatures and returns an error if any signatures in the
/// collection are not valid for the corresponding `(pubkey, message)`
/// pair. All slices must be the same length or this function will
/// return an error.
///
/// As part of batch verification, signature nonces must be parsed
/// as valid curve points, so the raw signature type `T` must be fallibly
/// convertible to a [`LiftedSignature`], such as `&[u8]`, `[u8; 64]`,
/// [`CompactSignature`], [`secp256k1::schnorr::Signature`], etc.
/// If the conversion fails, we return [`VerifyError::BadSignature`].
///
/// Batch verification enables noteworthy speedups when verifying
/// large numbers of signatures, but does not give any indication
/// of _which_ signature(s) were invalid upon failure. Manual
/// investigation would be needed to narrow down which signature(s)
/// caused the verification to fail.
///
/// This requires the `rand` library for access to a seedable CSPRNG.
/// The RNG is seeded with all the pubkeys, messages, and signatures
/// rather than being truly random.
#[cfg(feature = "rand")]
pub fn verify_batch<P, M, T>(
    pubkeys: &[P],
    messages: &[M],
    raw_signatures: &[T],
) -> Result<(), VerifyError>
where
    P: Clone,
    Point: From<P>,
    M: AsRef<[u8]>,
    T: Clone,
    LiftedSignature: TryFrom<T>,
{
    use VerifyError::BadSignature;

    if pubkeys.len() != messages.len() || raw_signatures.len() != pubkeys.len() {
        return Err(BadSignature);
    }

    let pubkeys: Vec<Point> = pubkeys
        .iter()
        .map(|pubkey| Point::from(pubkey.clone()))
        .collect();

    let mut parsed_signatures = Vec::<LiftedSignature>::with_capacity(pubkeys.len());
    let mut challenge_tweaks = Vec::<MaybeScalar>::with_capacity(pubkeys.len());
    for (i, raw_signature) in raw_signatures.iter().enumerate() {
        let parsed_signature =
            LiftedSignature::try_from(raw_signature.clone()).map_err(|_| BadSignature)?;

        let e = compute_challenge_hash_tweak(
            &parsed_signature.R.serialize_xonly(),
            &pubkeys[i],
            messages[i].as_ref(),
        );

        parsed_signatures.push(parsed_signature);
        challenge_tweaks.push(e)
    }

    // Seed the CSPRNG

    let mut rng = {
        let mut seed_hash = tagged_hashes::BIP0340_BATCH_TAG_HASHER.clone();
        for pubkey in pubkeys.iter() {
            seed_hash.update(&pubkey.serialize());
        }
        for message in messages {
            seed_hash.update(message.as_ref());
        }
        for signature in parsed_signatures.iter() {
            seed_hash.update(&signature.serialize());
        }
        rand::rngs::StdRng::from_seed(seed_hash.finalize().into())
    };

    let mut lhs = MaybeScalar::Zero;
    let mut rhs_terms = Vec::<MaybePoint>::with_capacity(pubkeys.len());

    for i in 0..pubkeys.len() {
        let random = if i == 0 {
            Scalar::one()
        } else {
            Scalar::random(&mut rng)
        };

        let pubkey = pubkeys[i].to_even_y(); // lift_x on all pubkeys
        let (R, s): (Point, MaybeScalar) = parsed_signatures[i].unzip();
        let challenge = challenge_tweaks[i];

        lhs += s * random;
        rhs_terms.push(MaybePoint::Valid(R * random));
        rhs_terms.push((random * challenge) * pubkey);
    }

    // (s1*a1 + s2*a2 + ... + sn*an)G ?= (a1*R1) + (a2*R2) + ... + (an*Rn) +
    //                                   (a1*e1*P1) + (a2*e2*P2) + ... + (an*en*Pn)
    let rhs = MaybePoint::sum(rhs_terms);
    if lhs * G == rhs {
        Ok(())
    } else {
        Err(BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{testhex, BinaryEncoding, CompactSignature};
    use secp::Scalar;

    #[test]
    fn test_bip340_signatures() {
        const BIP340_TEST_VECTORS: &[u8] = include_bytes!("test_vectors/bip340_vectors.csv");

        #[derive(serde::Deserialize)]
        struct TestVectorRecord {
            index: usize,
            #[serde(rename = "secret key")]
            seckey: Option<Scalar>,
            #[serde(rename = "public key", deserialize_with = "testhex::deserialize")]
            pubkey_x: [u8; 32],
            #[serde(deserialize_with = "testhex::deserialize")]
            aux_rand: Vec<u8>,
            #[serde(deserialize_with = "testhex::deserialize")]
            message: Vec<u8>,
            signature: String,
            #[serde(rename = "verification result")]
            verification_result: String,
            comment: String,
        }

        let mut csv_reader = csv::Reader::from_reader(BIP340_TEST_VECTORS);

        let mut valid_sigs_batch = Vec::<(Point, Vec<u8>, [u8; 64])>::new();

        for result in csv_reader.deserialize() {
            let record: TestVectorRecord = result.expect("failed to parse BIP340 test vector");

            let pubkey = match Point::lift_x(&record.pubkey_x) {
                Ok(p) => p,
                Err(_) => {
                    if record.verification_result == "TRUE" {
                        panic!(
                            "expected verification to succeed on invalid public key {}",
                            base16ct::lower::encode_string(&record.pubkey_x)
                        );
                    }
                    continue; // not a test case we have to worry about.
                }
            };

            let test_vec_signature: [u8; 64] = base16ct::mixed::decode_vec(&record.signature)
                .expect(&format!("invalid signature hex: {}", record.signature))
                .try_into()
                .expect("invalid signature length");

            if let Some(seckey) = record.seckey {
                let aux_rand = <[u8; 32]>::try_from(record.aux_rand.as_slice()).expect(&format!(
                    "invalid aux_rand: {}",
                    base16ct::lower::encode_string(&record.aux_rand)
                ));

                let created_signature: CompactSignature =
                    sign_solo(seckey, &record.message, &aux_rand);

                assert_eq!(
                    created_signature.to_bytes(),
                    test_vec_signature,
                    "test vector signature does not match for test vector {}; {}",
                    record.index,
                    &record.comment
                );
            }

            let verify_result = verify_single(pubkey, test_vec_signature, &record.message);
            match record.verification_result.as_str() {
                "TRUE" => {
                    verify_result.expect(&format!(
                        "verification should pass for signature {} - {}",
                        &record.signature, record.comment,
                    ));
                    valid_sigs_batch.push((pubkey, record.message, test_vec_signature));
                }

                "FALSE" => {
                    assert_eq!(
                        verify_result,
                        Err(VerifyError::BadSignature),
                        "verification should fail for signature {} - {}",
                        &record.signature,
                        record.comment
                    );
                }

                s => panic!("unexpected verification result column value: {}", s),
            };
        }

        #[cfg(feature = "rand")]
        {
            // test batch verification
            let (pubkeys, (messages, raw_signatures)): (Vec<_>, (Vec<_>, Vec<_>)) =
                valid_sigs_batch
                    .into_iter()
                    .map(|(pk, msg, sig)| (pk, (msg, sig))) // unzip only supports tuples of length two
                    .unzip();

            verify_batch(&pubkeys, &messages, &raw_signatures).expect("batch verification failed");
        }
    }
}
