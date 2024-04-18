use crate::errors::VerifyError;
use crate::{
    compute_challenge_hash_tweak, tagged_hashes, xor_bytes, AdaptorSignature, CompactSignature,
    LiftedSignature, NonceSeed,
};

use secp::{MaybePoint, MaybeScalar, Point, Scalar, G};

#[cfg(any(test, feature = "rand"))]
use rand::SeedableRng as _;

use sha2::Digest as _;
use subtle::ConstantTimeEq as _;

/// Create a [BIP340-compatible](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
/// Schnorr adaptor signature on the given message with a single private key.
///
/// The resulting signature is verifiably encrypted under the given `adaptor_point`,
/// such that it can only be considered valid under BIP340 if it is then
/// _adapted_ using the discrete log of `adaptor_point`. See
/// [`AdaptorSignature::adapt`] to decrypt it once you know the adaptor secret.
///
/// You can also compute the adaptor secret from the final decrypted signature,
/// if you can find it.
///
/// This is provided in case MuSig implementations may wish to make use of
/// signatures to non-interactively prove the origin of a message. For example,
/// if all messages between co-signers are signed, then peers can assign blame
/// to any dishonest signers by sharing a copy of their dishonest message, which
/// will bear their signature.
pub fn sign_solo_adaptor(
    seckey: impl Into<Scalar>,
    message: impl AsRef<[u8]>,
    nonce_seed: impl Into<NonceSeed>,
    adaptor_point: impl Into<MaybePoint>,
) -> AdaptorSignature {
    let seckey: Scalar = seckey.into();
    let nonce_seed: NonceSeed = nonce_seed.into();

    let pubkey = seckey.base_point_mul();
    let d = seckey.negate_if(pubkey.parity());

    let h: [u8; 32] = tagged_hashes::BIP0340_AUX_TAG_HASHER
        .clone()
        .chain_update(&nonce_seed.0)
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

    let R = prenonce * G; // encrypted nonce
    let adapted_nonce = R + adaptor_point.into();

    // If the adapted nonce is odd-parity, we must negate our nonce and
    // later also negate the adaptor secret at decryption time.
    let k = prenonce.negate_if(adapted_nonce.parity());

    let nonce_x_bytes = adapted_nonce.serialize_xonly();
    let e: MaybeScalar = compute_challenge_hash_tweak(&nonce_x_bytes, &pubkey, message);

    let s = k + e * d;

    AdaptorSignature::new(R, s)
}

/// Create a [BIP340-compatible](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
/// Schnorr signature on the given message with a single private key.
///
/// This is provided in case MuSig implementations may wish to make use of
/// signatures to non-interactively prove the origin of a message. For example,
/// if all messages between co-signers are signed, then peers can assign blame
/// to any dishonest signers by sharing a copy of their dishonest message, which
/// will bear their signature.
///
/// This function is effectively the same as [`sign_solo_adaptor`] but passing
/// [`MaybePoint::Infinity`] as the adaptor point.
pub fn sign_solo<T>(
    seckey: impl Into<Scalar>,
    message: impl AsRef<[u8]>,
    nonce_seed: impl Into<NonceSeed>,
) -> T
where
    T: From<LiftedSignature>,
{
    sign_solo_adaptor(seckey, message, nonce_seed, MaybePoint::Infinity)
        .adapt(MaybeScalar::Zero)
        .map(T::from)
        .expect("signing with empty adaptor should never result in an adaptor failure")
}

/// Verifies a [BIP340-compatible](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
/// Schnorr adaptor signature, which could be aggregated or from a single-signer.
///
/// The signature will verify only if it is encrypted under the given adaptor point.
///
/// The `signature` argument is parsed as a [`LiftedSignature`]. You may pass any
/// type which converts fallibly to a [`LiftedSignature`], including `&[u8]`, `[u8; 64]`,
/// [`CompactSignature`], and so on.
///
/// Returns an error if the adaptor signature is invalid, which includes
/// if the signature has been decrypted and is a fully valid signature.
pub fn verify_single_adaptor(
    pubkey: impl Into<Point>,
    adaptor_signature: &AdaptorSignature,
    message: impl AsRef<[u8]>,
    adaptor_point: impl Into<MaybePoint>,
) -> Result<(), VerifyError> {
    use VerifyError::BadSignature;

    let pubkey: Point = pubkey.into().to_even_y(); // lift_x(x(P))

    let &AdaptorSignature { R, s } = adaptor_signature;

    let adapted_nonce = R + adaptor_point.into();
    let nonce_x_bytes = adapted_nonce.serialize_xonly();
    let e: MaybeScalar = compute_challenge_hash_tweak(&nonce_x_bytes, &pubkey, message);

    // If the adapted nonce is odd-parity, the signer should have negated their nonce
    // when signing.
    let effective_nonce = if adapted_nonce.has_even_y() { R } else { -R };

    // sG = R + eD
    if s * G != effective_nonce + e * pubkey {
        return Err(BadSignature);
    }

    Ok(())
}

/// Verifies a [BIP340-compatible](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
/// Schnorr signature, which could be aggregated or from a single-signer.
///
/// The `signature` argument is parsed as a [`CompactSignature`]. You may pass any
/// type which converts fallibly to a [`CompactSignature`], including `&[u8]`, `[u8; 64]`,
/// [`LiftedSignature`], and so on.
///
/// Returns an error if the signature is invalid.
pub fn verify_single(
    pubkey: impl Into<Point>,
    signature: impl TryInto<CompactSignature>,
    message: impl AsRef<[u8]>,
) -> Result<(), VerifyError> {
    use VerifyError::BadSignature;

    let pubkey: Point = pubkey.into().to_even_y(); // lift_x(x(P))
    let CompactSignature { rx, s } = signature.try_into().map_err(|_| BadSignature)?;
    let e: MaybeScalar = compute_challenge_hash_tweak(&rx, &pubkey, message);

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

/// Represents a pre-processed entry in a batch of signatures to be verified.
/// This can encapsulate either a normal BIP340 signature, or an adaptor signature.
///
/// To verify a large number of signatures efficiently, pass a slice of
/// [`BatchVerificationRow`] to [`verify_batch`].
#[cfg(any(test, feature = "rand"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchVerificationRow {
    pubkey: Point,
    challenge: MaybeScalar,
    R: MaybePoint,
    s: MaybeScalar,
}

#[cfg(any(test, feature = "rand"))]
impl BatchVerificationRow {
    /// Construct a row in a batch verification table from a given BIP340 signature.
    pub fn from_signature<M: AsRef<[u8]>>(
        pubkey: impl Into<Point>,
        message: M,
        signature: LiftedSignature,
    ) -> Self {
        let pubkey = pubkey.into();
        let challenge =
            compute_challenge_hash_tweak(&signature.R.serialize_xonly(), &pubkey, message.as_ref());

        BatchVerificationRow {
            pubkey,
            challenge,
            R: MaybePoint::Valid(signature.R),
            s: signature.s,
        }
    }

    /// Construct a row in a batch verification table from a given BIP340 adaptor signature.
    pub fn from_adaptor_signature<M: AsRef<[u8]>>(
        pubkey: impl Into<Point>,
        message: M,
        adaptor_signature: AdaptorSignature,
        adaptor_point: MaybePoint,
    ) -> Self {
        let pubkey = pubkey.into();
        let adapted_nonce = adaptor_signature.R + adaptor_point;

        // If the adapted nonce is odd-parity, the signer should have negated their nonce
        // when signing.
        let effective_nonce = if adapted_nonce.has_even_y() {
            adaptor_signature.R
        } else {
            -adaptor_signature.R
        };

        let challenge = compute_challenge_hash_tweak(
            &adapted_nonce.serialize_xonly(),
            &pubkey,
            message.as_ref(),
        );

        BatchVerificationRow {
            pubkey,
            challenge,
            R: effective_nonce,
            s: adaptor_signature.s,
        }
    }
}

/// Runs [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
/// batch verification on a collection of schnorr signatures.
///
/// Batch verification checks a table of pubkeys, messages, and
/// signatures and returns an error if any signatures in the
/// collection are not valid for the corresponding `(pubkey, message)`
/// pair.
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
#[cfg(any(test, feature = "rand"))]
pub fn verify_batch(rows: &[BatchVerificationRow]) -> Result<(), VerifyError> {
    // Seed the CSPRNG
    let mut rng = {
        let mut seed_hash = tagged_hashes::BIP0340_BATCH_TAG_HASHER.clone();

        // Challenges commit to the pubkey, nonce, and message. That's why
        // we're not explicitly seeding the RNG with the pubkey, nonce, and message
        // as suggested by BIP340.
        for row in rows {
            seed_hash.update(&row.challenge.serialize());
        }

        for row in rows {
            seed_hash.update(&row.s.serialize());
        }
        rand::rngs::StdRng::from_seed(seed_hash.finalize().into())
    };

    let mut lhs = MaybeScalar::Zero;
    let mut rhs_terms = Vec::<MaybePoint>::with_capacity(rows.len() * 2);

    for (i, row) in rows.into_iter().enumerate() {
        let random = if i == 0 {
            Scalar::one()
        } else {
            Scalar::random(&mut rng)
        };

        let pubkey = row.pubkey.to_even_y(); // lift_x on all pubkeys

        lhs += row.s * random;
        rhs_terms.push(row.R * random);
        rhs_terms.push((random * row.challenge) * pubkey);
    }

    // (s1*a1 + s2*a2 + ... + sn*an)G ?= (a1*R1) + (a2*R2) + ... + (an*Rn) +
    //                                   (a1*e1*P1) + (a2*e2*P2) + ... + (an*en*Pn)
    let rhs = MaybePoint::sum(rhs_terms);
    if lhs * G == rhs {
        Ok(())
    } else {
        Err(VerifyError::BadSignature)
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

        let mut valid_sigs_batch = Vec::<BatchVerificationRow>::new();

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

                // Test adaptor signatures
                {
                    let adaptor_secret = MaybeScalar::Valid(seckey); // arbitrary secret
                    let adaptor_point = adaptor_secret * G;
                    let adaptor_signature =
                        sign_solo_adaptor(seckey, &record.message, &aux_rand, adaptor_point);

                    verify_single_adaptor(
                        pubkey,
                        &adaptor_signature,
                        &record.message,
                        adaptor_point,
                    )
                    .expect("failed to verify valid adaptor signature");

                    // Ensure the decrypted signature is valid.
                    let valid_sig = adaptor_signature.adapt(adaptor_secret).unwrap();
                    verify_single(pubkey, valid_sig, &record.message)
                        .expect("failed to verify decrypted adaptor signature");

                    // Ensure observers can learn the adaptor secret from published signatures.
                    let revealed: MaybeScalar = adaptor_signature
                        .reveal_secret(&valid_sig)
                        .expect("decrypted signature should reveal adaptor secret");
                    assert_eq!(revealed, adaptor_secret);
                }
            }

            let verify_result = verify_single(pubkey, test_vec_signature, &record.message);
            match record.verification_result.as_str() {
                "TRUE" => {
                    verify_result.expect(&format!(
                        "verification should pass for signature {} - {}",
                        &record.signature, record.comment,
                    ));
                    valid_sigs_batch.push(BatchVerificationRow::from_signature(
                        pubkey,
                        record.message,
                        LiftedSignature::try_from(test_vec_signature).unwrap(),
                    ));
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

        // test batch verification
        verify_batch(&valid_sigs_batch).expect("batch verification failed");
    }
}
