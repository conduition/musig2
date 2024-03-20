use crate::errors::{SigningError, VerifyError};
use crate::{tagged_hashes, AggNonce, KeyAggContext, PubNonce, SecNonce};

use secp::{MaybePoint, MaybeScalar, Point, Scalar, G};

use sha2::Digest as _;

/// Partial signatures are just scalars in the range `[0, n)`.
///
/// See the documentation of [`secp::MaybeScalar`] for the
/// parsing, serializing, and conversion traits available
/// on this type.
pub type PartialSignature = MaybeScalar;

/// Computes the challenge hash `e` for for a signature. You probably don't need
/// to call this directly. Instead use [`sign_solo`][crate::sign_solo] or
/// [`sign_partial`][crate::sign_partial].
pub fn compute_challenge_hash_tweak<S: From<MaybeScalar>>(
    final_nonce_xonly: &[u8; 32],
    aggregated_pubkey: &Point,
    message: impl AsRef<[u8]>,
) -> S {
    let hash: [u8; 32] = tagged_hashes::BIP0340_CHALLENGE_TAG_HASHER
        .clone()
        .chain_update(final_nonce_xonly)
        .chain_update(&aggregated_pubkey.serialize_xonly())
        .chain_update(message.as_ref())
        .finalize()
        .into();

    S::from(MaybeScalar::reduce_from(&hash))
}

/// Compute a partial signature on a message encrypted under an adaptor point.
///
/// The partial signature returned from this function is a potentially-zero
/// scalar value which can then be passed to other signers for verification
/// and aggregation.
///
/// Once aggregated, the signature must be adapted with the discrete log
/// (secret key) of `adaptor_point` for the signature to be considered valid.
///
/// Returns an error if the given secret key does not belong to this
/// `key_agg_ctx`. As an added safety, we also verify the partial signature
/// before returning it.
pub fn sign_partial_adaptor<T: From<PartialSignature>>(
    key_agg_ctx: &KeyAggContext,
    seckey: impl Into<Scalar>,
    secnonce: SecNonce,
    aggregated_nonce: &AggNonce,
    adaptor_point: impl Into<MaybePoint>,
    message: impl AsRef<[u8]>,
) -> Result<T, SigningError> {
    let adaptor_point: MaybePoint = adaptor_point.into();
    let seckey: Scalar = seckey.into();
    let pubkey = seckey.base_point_mul();

    // As a side-effect, looking up the cached key coefficient also confirms
    // the individual key is indeed part of the aggregated key.
    let key_coeff = key_agg_ctx
        .key_coefficient(pubkey)
        .ok_or(SigningError::UnknownKey)?;

    let aggregated_pubkey = key_agg_ctx.pubkey;
    let pubnonce = secnonce.public_nonce();

    let b: MaybeScalar = aggregated_nonce.nonce_coefficient(aggregated_pubkey, &message);
    let final_nonce: Point = aggregated_nonce.final_nonce(b);
    let adapted_nonce = final_nonce + adaptor_point;

    // `d` is negated if only one of the parity accumulator OR the aggregated pubkey
    // has odd parity.
    let d = seckey.negate_if(aggregated_pubkey.parity() ^ key_agg_ctx.parity_acc);

    let nonce_x_bytes = adapted_nonce.serialize_xonly();
    let e: MaybeScalar = compute_challenge_hash_tweak(&nonce_x_bytes, &aggregated_pubkey, &message);

    // if has_even_Y(R):
    //   k = k1 + b*k2
    // else:
    //   k = (n-k1) + b(n-k2)
    //     = n - (k1 + b*k2)
    let secnonce_sum = (secnonce.k1 + b * secnonce.k2).negate_if(adapted_nonce.parity());

    // s = k + e*a*d
    let partial_signature = secnonce_sum + (e * key_coeff * d);

    verify_partial_adaptor(
        key_agg_ctx,
        partial_signature,
        aggregated_nonce,
        adaptor_point,
        pubkey,
        &pubnonce,
        &message,
    )?;

    Ok(T::from(partial_signature))
}

/// Compute a partial signature on a message.
///
/// The partial signature returned from this function is a potentially-zero
/// scalar value which can then be passed to other signers for verification
/// and aggregation.
///
/// Returns an error if the given secret key does not belong to this
/// `key_agg_ctx`. As an added safety, we also verify the partial signature
/// before returning it.
///
/// This is equivalent to invoking [`sign_partial_adaptor`], but passing
/// [`MaybePoint::Infinity`] as the adaptor point.
pub fn sign_partial<T: From<PartialSignature>>(
    key_agg_ctx: &KeyAggContext,
    seckey: impl Into<Scalar>,
    secnonce: SecNonce,
    aggregated_nonce: &AggNonce,
    message: impl AsRef<[u8]>,
) -> Result<T, SigningError> {
    sign_partial_adaptor(
        key_agg_ctx,
        seckey,
        secnonce,
        aggregated_nonce,
        MaybePoint::Infinity,
        message,
    )
}

/// Verify a partial signature, usually from an untrusted co-signer,
/// which has been encrypted under an adaptor point.
///
/// If `verify_partial_adaptor` succeeds for every signature in
/// a signing session, the resulting aggregated signature is guaranteed
/// to be valid once it is adapted with the discrete log (secret key)
/// of `adaptor_point`.
///
/// Returns an error if the given public key doesn't belong to the
/// `key_agg_ctx`, or if the signature is invalid.
pub fn verify_partial_adaptor(
    key_agg_ctx: &KeyAggContext,
    partial_signature: impl Into<PartialSignature>,
    aggregated_nonce: &AggNonce,
    adaptor_point: impl Into<MaybePoint>,
    individual_pubkey: impl Into<Point>,
    individual_pubnonce: &PubNonce,
    message: impl AsRef<[u8]>,
) -> Result<(), VerifyError> {
    let partial_signature: MaybeScalar = partial_signature.into();

    // As a side-effect, looking up the cached effective key also confirms
    // the individual key is indeed part of the aggregated key.
    let effective_pubkey: MaybePoint = key_agg_ctx
        .effective_pubkey(individual_pubkey)
        .ok_or(VerifyError::UnknownKey)?;

    let aggregated_pubkey = key_agg_ctx.pubkey;

    let b: MaybeScalar = aggregated_nonce.nonce_coefficient(aggregated_pubkey, &message);
    let final_nonce: Point = aggregated_nonce.final_nonce(b);
    let adapted_nonce = final_nonce + adaptor_point.into();

    let mut effective_nonce = individual_pubnonce.R1 + b * individual_pubnonce.R2;

    // Don't need constant time ops here as adapted_nonce is public.
    if adapted_nonce.has_odd_y() {
        effective_nonce = -effective_nonce;
    }

    let nonce_x_bytes = adapted_nonce.serialize_xonly();
    let e: MaybeScalar = compute_challenge_hash_tweak(&nonce_x_bytes, &aggregated_pubkey, &message);

    // s * G == R + (g * gacc * e * a * P)
    let challenge_parity = aggregated_pubkey.parity() ^ key_agg_ctx.parity_acc;
    let challenge_point = (e * effective_pubkey).negate_if(challenge_parity);

    if partial_signature * G != effective_nonce + challenge_point {
        return Err(VerifyError::BadSignature);
    }

    Ok(())
}

/// Verify a partial signature, usually from an untrusted co-signer.
///
/// If `verify_partial` succeeds for every signature in
/// a signing session, the resulting aggregated signature is guaranteed
/// to be valid.
///
/// This function is effectively the same as invoking [`verify_partial_adaptor`]
/// but passing [`MaybePoint::Infinity`] as the adaptor point.
///
/// Returns an error if the given public key doesn't belong to the
/// `key_agg_ctx`, or if the signature is invalid.
pub fn verify_partial(
    key_agg_ctx: &KeyAggContext,
    partial_signature: impl Into<PartialSignature>,
    aggregated_nonce: &AggNonce,
    individual_pubkey: impl Into<Point>,
    individual_pubnonce: &PubNonce,
    message: impl AsRef<[u8]>,
) -> Result<(), VerifyError> {
    verify_partial_adaptor(
        key_agg_ctx,
        partial_signature,
        aggregated_nonce,
        MaybePoint::Infinity,
        individual_pubkey,
        individual_pubnonce,
        message,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::DecodeError;
    use crate::testhex;

    #[test]
    fn test_partial_sign_and_verify() {
        const SIGN_VERIFY_VECTORS: &[u8] = include_bytes!("test_vectors/sign_verify_vectors.json");

        #[derive(serde::Deserialize)]
        struct ValidSignVerifyTestCase {
            key_indices: Vec<usize>,
            nonce_indices: Vec<usize>,
            aggnonce_index: usize,
            msg_index: usize,
            signer_index: usize,
            expected: MaybeScalar,
        }

        #[derive(serde::Deserialize, Clone)]
        struct SignError {
            signer: Option<usize>,
        }

        #[derive(serde::Deserialize, Clone)]
        struct SignErrorTestCase {
            key_indices: Vec<usize>,
            aggnonce_index: usize,
            msg_index: usize,
            secnonce_index: usize,
            error: SignError,
            comment: String,
        }

        #[derive(serde::Deserialize)]
        struct VerifyFailTestCase {
            #[serde(rename = "sig", deserialize_with = "testhex::deserialize")]
            partial_signature: Vec<u8>,
            key_indices: Vec<usize>,
            nonce_indices: Vec<usize>,
            msg_index: usize,
            signer_index: usize,
            comment: String,
        }

        #[derive(serde::Deserialize)]
        struct SignVerifyVectors {
            #[serde(rename = "sk")]
            seckey: Scalar,

            #[serde(deserialize_with = "testhex::deserialize_vec")]
            pubkeys: Vec<[u8; 33]>,

            #[serde(rename = "secnonces", deserialize_with = "testhex::deserialize_vec")]
            secret_nonces: Vec<[u8; 97]>,

            #[serde(rename = "pnonces", deserialize_with = "testhex::deserialize_vec")]
            public_nonces: Vec<[u8; 66]>,

            #[serde(rename = "aggnonces", deserialize_with = "testhex::deserialize_vec")]
            aggregated_nonces: Vec<[u8; 66]>,

            #[serde(rename = "msgs", deserialize_with = "testhex::deserialize_vec")]
            messages: Vec<Vec<u8>>,

            valid_test_cases: Vec<ValidSignVerifyTestCase>,
            sign_error_test_cases: Vec<SignErrorTestCase>,
            verify_fail_test_cases: Vec<VerifyFailTestCase>,
        }

        let vectors: SignVerifyVectors = serde_json::from_slice(SIGN_VERIFY_VECTORS)
            .expect("error parsing test vectors from sign_verify.json");

        let secnonce = SecNonce::try_from(vectors.secret_nonces[0].as_ref())
            .expect("error parsing secret nonce");

        for (test_index, test_case) in vectors.valid_test_cases.into_iter().enumerate() {
            let pubkeys: Vec<Point> = test_case
                .key_indices
                .into_iter()
                .map(|i| {
                    Point::try_from(&vectors.pubkeys[i]).expect(&format!(
                        "invalid pubkey used in valid test: {}",
                        base16ct::lower::encode_string(&vectors.pubkeys[i])
                    ))
                })
                .collect();

            let signer_pubkey = pubkeys[test_case.signer_index];
            assert_eq!(signer_pubkey, vectors.seckey.base_point_mul());

            let aggnonce_bytes = &vectors.aggregated_nonces[test_case.aggnonce_index];
            let aggregated_nonce = AggNonce::from_bytes(aggnonce_bytes).expect(&format!(
                "invalid aggregated nonce used in valid test case: {}",
                base16ct::lower::encode_string(aggnonce_bytes)
            ));

            let key_agg_ctx =
                KeyAggContext::new(pubkeys).expect("error constructing key aggregation context");

            let message = &vectors.messages[test_case.msg_index];

            let partial_signature: PartialSignature = sign_partial(
                &key_agg_ctx,
                vectors.seckey,
                secnonce.clone(),
                &aggregated_nonce,
                message,
            )
            .expect("error during partial signing");

            assert_eq!(
                partial_signature, test_case.expected,
                "partial signature does not match expected for test case {}",
                test_index,
            );

            let adaptor_secret = MaybeScalar::Valid(vectors.seckey);
            let adaptor_point = adaptor_secret * G;
            let partial_adaptor_signature: PartialSignature = sign_partial_adaptor(
                &key_agg_ctx,
                vectors.seckey,
                secnonce.clone(),
                &aggregated_nonce,
                adaptor_point,
                message,
            )
            .expect("error during partial adaptor signing");

            let public_nonces: Vec<PubNonce> = test_case
                .nonce_indices
                .into_iter()
                .map(|i| {
                    PubNonce::from_bytes(&vectors.public_nonces[i]).expect(&format!(
                        "invalid pubnonce in valid test: {}",
                        base16ct::lower::encode_string(&vectors.public_nonces[i])
                    ))
                })
                .collect();

            // Ensure the aggregated nonce in the test vector is correct
            assert_eq!(&AggNonce::sum(&public_nonces), &aggregated_nonce);

            verify_partial(
                &key_agg_ctx,
                partial_signature,
                &aggregated_nonce,
                signer_pubkey,
                &public_nonces[test_case.signer_index],
                message,
            )
            .expect("failed to verify valid partial signature");

            verify_partial_adaptor(
                &key_agg_ctx,
                partial_adaptor_signature,
                &aggregated_nonce,
                adaptor_point,
                signer_pubkey,
                &public_nonces[test_case.signer_index],
                message,
            )
            .expect("failed to verify valid partial signature");
        }

        // invalid input test case 0: signer's pubkey is not in the key_agg_ctx
        {
            let test_case = vectors.sign_error_test_cases[0].clone();

            let pubkeys: Vec<Point> = test_case
                .key_indices
                .into_iter()
                .map(|i| Point::try_from(&vectors.pubkeys[i]).unwrap())
                .collect();

            let aggnonce_bytes = &vectors.aggregated_nonces[test_case.aggnonce_index];
            let aggregated_nonce = AggNonce::from_bytes(aggnonce_bytes).unwrap();

            let key_agg_ctx =
                KeyAggContext::new(pubkeys).expect("error constructing key aggregation context");

            let message = &vectors.messages[test_case.msg_index];

            assert_eq!(
                sign_partial::<PartialSignature>(
                    &key_agg_ctx,
                    vectors.seckey,
                    secnonce.clone(),
                    &aggregated_nonce,
                    message,
                ),
                Err(SigningError::UnknownKey),
                "partial signing should fail for pubkey not in key_agg_ctx",
            );
        }

        // invalid input test case 1: invalid pubkey
        {
            let test_case = &vectors.sign_error_test_cases[1];
            for (signer_index, &key_index) in test_case.key_indices.iter().enumerate() {
                let result = Point::try_from(&vectors.pubkeys[key_index]);
                if signer_index == test_case.error.signer.unwrap() {
                    assert_eq!(
                        result,
                        Err(secp::errors::InvalidPointBytes),
                        "expected invalid signer pubkey"
                    );
                } else {
                    result.expect("expected valid signer pubkey");
                }
            }
        }

        // invalid input test case 2, 3, and 4: invalid aggnonce
        {
            for test_case in vectors.sign_error_test_cases[2..5].into_iter() {
                let result =
                    AggNonce::from_bytes(&vectors.aggregated_nonces[test_case.aggnonce_index]);

                assert_eq!(
                    result,
                    Err(DecodeError::from(secp::errors::InvalidPointBytes)),
                    "{} - invalid AggNonce should fail to decode",
                    &test_case.comment
                );
            }
        }

        // invalid input test case 5: invalid secnonce
        {
            let test_case = &vectors.sign_error_test_cases[5];
            let result = SecNonce::from_bytes(&vectors.secret_nonces[test_case.secnonce_index]);
            assert_eq!(
                result,
                Err(DecodeError::from(secp::errors::InvalidScalarBytes)),
                "invalid SecNonce should fail to decode"
            );
        }

        // Verification failure test cases 0 and 1: fake signatures
        {
            for test_case in vectors.verify_fail_test_cases[..2].into_iter() {
                let pubkeys: Vec<Point> = test_case
                    .key_indices
                    .iter()
                    .map(|&i| Point::try_from(&vectors.pubkeys[i]).unwrap())
                    .collect();

                let signer_pubkey = pubkeys[test_case.signer_index];

                let key_agg_ctx = KeyAggContext::new(pubkeys)
                    .expect("error constructing key aggregation context");

                let public_nonces: Vec<PubNonce> = test_case
                    .nonce_indices
                    .iter()
                    .map(|&i| PubNonce::from_bytes(&vectors.public_nonces[i]).unwrap())
                    .collect();

                let aggregated_nonce = AggNonce::sum(&public_nonces);

                let message = &vectors.messages[test_case.msg_index];

                let partial_signature =
                    MaybeScalar::try_from(test_case.partial_signature.as_slice())
                        .expect("unexpected invalid partial signature");

                assert_eq!(
                    verify_partial(
                        &key_agg_ctx,
                        partial_signature,
                        &aggregated_nonce,
                        signer_pubkey,
                        &public_nonces[test_case.signer_index],
                        message,
                    ),
                    Err(VerifyError::BadSignature),
                    "{} - unexpected success while verifying invalid partial signature",
                    test_case.comment,
                );
            }
        }

        // Verification failure test case 2: invalid signature
        {
            let test_case = &vectors.verify_fail_test_cases[2];
            let result = PartialSignature::try_from(test_case.partial_signature.as_slice());
            assert_eq!(
                result,
                Err(secp::errors::InvalidScalarBytes),
                "unexpected valid partial signature"
            );
        }
    }

    #[test]
    fn test_sign_with_tweaks() {
        const TWEAK_VECTORS: &[u8] = include_bytes!("test_vectors/tweak_vectors.json");

        #[derive(serde::Deserialize)]
        struct ValidTweakTestCase {
            key_indices: Vec<usize>,
            nonce_indices: Vec<usize>,
            tweak_indices: Vec<usize>,
            is_xonly: Vec<bool>,
            signer_index: usize,
            #[serde(rename = "expected")]
            partial_signature: MaybeScalar,
        }

        #[derive(serde::Deserialize)]
        struct TweakVectors {
            #[serde(rename = "sk")]
            seckey: Scalar,
            pubkeys: Vec<Point>,

            #[serde(rename = "secnonce")]
            secret_nonces: SecNonce,

            #[serde(rename = "pnonces")]
            public_nonces: Vec<PubNonce>,

            #[serde(rename = "aggnonce")]
            aggregated_nonce: AggNonce,

            #[serde(deserialize_with = "testhex::deserialize_vec")]
            tweaks: Vec<Vec<u8>>,

            #[serde(rename = "msg", deserialize_with = "testhex::deserialize")]
            message: Vec<u8>,

            valid_test_cases: Vec<ValidTweakTestCase>,
        }

        let vectors: TweakVectors =
            serde_json::from_slice(TWEAK_VECTORS).expect("failed to parse test_vectors/tweak.json");

        for test_case in vectors.valid_test_cases {
            let pubkeys: Vec<Point> = test_case
                .key_indices
                .into_iter()
                .map(|i| vectors.pubkeys[i])
                .collect();

            let signer_pubkey = pubkeys[test_case.signer_index];

            let mut key_agg_ctx =
                KeyAggContext::new(pubkeys).expect("error creating key aggregation context");

            key_agg_ctx = test_case
                .tweak_indices
                .into_iter()
                .map(|i| {
                    Scalar::try_from(vectors.tweaks[i].as_slice())
                        .expect("failed to parse valid tweak value")
                })
                .zip(test_case.is_xonly)
                .fold(key_agg_ctx, |ctx, (tweak, is_xonly)| {
                    ctx.with_tweak(tweak, is_xonly)
                        .expect(&format!("failed to tweak key agg context with {:x}", tweak))
                });

            let partial_signature: PartialSignature = sign_partial(
                &key_agg_ctx,
                vectors.seckey,
                vectors.secret_nonces.clone(),
                &vectors.aggregated_nonce,
                &vectors.message,
            )
            .expect("error during partial signing");

            assert_eq!(
                partial_signature, test_case.partial_signature,
                "incorrect tweaked partial signature",
            );

            let public_nonces: Vec<&PubNonce> = test_case
                .nonce_indices
                .into_iter()
                .map(|i| &vectors.public_nonces[i])
                .collect();

            verify_partial(
                &key_agg_ctx,
                partial_signature,
                &vectors.aggregated_nonce,
                signer_pubkey,
                public_nonces[test_case.signer_index],
                &vectors.message,
            )
            .expect("failed to verify valid partial signature");
        }
    }
}
