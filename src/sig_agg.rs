use secp::{MaybePoint, MaybeScalar, Point, G};

use crate::errors::VerifyError;
use crate::{
    compute_challenge_hash_tweak, AdaptorSignature, AggNonce, KeyAggContext, LiftedSignature,
    PartialSignature,
};

/// Aggregate a collection of partial adaptor signatures together into a final
/// adaptor signature on a given `message`, under the aggregated public key in
/// `key_agg_ctx`.
///
/// The resulting signature will not be valid unless adapted with the discrete log
/// of the `adaptor_point`.
///
/// Returns an error if the resulting signature would not be valid.
pub fn aggregate_partial_adaptor_signatures<S: Into<PartialSignature>>(
    key_agg_ctx: &KeyAggContext,
    aggregated_nonce: &AggNonce,
    adaptor_point: impl Into<MaybePoint>,
    partial_signatures: impl IntoIterator<Item = S>,
    message: impl AsRef<[u8]>,
) -> Result<AdaptorSignature, VerifyError> {
    let adaptor_point: MaybePoint = adaptor_point.into();
    let aggregated_pubkey = key_agg_ctx.pubkey;

    let b: MaybeScalar = aggregated_nonce.nonce_coefficient(aggregated_pubkey, &message);
    let final_nonce: Point = aggregated_nonce.final_nonce(b);
    let adapted_nonce = final_nonce + adaptor_point;
    let nonce_x_bytes = adapted_nonce.serialize_xonly();
    let e: MaybeScalar = compute_challenge_hash_tweak(&nonce_x_bytes, &aggregated_pubkey, &message);

    let aggregated_signature = partial_signatures
        .into_iter()
        .map(|sig| sig.into())
        .sum::<PartialSignature>()
        + (e * key_agg_ctx.tweak_acc).negate_if(aggregated_pubkey.parity());

    let effective_nonce = if adapted_nonce.has_even_y() {
        final_nonce
    } else {
        -final_nonce
    };

    // Ensure the signature will verify as valid.
    if aggregated_signature * G != effective_nonce + e * aggregated_pubkey.to_even_y() {
        return Err(VerifyError::BadSignature);
    }

    let adaptor_sig = AdaptorSignature {
        R: MaybePoint::Valid(final_nonce),
        s: aggregated_signature,
    };
    Ok(adaptor_sig)
}

/// Aggregate a collection of partial signatures together into a final
/// signature on a given `message`, valid under the aggregated public
/// key in `key_agg_ctx`.
///
/// Returns an error if the resulting signature would not be valid.
pub fn aggregate_partial_signatures<S, T>(
    key_agg_ctx: &KeyAggContext,
    aggregated_nonce: &AggNonce,
    partial_signatures: impl IntoIterator<Item = S>,
    message: impl AsRef<[u8]>,
) -> Result<T, VerifyError>
where
    S: Into<PartialSignature>,
    T: From<LiftedSignature>,
{
    let sig = aggregate_partial_adaptor_signatures(
        key_agg_ctx,
        aggregated_nonce,
        MaybePoint::Infinity,
        partial_signatures,
        message,
    )?
    .adapt(MaybeScalar::Zero)
    .map(T::from)
    .expect("aggregating with empty adaptor should never result in an adaptor failure");

    Ok(sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhex;
    use crate::{verify_single, CompactSignature, PubNonce, SecNonce};

    use secp::{Point, Scalar};

    #[test]
    fn test_aggregate_partial_signatures() {
        const SIG_AGG_VECTORS: &[u8] = include_bytes!("test_vectors/sig_agg_vectors.json");

        #[derive(serde::Deserialize)]
        struct ValidSigAggTestCase {
            #[serde(rename = "aggnonce")]
            aggregated_nonce: AggNonce,
            nonce_indices: Vec<usize>,
            key_indices: Vec<usize>,
            tweak_indices: Vec<usize>,
            is_xonly: Vec<bool>,
            psig_indices: Vec<usize>,

            #[serde(rename = "expected")]
            aggregated_signature: CompactSignature,
        }

        #[derive(serde::Deserialize)]
        struct SigAggVectors {
            pubkeys: Vec<Point>,

            #[serde(rename = "pnonces")]
            public_nonces: Vec<PubNonce>,

            tweaks: Vec<Scalar>,

            #[serde(rename = "psigs", deserialize_with = "testhex::deserialize_vec")]
            partial_signatures: Vec<Vec<u8>>,

            #[serde(rename = "msg", deserialize_with = "testhex::deserialize")]
            message: Vec<u8>,

            valid_test_cases: Vec<ValidSigAggTestCase>,
        }

        let vectors: SigAggVectors = serde_json::from_slice(SIG_AGG_VECTORS)
            .expect("failed to parse test vectors from sig_agg_vectors.json");

        for test_case in vectors.valid_test_cases {
            let pubkeys = test_case
                .key_indices
                .into_iter()
                .map(|i| vectors.pubkeys[i]);

            let public_nonces = test_case
                .nonce_indices
                .into_iter()
                .map(|i| &vectors.public_nonces[i]);

            let aggregated_nonce = AggNonce::sum(public_nonces);

            assert_eq!(
                &aggregated_nonce, &test_case.aggregated_nonce,
                "aggregated nonce does not match test vector"
            );

            let mut key_agg_ctx =
                KeyAggContext::new(pubkeys).expect("error constructing key aggregation context");

            key_agg_ctx = test_case
                .tweak_indices
                .into_iter()
                .map(|i| vectors.tweaks[i])
                .zip(test_case.is_xonly)
                .fold(key_agg_ctx, |ctx, (tweak, is_xonly)| {
                    ctx.with_tweak(tweak, is_xonly).unwrap_or_else(|_| {
                        panic!("failed to tweak key agg context with {:x}", tweak)
                    })
                });

            let partial_signatures: Vec<Scalar> = test_case
                .psig_indices
                .into_iter()
                .map(|i| {
                    Scalar::try_from(vectors.partial_signatures[i].as_slice())
                        .expect("failed to parse partial signature")
                })
                .collect();

            let aggregated_signature: CompactSignature = aggregate_partial_signatures(
                &key_agg_ctx,
                &aggregated_nonce,
                partial_signatures,
                &vectors.message,
            )
            .expect("failed to aggregate partial signatures");

            assert_eq!(
                &aggregated_signature, &test_case.aggregated_signature,
                "incorrect aggregated signature"
            );

            verify_single(key_agg_ctx.pubkey, aggregated_signature, &vectors.message)
                .unwrap_or_else(|_| {
                    panic!(
                        "aggregated signature {} should be valid BIP340 signature",
                        aggregated_signature
                    )
                });
        }
    }

    #[test]
    fn test_adaptor_signature_aggregation() {
        const ITERATIONS: usize = 10;

        for _ in 0..ITERATIONS {
            let seckeys = [
                Scalar::random(&mut rand::thread_rng()),
                Scalar::random(&mut rand::thread_rng()),
                Scalar::random(&mut rand::thread_rng()),
            ];

            let pubkeys = [
                seckeys[0].base_point_mul(),
                seckeys[1].base_point_mul(),
                seckeys[2].base_point_mul(),
            ];

            let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();

            let message = b"danger, will robinson!";

            let secnonces = [
                SecNonce::random(&mut rand::thread_rng()),
                SecNonce::random(&mut rand::thread_rng()),
                SecNonce::random(&mut rand::thread_rng()),
            ];

            let pubnonces = [
                secnonces[0].public_nonce(),
                secnonces[1].public_nonce(),
                secnonces[2].public_nonce(),
            ];

            let aggnonce = AggNonce::sum(&pubnonces);

            let adaptor_secret = Scalar::random(&mut rand::thread_rng());
            let adaptor_point = adaptor_secret.base_point_mul();

            let partial_signatures: Vec<PartialSignature> = seckeys
                .into_iter()
                .zip(secnonces)
                .map(|(seckey, secnonce)| {
                    crate::adaptor::sign_partial(
                        &key_agg_ctx,
                        seckey,
                        secnonce,
                        &aggnonce,
                        adaptor_point,
                        message,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
                .expect("failed to create partial adaptor signatures");

            let adaptor_signature: AdaptorSignature = crate::adaptor::aggregate_partial_signatures(
                &key_agg_ctx,
                &aggnonce,
                adaptor_point,
                partial_signatures.iter().copied(),
                message,
            )
            .expect("failed to aggregate partial adaptor signatures");

            crate::adaptor::verify_single(
                key_agg_ctx.aggregated_pubkey::<Point>(),
                &adaptor_signature,
                message,
                adaptor_point,
            )
            .expect("invalid aggregated adaptor signature");

            let valid_signature = adaptor_signature.adapt(adaptor_secret).unwrap();
            verify_single(
                key_agg_ctx.aggregated_pubkey::<Point>(),
                valid_signature,
                message,
            )
            .expect("invalid decrypted adaptor signature");

            let revealed: MaybeScalar = adaptor_signature
                .reveal_secret(&valid_signature)
                .expect("should compute adaptor secret from decrypted signature");

            assert_eq!(revealed, MaybeScalar::Valid(adaptor_secret));
        }
    }
}
