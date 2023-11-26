This module exports [adaptor signature](https://bitcoinops.org/en/topics/adaptor-signatures/) implementations of BIP340 signing and MuSig signing.

Adaptor signatures allow signers to create Schnorr signatures which can be verified, but do not pass BIP340 verification logic unless a specific secret scalar is added to the signature.

[Further reading](https://conduition.io/scriptless/adaptorsigs/).

## MuSig Example

Here we demonstrate a group of MuSig2 signers adaptor-signing the same message. The final signature which the group constructs is an [`AdaptorSignature`][crate::AdaptorSignature], which they cannot use until it has been decrypted (AKA 'adapted') by the correct adaptor secret (a scalar).

```rust
use secp::{MaybeScalar, Point, Scalar};
use musig2::{AdaptorSignature, KeyAggContext, PartialSignature, PubNonce};

let seckeys = [
    Scalar::from_slice(&[0x11; 32]).unwrap(),
    Scalar::from_slice(&[0x22; 32]).unwrap(),
    Scalar::from_slice(&[0x33; 32]).unwrap(),
];

let pubkeys = [
    seckeys[0].base_point_mul(),
    seckeys[1].base_point_mul(),
    seckeys[2].base_point_mul(),
];

let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();
let aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey();

let message = "danger, will robinson!";

let adaptor_secret = Scalar::random(&mut rand::thread_rng());
let adaptor_point = adaptor_secret.base_point_mul();

// Using the functional API.
{
    use musig2::{AggNonce, SecNonce};

    let secnonces = [
        SecNonce::build([0x11; 32]).build(),
        SecNonce::build([0x22; 32]).build(),
        SecNonce::build([0x33; 32]).build(),
    ];

    let pubnonces = [
        secnonces[0].public_nonce(),
        secnonces[1].public_nonce(),
        secnonces[2].public_nonce(),
    ];

    let aggnonce = AggNonce::sum(&pubnonces);

    let partial_signatures: Vec<PartialSignature> = seckeys
        .into_iter()
        .zip(secnonces)
        .map(|(seckey, secnonce)| {
            musig2::adaptor::sign_partial(
                &key_agg_ctx,
                seckey,
                secnonce,
                &aggnonce,
                adaptor_point,
                &message,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .expect("failed to create partial adaptor signatures");

    let adaptor_signature: AdaptorSignature = musig2::adaptor::aggregate_partial_signatures(
        &key_agg_ctx,
        &aggnonce,
        adaptor_point,
        partial_signatures.iter().copied(),
        &message,
    )
    .expect("failed to aggregate partial adaptor signatures");

    // Verify the adaptor signature is valid for the given adaptor point and pubkey.
    musig2::adaptor::verify_single(
        aggregated_pubkey,
        &adaptor_signature,
        &message,
        adaptor_point,
    )
    .expect("invalid aggregated adaptor signature");

    // Decrypt the signature with the adaptor secret.
    let valid_signature = adaptor_signature.adapt(adaptor_secret).unwrap();

    musig2::verify_single(
        aggregated_pubkey,
        valid_signature,
        &message,
    )
    .expect("invalid decrypted adaptor signature");

    // The decrypted signature and the adaptor signature allow an
    // observer to deduce the adaptor secret.
    let revealed: MaybeScalar = adaptor_signature
        .reveal_secret(&valid_signature)
        .expect("should compute adaptor secret from decrypted signature");

    assert_eq!(revealed, MaybeScalar::Valid(adaptor_secret));
}

// Using the state-machine API
{
    use musig2::{FirstRound, SecNonceSpices, SecondRound};

    let spiced = |i| SecNonceSpices::new()
        .with_seckey(seckeys[i])
        .with_message(&message);

    let mut first_rounds = vec![
        FirstRound::new(key_agg_ctx.clone(), [0x11; 32], 0, spiced(0)).unwrap(),
        FirstRound::new(key_agg_ctx.clone(), [0x22; 32], 1, spiced(1)).unwrap(),
        FirstRound::new(key_agg_ctx.clone(), [0x33; 32], 2, spiced(2)).unwrap(),
    ];

    let public_nonces = [
        first_rounds[0].our_public_nonce(),
        first_rounds[1].our_public_nonce(),
        first_rounds[2].our_public_nonce(),
    ];

    for round in first_rounds.iter_mut() {
        round.receive_nonce(0, public_nonces[0].clone()).unwrap();
        round.receive_nonce(1, public_nonces[1].clone()).unwrap();
        round.receive_nonce(2, public_nonces[2].clone()).unwrap();
    }

    // The `finalize_adaptor` method must be used instead of `finalize`, on
    // both first and second rounds.
    let mut second_rounds: Vec<SecondRound<&str>> = first_rounds
        .into_iter()
        .enumerate()
        .map(|(i, round)| round.finalize_adaptor(seckeys[i], adaptor_point, message).unwrap())
        .collect();

    let partial_sigs: [PartialSignature; 3] = [
        second_rounds[0].our_signature(),
        second_rounds[1].our_signature(),
        second_rounds[2].our_signature(),
    ];

    for round in second_rounds.iter_mut() {
        round.receive_signature(0, partial_sigs[0]).unwrap();
        round.receive_signature(1, partial_sigs[1]).unwrap();
        round.receive_signature(2, partial_sigs[2]).unwrap();
    }

    for second_round in second_rounds.into_iter() {
        let adaptor_signature = second_round.finalize_adaptor::<AdaptorSignature>().unwrap();

        // Verify the adaptor signature is valid for the given adaptor point and pubkey.
        musig2::adaptor::verify_single(
            aggregated_pubkey,
            &adaptor_signature,
            &message,
            adaptor_point,
        )
        .expect("invalid aggregated adaptor signature");

        // Decrypt the signature with the adaptor secret.
        let valid_signature = adaptor_signature.adapt(adaptor_secret).unwrap();
        musig2::verify_single(
            aggregated_pubkey,
            valid_signature,
            &message,
        )
        .expect("invalid decrypted adaptor signature");

        // The decrypted signature and the adaptor signature allow an
        // observer to deduce the adaptor secret.
        let revealed: MaybeScalar = adaptor_signature
            .reveal_secret(&valid_signature)
            .expect("should compute adaptor secret from decrypted signature");

        assert_eq!(revealed, MaybeScalar::Valid(adaptor_secret));
    }
}
```

## Single Signer Example

We also export single-signer adaptor signing logic.

```rust
use secp::{MaybeScalar, Scalar};

let seckey = Scalar::random(&mut rand::rngs::OsRng);
let message = "hello world!";

// Create an adaptor signature, encrypted under a specific adaptor point.
let adaptor_secret = Scalar::random(&mut rand::rngs::OsRng);
let adaptor_point = adaptor_secret.base_point_mul();
let aux_rand = [0xAA; 32]; // Should use an actual RNG.
let adaptor_signature =
    musig2::adaptor::sign_solo(seckey, message, aux_rand, adaptor_point);

// Verify the adaptor signature is valid for the given adaptor point and pubkey.
let pubkey = seckey.base_point_mul();
musig2::adaptor::verify_single(pubkey, &adaptor_signature, message, adaptor_point)
    .expect("valid adaptor signature should verify");

// Decrypt the signature with the adaptor secret.
let valid_sig: musig2::LiftedSignature = adaptor_signature
    .adapt(adaptor_secret)
    .expect("invalid adaptor secret");

musig2::verify_single(pubkey, valid_sig, message)
    .expect("decrypted adaptor signature is valid");

// The decrypted signature and the adaptor signature allow an
// observer to deduce the adaptor secret.
let revealed: MaybeScalar = adaptor_signature.reveal_secret(&valid_sig)
    .expect("decrypted sig should reveal adaptor secret");
assert_eq!(revealed, MaybeScalar::Valid(adaptor_secret));
```

## Encrypting Signatures

The above examples create signatures by committing to an adaptor point as part of the signing process. This is the way most adaptor signatures are created.

However, you can also encrypt existing signatures (including existing adaptor signatures) by tweaking them with an adaptor secret. This requires knowing the adaptor secret though, so you can't do this if you only know the public adaptor point.

```rust
let signature = musig2::LiftedSignature::from_hex(
    "e565f19755422162cf7dc69ed8a4f4a27d81363d024a3de355644003da33ed2f\
     0cdd95945c6d28841192867842c104391b9cc31f25706ee302a96204a1d43eb7"
)
.unwrap();

let adaptor_secret_1 = secp::Scalar::from_slice(&[0x55; 32]).unwrap();
let mut adaptor_signature: musig2::AdaptorSignature = signature.encrypt(adaptor_secret_1);

// We can re-encrypt the same adaptor signature twice, so that it is locked behind
// two different points. Both secrets must be learned to compute the valid signature.
let adaptor_secret_2 = secp::Scalar::from_slice(&[0x66; 32]).unwrap();
adaptor_signature = adaptor_signature.encrypt(adaptor_secret_2);

let decrypted: [u8; 64] = adaptor_signature
    .adapt(adaptor_secret_1 + adaptor_secret_2)
    .expect("valid decrypted adaptor signature");
assert_eq!(decrypted, signature.serialize());
```
