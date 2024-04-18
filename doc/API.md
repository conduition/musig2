# Features

| Feature | Description | Dependencies | Enabled by Default |
|---------|-------------|--------------|:------------------:|
| `secp256k1` | Use [`libsecp256k1`](https://github.com/bitcoin-core/secp256k1) bindings for elliptic curve math. Include trait implementations for converting to and from types in [the `secp256k1` crate][secp256k1]. This feature supercedes the `k256` feature if that one is enabled. | [`secp256k1`] | ✅ |
| `k256` | Use [the `k256` crate][k256] for elliptic curve math. This allows a pure-rust implementation of MuSig2. Include trait implementations for types from [`k256`]. If the `secp256k1` feature is enabled, then [`k256`] will still be brought in and trait implementations will be included, but the actual curve math will be done by `libsecp256k1`. | [`k256`] | ❌ |
| `serde` | Implement serialization and deserialization for types in this crate. | [`serde`](https://docs.rs/serde) | ❌ |
| `rand` | Enable support for accepting a CSPRNG as input, via [the `rand` crate][rand] | [`rand`] | ❌ |

# Key Aggregation

Once all signers know each other's public keys (out of scope for this crate), they can construct a [`KeyAggContext`] which aggregates their public keys together, along with optional _tweak values_ (see [`KeyAggContext::with_tweak`] to learn more).


<details>
    <summary><h2>Example</h2></summary>

```rust
# #[cfg(feature = "secp256k1")]
use secp256k1::{SecretKey, PublicKey};
#
# // k256::SecretKey and k256::PublicKey don't have string parsing traits,
# // so I'll just use our own representations for this example.
# #[cfg(not(feature = "secp256k1"))]
# use musig2::secp::{Point as PublicKey, Scalar as SecretKey};
use musig2::KeyAggContext;

let pubkeys = [
    "026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f4"
        .parse::<PublicKey>()
        .unwrap(),
    "02f3b071c064f115ca762ed88c3efd1927ea657c7949698b77255ea25751331f0b"
        .parse::<PublicKey>()
        .unwrap(),
    "03204ea8bc3425b2cbc9cb20617f67dc6b202467591d0b26d059e370b71ee392eb"
        .parse::<PublicKey>()
        .unwrap(),
];

let signer_index = 2;
let seckey: SecretKey = "10e7721a3aa6de7a98cecdbd7c706c836a907ca46a43235a7b498b12498f98f0"
    .parse()
    .unwrap();

let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();


// This is the key which the group has control over.
let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
assert_eq!(
    aggregated_pubkey,
    "02e272de44ea720667aba55341a1a761c0fc8fbe294aa31dbaf1cff80f1c2fd940"
        .parse()
        .unwrap()
);
```
<br>
</details>

A handy property of the MuSig2 protocol is that signers do not need proof that the other signers in the group know their own secret keys. They can simply exchange public keys and continue once all signers agree on an aggregated pubkey.

Once you have a [`KeyAggContext`], you may choose between two sets of APIs for running the MuSig2 protocol, covering both **Functional** and **State-Machine** approaches.

## State-Machine API

<sub>A state machine is a stateful object which manipulates its internal state based on external input, fed to it by the caller (you).</sub>

This crate's _State-Machine_-based signing API is safer, but may not be as flexible as the _Functional_ API. It is constructed around two stateful types, [`FirstRound`] and [`SecondRound`], which handle storing partial nonces and partial signatures.

[`FirstRound`] is analagous to the first signing round of MuSig2, wherein signers generate and send nonces to one-another, or to a [designated aggregator](#single-aggregator).

[`SecondRound`] is analagous to the second signing round where signers share and verify their partial signatures. Once the [`SecondRound`] complete, it can be finalized into a valid aggregated Schnorr signature.


<details>
    <summary><h2>Example</h2></summary>

```rust
# #[cfg(feature = "secp256k1")]
# use secp256k1::{SecretKey, PublicKey};
# #[cfg(not(feature = "secp256k1"))]
# use musig2::secp::{Point as PublicKey, Scalar as SecretKey};
# use musig2::KeyAggContext;
#
# /// Same pubkeys as in previous example
# let key_agg_ctx =
#     "0000000003026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f402f3\
#      b071c064f115ca762ed88c3efd1927ea657c7949698b77255ea25751331f0b03204ea8bc3425b2cb\
#      c9cb20617f67dc6b202467591d0b26d059e370b71ee392eb"
#       .parse::<KeyAggContext>()
#       .unwrap();
#
# let signer_index = 2;
# let seckey: SecretKey = "10e7721a3aa6de7a98cecdbd7c706c836a907ca46a43235a7b498b12498f98f0"
#     .parse()
#     .unwrap();
#
# let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
#
use musig2::{
    CompactSignature, FirstRound, PartialSignature, PubNonce, SecNonceSpices, SecondRound,
};

// The group wants to sign something!
let message = "hello interwebz!";

// Normally this should be sampled securely from a CSPRNG.
// let mut nonce_seed = [0u8; 32]
// rand::rngs::OsRng.fill_bytes(&mut nonce_seed);
let nonce_seed = [0xACu8; 32];

let mut first_round = FirstRound::new(
    key_agg_ctx,
    nonce_seed,
    signer_index,
    SecNonceSpices::new()
        .with_seckey(seckey)
        .with_message(&message),
)
.unwrap();

// We would share our public nonce with our peers.
assert_eq!(
    first_round.our_public_nonce(),
    "02d1e90616ea78a612dddfe97de7b5e7e1ceef6e64b7bc23b922eae30fa2475cca\
     02e676a3af322965d53cc128597897ef4f84a8d8080b456e27836db70e5343a2bb"
        .parse()
        .unwrap(),
    "Our public nonce should match"
);

// We can see a list of which signers (by index) have yet to provide us
// with a nonce.
assert_eq!(first_round.holdouts(), &[0, 1]);

// We receive the public nonces from our peers one at a time.
first_round.receive_nonce(
    0,
    "02af252206259fc1bf588b1f847e15ac78fa840bfb06014cdbddcfcc0e5876f9c9\
     0380ab2fc9abe84ef42a8d87062d5094b9ab03f4150003a5449846744a49394e45"
        .parse::<PubNonce>()
        .unwrap()
)
.unwrap();

// `is_complete` provides a quick check to see whether we have nonces from
// every signer yet.
assert!(!first_round.is_complete());

// ...once we receive all their nonces...
first_round.receive_nonce(
    1,
    "020ab52d58f00887d5082c41dc85fd0bd3aaa108c2c980e0337145ac7003c28812\
     03956ec5bd53023261e982ac0c6f5f2e4b6c1e14e9b1992fb62c9bdfcf5b27dc8d"
        .parse::<PubNonce>()
        .unwrap()
)
.unwrap();

// ... the round will be complete.
assert!(first_round.is_complete());

let mut second_round: SecondRound<&str> = first_round.finalize(seckey, message).unwrap();

// We could now send our partial signature to our peers.
// Be careful not to send your signature first if your peers
// might run away without surrendering their signatures in exchange!
let our_partial_signature: PartialSignature = second_round.our_signature();
assert_eq!(
    our_partial_signature,
    "efd62850b959a76a462f1e42eb3cecc77a5a0982742fff2901456b7d1453a817"
        .parse()
        .unwrap()
);

second_round.receive_signature(
    0,
    "5a476e0126583e9e0ceebb01a34bdd342c72eab92efbe8a1c7f07e793fd88f96"
        .parse::<PartialSignature>()
        .unwrap()
)
.expect("signer 0's partial signature should be valid");

// Same methods as on FirstRound are available for SecondRound.
assert!(!second_round.is_complete());
assert_eq!(second_round.holdouts(), &[1]);

// Receive a partial signature from one of our cosigners. This
// automatically verifies the partial signature and returns an
// error if the signature is invalid.
second_round.receive_signature(
    1,
    "45ac8a698fc9e82408367e28a2d257edf6fc49f14dcc8a98c43e9693e7265e7e"
        .parse::<PartialSignature>()
        .unwrap()
)
.expect("signer 1's partial signature should be valid");

assert!(second_round.is_complete());

// If all signatures were received successfully, finalizing the second round
// should succeed with overwhelming probability.
let final_signature: CompactSignature = second_round.finalize().unwrap();

assert_eq!(
    final_signature.to_string(),
    "38fbd82d1d27bb3401042062acfd4e7f54ce93ddf26a4ae87cf71568c1d4e8bb\
     8fca20bb6f7bce2c5b54576d315b21eae31a614641afd227cda221fd6b1c54ea"
);

musig2::verify_single(
    aggregated_pubkey,
    final_signature,
    message
)
.expect("aggregated signature must be valid");
```
<br>
</details>

## Functional API

The _Functional_ API exposes the MuSig2 protocol through pure functions which accept read-only inputs and produce deterministic outputs. This obviously lacks internal state and it is thus entirely dependent on the caller to securely handle nonce state management. The caller is free to implement nonce state management however they like with this API. [Please read the warning below about nonce-reuse BEFORE attempting to use the Functional API](#nonce-reuse).

Instead of using [`FirstRound`] and [`SecondRound`], the Functional API is exposed through these pure functions:

- [`SecNonce::generate`] - Generate a secret nonce.
- [`AggNonce::sum`] - Aggregate public nonces together.
- [`sign_partial`] - Create a partial signature on a message.
- [`verify_partial`] - Verify a partial signature.
- [`aggregate_partial_signatures`] - Aggregate a collection of partial signatures into a final valid signature.

<details>
    <summary><h2>Example</h2></summary>

```rust
# #[cfg(feature = "secp256k1")]
# use secp256k1::{SecretKey, PublicKey};
# #[cfg(not(feature = "secp256k1"))]
# use musig2::secp::{Point as PublicKey, Scalar as SecretKey};
# use musig2::{KeyAggContext, PartialSignature, PubNonce};
#
# let signer_index = 2;
# let seckey: SecretKey = "10e7721a3aa6de7a98cecdbd7c706c836a907ca46a43235a7b498b12498f98f0"
#    .parse()
#    .unwrap();
#
# /// Same pubkeys as in previous example
# let key_agg_ctx =
#     "0000000003026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f402f3\
#      b071c064f115ca762ed88c3efd1927ea657c7949698b77255ea25751331f0b03204ea8bc3425b2cb\
#      c9cb20617f67dc6b202467591d0b26d059e370b71ee392eb"
#       .parse::<KeyAggContext>()
#       .unwrap();
#
# let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
# let message = "hello interwebz!";
# let nonce_seed = [0xACu8; 32];
use musig2::{AggNonce, SecNonce};

// This is how `FirstRound` derives the nonce internally.
let secnonce = SecNonce::build(nonce_seed)
    .with_seckey(seckey)
    .with_message(&message)
    .with_aggregated_pubkey(aggregated_pubkey)
    .with_extra_input(&(signer_index as u32).to_be_bytes())
    .build();

let our_public_nonce = secnonce.public_nonce();
assert_eq!(
    our_public_nonce,
    "02d1e90616ea78a612dddfe97de7b5e7e1ceef6e64b7bc23b922eae30fa2475cca\
     02e676a3af322965d53cc128597897ef4f84a8d8080b456e27836db70e5343a2bb"
        .parse()
        .unwrap()
);

// ...Exchange nonces with peers...

let public_nonces = [
    "02af252206259fc1bf588b1f847e15ac78fa840bfb06014cdbddcfcc0e5876f9c9\
     0380ab2fc9abe84ef42a8d87062d5094b9ab03f4150003a5449846744a49394e45"
        .parse::<PubNonce>()
        .unwrap(),

    "020ab52d58f00887d5082c41dc85fd0bd3aaa108c2c980e0337145ac7003c28812\
     03956ec5bd53023261e982ac0c6f5f2e4b6c1e14e9b1992fb62c9bdfcf5b27dc8d"
        .parse::<PubNonce>()
        .unwrap(),

    our_public_nonce,
];

// We manually aggregate the nonces together and then construct our partial signature.
let aggregated_nonce: AggNonce = public_nonces.iter().sum();
let our_partial_signature: PartialSignature = musig2::sign_partial(
    &key_agg_ctx,
    seckey,
    secnonce,
    &aggregated_nonce,
    message
)
.expect("error creating partial signature");

let partial_signatures = [
    "5a476e0126583e9e0ceebb01a34bdd342c72eab92efbe8a1c7f07e793fd88f96"
        .parse::<PartialSignature>()
        .unwrap(),
    "45ac8a698fc9e82408367e28a2d257edf6fc49f14dcc8a98c43e9693e7265e7e"
        .parse::<PartialSignature>()
        .unwrap(),
    our_partial_signature,
];

/// Signatures should be verified upon receipt and invalid signatures
/// should be blamed on the signer who sent them.
for (i, partial_signature) in partial_signatures.into_iter().enumerate() {
    if i == signer_index {
        // Don't bother verifying our own signature
        continue;
    }

    let their_pubkey: PublicKey = key_agg_ctx.get_pubkey(i).unwrap();
    let their_pubnonce = &public_nonces[i];

    musig2::verify_partial(
        &key_agg_ctx,
        partial_signature,
        &aggregated_nonce,
        their_pubkey,
        their_pubnonce,
        message
    )
    .expect("received invalid signature from a peer");
}

let final_signature: [u8; 64] = musig2::aggregate_partial_signatures(
    &key_agg_ctx,
    &aggregated_nonce,
    partial_signatures,
    message,
)
.expect("error aggregating signatures");

assert_eq!(
    final_signature,
    [
        0x38, 0xFB, 0xD8, 0x2D, 0x1D, 0x27, 0xBB, 0x34, 0x01, 0x04, 0x20, 0x62, 0xAC, 0xFD,
        0x4E, 0x7F, 0x54, 0xCE, 0x93, 0xDD, 0xF2, 0x6A, 0x4A, 0xE8, 0x7C, 0xF7, 0x15, 0x68,
        0xC1, 0xD4, 0xE8, 0xBB, 0x8F, 0xCA, 0x20, 0xBB, 0x6F, 0x7B, 0xCE, 0x2C, 0x5B, 0x54,
        0x57, 0x6D, 0x31, 0x5B, 0x21, 0xEA, 0xE3, 0x1A, 0x61, 0x46, 0x41, 0xAF, 0xD2, 0x27,
        0xCD, 0xA2, 0x21, 0xFD, 0x6B, 0x1C, 0x54, 0xEA
    ]
);

musig2::verify_single(
    aggregated_pubkey,
    &final_signature,
    message
)
.expect("aggregated signature must be valid");
```
<br>
</details>

## Single Aggregator

As an alternative to a many-to-many topology where each signer must collect nonces and partial signatures from everyone else in the group, the group can instead opt to nominate an _aggregator node_ whose duty is to collect nonces and signatures from all other signers, and then broadcast the aggregated signature once they receive all partial signatures.

This dramatically decreases the number of network round-trips required for large groups of signers, and doesn't require any trust in the aggregator node beyond the possibility that they may refuse to reveal the final signature.

Here's an example of how to use the State-Machine API to interact with an untrusted remote aggregator node.

<details>
    <summary><h2>Example</h2></summary>

```rust
# #[cfg(feature = "secp256k1")]
# use secp256k1::{SecretKey, PublicKey};
# #[cfg(not(feature = "secp256k1"))]
# use musig2::secp::{Point as PublicKey, Scalar as SecretKey};
# use musig2::KeyAggContext;
#
# /// Same pubkeys as in previous example
# let key_agg_ctx =
#     "0000000003026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f402f3\
#      b071c064f115ca762ed88c3efd1927ea657c7949698b77255ea25751331f0b03204ea8bc3425b2cb\
#      c9cb20617f67dc6b202467591d0b26d059e370b71ee392eb"
#       .parse::<KeyAggContext>()
#       .unwrap();
#
# let signer_index = 2;
# let seckey: SecretKey = "10e7721a3aa6de7a98cecdbd7c706c836a907ca46a43235a7b498b12498f98f0"
#     .parse()
#     .unwrap();
#
# let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
#
use musig2::{
    AggNonce, FirstRound, PartialSignature, PubNonce, SecNonceSpices, SecondRound,
};

let message = "hello interwebz!";

// Normally this should be sampled securely from a CSPRNG.
let nonce_seed = [0xACu8; 32];

let first_round = FirstRound::new(
    key_agg_ctx.clone(),
    nonce_seed,
    signer_index,
    SecNonceSpices::new()
        .with_seckey(seckey)
        .with_message(&message),
)
.unwrap();

// We would share our public nonce with the aggregator.
// The aggregator aggregates the group's nonces together
// and sends us the resulting `AggNonce`.
let aggregated_nonce = AggNonce::sum([
    "02af252206259fc1bf588b1f847e15ac78fa840bfb06014cdbddcfcc0e5876f9c9\
     0380ab2fc9abe84ef42a8d87062d5094b9ab03f4150003a5449846744a49394e45"
        .parse::<PubNonce>()
        .unwrap(),

    "020ab52d58f00887d5082c41dc85fd0bd3aaa108c2c980e0337145ac7003c28812\
     03956ec5bd53023261e982ac0c6f5f2e4b6c1e14e9b1992fb62c9bdfcf5b27dc8d"
        .parse::<PubNonce>()
        .unwrap(),

    first_round.our_public_nonce(),
]);

// Once we have the aggregated nonce, we can sign the message,
// and send the partial signature to the aggregator.
let our_partial_signature = first_round
    .sign_for_aggregator(seckey, message, &aggregated_nonce)
    .unwrap();

let partial_signatures = [
    "5a476e0126583e9e0ceebb01a34bdd342c72eab92efbe8a1c7f07e793fd88f96"
        .parse::<PartialSignature>()
        .unwrap(),
    "45ac8a698fc9e82408367e28a2d257edf6fc49f14dcc8a98c43e9693e7265e7e"
        .parse::<PartialSignature>()
        .unwrap(),
    our_partial_signature,
];

// The aggregator aggregates the group's partial signatures,
// either using `SecondRound` or the functional API.
let final_signature: [u8; 64] = musig2::aggregate_partial_signatures(
    &key_agg_ctx,
    &aggregated_nonce,
    partial_signatures,
    message,
)
.unwrap();

musig2::verify_single(
    aggregated_pubkey,
    &final_signature,
    message
)
.expect("aggregated signature must be valid");
```
<br>
</details>

The partial signatures can also be created using the functional API, as long as `SecNonce` is [managed carefully so that it is not accidentally reused.](#nonce-reuse)

## Signatures

Partial signatures are represented as a [`secp::MaybeScalar`], which is just a scalar in the range `[0, n)` (where `n` is the number of points on the curve). This is aliased as [`PartialSignature`] for clarity. `PartialSignature` implements `Serialize` and `Deserialize` if the `serde` feature is enabled.

The final output of a signature aggregation is a tuple of numbers `(R, s)` where `R` is a point and `s` is a scalar. This output type is represented by the [`LiftedSignature`] type. The return value of [`SecondRound::finalize`] or [`aggregate_partial_signatures`] can be converted to any type that implements `From<LiftedSignature>`.

<details>
    <summary><h2>Example</h2></summary>

```rust
# use musig2::{AggNonce, KeyAggContext, PartialSignature};
#
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# /// Same pubkeys as in previous example
# let key_agg_ctx =
#     "0000000003026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f402f3\
#      b071c064f115ca762ed88c3efd1927ea657c7949698b77255ea25751331f0b03204ea8bc3425b2cb\
#      c9cb20617f67dc6b202467591d0b26d059e370b71ee392eb"
#       .parse::<KeyAggContext>()
#       .unwrap();
# let message = "hello interwebz!";
# let partial_signatures = [
#     "5a476e0126583e9e0ceebb01a34bdd342c72eab92efbe8a1c7f07e793fd88f96"
#         .parse::<PartialSignature>()
#         .unwrap(),
#     "45ac8a698fc9e82408367e28a2d257edf6fc49f14dcc8a98c43e9693e7265e7e"
#         .parse::<PartialSignature>()
#         .unwrap(),
#     "efd62850b959a76a462f1e42eb3cecc77a5a0982742fff2901456b7d1453a817"
#         .parse::<PartialSignature>()
#         .unwrap(),
# ];
# let aggregated_nonce = "03f9ce0458831f7f8104f014d940db4048c4e045c369c207ec38530360ce7bfd3e\
#                         023f5d6a34513458188503e7c48c1a6efd75f52e77da57587f372be8f839ecc1f9"
#     .parse::<AggNonce>()
#     .unwrap();
#
use musig2::{aggregate_partial_signatures, CompactSignature, LiftedSignature};

// Represents a compacted signature with an X-only nonce point.
let final_signature: CompactSignature = aggregate_partial_signatures(
    // ...
#     &key_agg_ctx,
#     &aggregated_nonce,
#     partial_signatures,
#     message,
)?;

// Represents a fully parsed `(R, s)` signature pair.
let final_signature: LiftedSignature = aggregate_partial_signatures(
    // ...
#     &key_agg_ctx,
#     &aggregated_nonce,
#     partial_signatures,
#     message,
)?;

// Or you can convert it directly to a byte array.
let final_signature: [u8; 64] = aggregate_partial_signatures(
    // ...
#     &key_agg_ctx,
#     &aggregated_nonce,
#     partial_signatures,
#     message,
)?;

# #[cfg(feature = "secp256k1")]
let final_signature: secp256k1::schnorr::Signature = aggregate_partial_signatures(
    // ...
#     &key_agg_ctx,
#     &aggregated_nonce,
#     partial_signatures,
#     message,
)?;

// allows us to use `R` as a variable name in this block
#[allow(non_snake_case)]
{
    // You can also unzip signatures into their individual components `(R, s)`.
    let signature: LiftedSignature = aggregate_partial_signatures(
        // ...
    #     &key_agg_ctx,
    #     &aggregated_nonce,
    #     partial_signatures,
    #     message,
    )?;

    // `R` can be any type that impls `From<secp::Point>`.
    // `s` can be any type that impls `From<secp::MaybeScalar>`.
    let (R, s): (secp::Point, secp::MaybeScalar) = signature.unzip();
    let (R, s): ([u8; 33], [u8; 32]) = signature.unzip();
    # #[cfg(feature = "secp256k1")]
    let (R, s): (secp256k1::PublicKey, secp::MaybeScalar) = signature.unzip();
    # #[cfg(feature = "k256")]
    let (R, s): (k256::PublicKey, k256::Scalar) = signature.unzip();
    # #[cfg(feature = "k256")]
    let (R, s): (k256::AffinePoint, k256::Scalar) = signature.unzip();
}
#
# Ok(())
# }
```
<br>
</details>

This crate exports [BIP-0340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)-compatible compact Schnorr signature functionality as well.

- [`verify_single`] - Single Schnorr signature verification.
- [`verify_batch`] - Efficient batched signature verification.
- [`sign_solo`] - Single-key message signing.

## Serialization

Binary and hex serialization with is implemented for the following types.

- [`KeyAggContext`]
- [`SecNonce`]
- [`PubNonce`]
- [`AggNonce`]
- [`LiftedSignature`]
- [`CompactSignature`]

This is accomplished through the [`BinaryEncoding`] trait. Aliases to the methods of [`BinaryEncoding`] are declared on the vanilla implementations of each type. In addition, these types all implement common standard library traits:

- [`std::fmt::LowerHex`]
- [`std::fmt::UpperHex`]
- [`std::str::FromStr`]
- [`std::convert::TryFrom<&[u8]>`][std::convert::TryFrom]
- [`std::convert::TryFrom<[u8; N]>`][std::convert::TryFrom] (except [`KeyAggContext`])
- [`std::convert::TryFrom<&[u8; N]>`][std::convert::TryFrom] (except [`KeyAggContext`])

They can also be infallibly converted to [`Vec<u8>`][Vec] using [`std::convert::From`], or to `[u8; N]` for fixed-length encodable types.

If the `serde` feature is enabled, the above types implement [`serde::Serialize`] and [`serde::Deserialize`] for both binary and hex representations in constant time using the [`serdect`] crate.

<details>
    <summary><h2>Example</h2></summary>

```rust
# #[cfg(feature = "serde")]
# {
use musig2::{KeyAggContext, PubNonce, SecNonce};

#[derive(serde::Deserialize)]
struct CustomSigningSession {
    key_agg_ctx: KeyAggContext,
    pubnonces: Vec<PubNonce>,
    secnonce: SecNonce,
    message: String,
}

let json_data = "{
    \"key_agg_ctx\": \"034191a1714ff295b6bc1008aaab813ac5c47bb7d4e64065c0d488b35ead12e0ba\
                       000000020355d7de59c20355f9d8b14ccb60998983e9d73b38f64c9b9f2c4f868c\
                       0a7ac02f039582f6f17f99784bc6de6e5664ef5f69eb1bf0dc151d824b19481ab0717c0cd5\",
    \"pubnonces\": [
        \"02af252206259fc1bf588b1f847e15ac78fa840bfb06014cdbddcfcc0e5876f9c9\
          0380ab2fc9abe84ef42a8d87062d5094b9ab03f4150003a5449846744a49394e45\",
        \"020ab52d58f00887d5082c41dc85fd0bd3aaa108c2c980e0337145ac7003c28812\
          03956ec5bd53023261e982ac0c6f5f2e4b6c1e14e9b1992fb62c9bdfcf5b27dc8d\"
    ],
    \"secnonce\": \"B114E502BEAA4E301DD08A50264172C84E41650E6CB726B410C0694D59EFFB64\
                    95B5CAF28D045B973D63E3C99A44B807BDE375FD6CB39E46DC4A511708D0E9D2\",
    \"message\": \"attack at dawn\"
}";

let session: CustomSigningSession = serde_json::from_str(json_data).unwrap();

use musig2::BinaryEncoding;

let key_agg_bytes: Vec<u8> = session.key_agg_ctx.to_bytes();
let first_pubnonce_bytes: [u8; 66] = session.pubnonces[0].to_bytes();
let secnonce_bytes = <[u8; 64]>::from(session.secnonce);

let decoded_key_agg_ctx = KeyAggContext::from_bytes(&key_agg_bytes).unwrap();
let decoded_pubnonce = PubNonce::try_from(&first_pubnonce_bytes).unwrap();
let decoded_secnonce = SecNonce::try_from(secnonce_bytes).unwrap();
# }
```
<br>
</details>

# Security

## Nonce Reuse

The easiest pitfall for downstream instantiations of the MuSig2 protocol is accidental nonce reuse. If you ever reuse a [`SecNonce`] for two different signing sessions, [a co-signer can trick you into exposing your private key](https://medium.com/blockstream/musig-dn-schnorr-multisignatures-with-verifiably-deterministic-nonces-27424b5df9d6#e3b6).

<details>
    <summary><h3>But how?</h3></summary>

The malicious co-signer opens two signing sessions on the same message, and provides different nonces to the victim in both sessions. Even if the victim reuses _their_ secret nonce, a different nonce from a co-signer will result in different _aggregated_ nonces `R` and `R'` for both signing sessions. See [the Nonce Generation Algorithm in BIP327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki#user-content-nonce-aggregation) for more details on why this is.

The challenge hash `e` is computed as `e = H(R, Q, m)` (where `Q` is the aggregated pubkey and `m` is the message). Since the aggregated nonce `R'` of the second session is different, this results in a new challenge hash `e' = H(R', Q, m)` for the second signing session.

The victim's partial signatures `s` and `s'` for both signing sessions would be computed as:

```notrust
s = k + e * a * d
s' = k + e' * a * d
```

...Where `d` is their secret key, `a` is a publicly known key-coefficient, and `k` is their secret nonce.

Given both `s` and `s'` from the victim, the attacker can then solve for and compute the victim's private key `d`.

```notrust
k = s - e * a * d
s' = k + e' * a * d
s' = s - e * a * d + e' * a * d
s' = s - a * d * (e + e')
a * d * (e + e') = s - s'
d = (s - s') / a * (e + e')
```
<br>
</details>


The [State-Machine API](#state-machine-api) is designed to avoid this possibility by computing and storing the [`SecNonce`] inside the [`FirstRound`] struct, and never exposing it directly to the downstream consumer.

When using the `FirstRound` API, we recommend enabling the `rand` feature on this crate, and passing [`&mut rand::rngs::OsRng`][rand::rngs::OsRng] or [`&mut rand::thread_rng()`][rand::thread_rng] as the `nonce_seed` argument to [`FirstRound::new`]. This reduces the risk of accidental nonce reuse significantly.

<details>
    <summary><h2>Example</h2></summary>

```rust
# #[cfg(feature = "secp256k1")]
# use secp256k1::{SecretKey, PublicKey};
# #[cfg(not(feature = "secp256k1"))]
# use musig2::secp::{Point as PublicKey, Scalar as SecretKey};
# use musig2::KeyAggContext;
#
# /// Same pubkeys as in previous example
# let key_agg_ctx =
#     "0000000003026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f402f3\
#      b071c064f115ca762ed88c3efd1927ea657c7949698b77255ea25751331f0b03204ea8bc3425b2cb\
#      c9cb20617f67dc6b202467591d0b26d059e370b71ee392eb"
#       .parse::<KeyAggContext>()
#       .unwrap();
#
# let signer_index = 2;
# let seckey: SecretKey = "10e7721a3aa6de7a98cecdbd7c706c836a907ca46a43235a7b498b12498f98f0"
#     .parse()
#     .unwrap();
#
# let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
#
# // The group wants to sign something!
# let message = "hello interwebz!";
use musig2::{FirstRound, SecNonceSpices};

# #[cfg(feature = "rand")]
let mut first_round = FirstRound::new(
    key_agg_ctx,
    &mut rand::rngs::OsRng,
    signer_index,
    SecNonceSpices::new()
        .with_seckey(seckey)
        .with_message(&message),
)
.unwrap();
```

</details>

If you decide to use the Functional API instead for any reason, **you must ensure your code is adequately protected against accidental nonce reuse.**

## Constant Time Operations

All sensitive operations in this library endeavor to act in constant-time, independent of secret input. We mostly depend on the upstream [`k256`] and [`secp256k1`] crates for this functionality though, and no independent testing has confirmed this yet.
