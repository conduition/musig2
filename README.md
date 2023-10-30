# MuSig2

This crate provides a flexible rust implementation of [MuSig2](https://eprint.iacr.org/2020/1261), an optimized digital signature aggregation protocol, on the `secp256k1` elliptic curve.

MuSig2 allows groups of mutually distrusting parties to cooperatively sign data and aggregate their signatures into a single aggregated signature which is indistinguishable from a signature made by a single private key. The group collectively controls an _aggregated public key_ which can only create signatures if everyone in the group cooperates (AKA an N-of-N multisignature scheme). MuSig2 is optimized to support secure signature aggregation with only **two round-trips of network communication.**

Specifically, this crate implements [BIP-0327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki), for creating and verifying signatures which validate under Bitcoin consensus rules, but the protocol is flexible and can be applied to any N-of-N multisignature use-case.

## ⚠️ Beta Status ⚠️

This crate is in beta status. The latest release is a `v0.0.x` version number. Expect breaking changes and security fixes. Once this crate is stabilized, we will tag and release `v1.0.0`.

## Overview

If you're not already familiar with MuSig2, the process of cooperative signing runs like so:

1. All signers share their public keys with one-another. The group computes an _aggregated public key_ which they collectively control.
2. In the **first signing round,** signers generate and share _nonces_ (random numbers) with one-another. These nonces have both secret and public versions. Only the public nonce (AKA `PubNonce`) should be shared, while the corresponding secret nonce (AKA `SecNonce`) must be kept secret.
3. Once every signer has received the public nonces of every other signer, each signer makes a _partial signature_ for a message using their secret key and secret nonce.
4. In the **second signing round,** signers share their partial signatures with one-another. Partial signatures can be verified to place blame on misbehaving signers.
5. A valid set of partial signatures can be aggregated into a final signature, which is just a normal [Schnorr signature](https://en.wikipedia.org/wiki/Schnorr_signature), valid under the aggregated public key.

## Choice of Backbone

This crate does not implement elliptic curve point math directly. Instead we depend on one of two reputable libraries:

- C bindings to [`libsecp256k1`](https://github.com/bitcoin-core/secp256k1), via [the `secp256k1` crate](https://crates.io/crates/secp256k1), maintained by the Bitcoin Core team.
- A pure-rust implementation via [the `k256` crate](https://crates.io/crates/k256), maintained by the [RustCrypto](https://github.com/RustCrypto) team.

One or the other can be used. By default, this crate prefers to rely on `libsecp256k1`, as this is the most vetted and publicly trusted implementation of secp256k1 curve math available anywhere. However, if you need a pure-rust implementation, you can install this crate without it, and use the pure-rust `k256` crate instead.

```notrust
cargo add musig2 --no-default-features --features k256
```

If both `k256` and `secp256k1` features are enabled, then we default to using `libsecp256k1` bindings for the actual math, but still provide trait implementations to make this crate interoperable with `k256`.

This crate internally represents elliptic curve points (e.g. public keys) and scalars (e.g. private keys) using the [`secp` crate](https://crates.io/crates/secp) and its types:

- [`secp::Scalar`](https://docs.rs/secp/struct.Scalar.html) for non-zero scalar values.
- [`secp::Point`](https://docs.rs/secp/struct.Point.html) for non-infinity curve points
- [`secp::MaybeScalar`](https://docs.rs/secp/enum.Point.html) for possibly-zero scalars.
- [`secp::MaybePoint`](https://docs.rs/secp/enum.Point.html) for possibly-infinity curve points.

Depending on which features of this crate are enabled, conversion traits are implemented between these types and higher-level types such as [`secp256k1::PublicKey`](https://docs.rs/secp256k1/struct.PublicKey.html) or [`k256::SecretKey`](https://docs.rs/k256/type.SecretKey.html). Generally, our API can accept or return any type that converts to/from the equivalent `secp` representations, although callers are also welcome to use `secp` directly too.

## Documentation

[Head on over to docs.rs to see the full API documentation and usage examples.](https://docs.rs/musig2)
