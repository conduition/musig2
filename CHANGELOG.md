# Changelog

## v0.4.1

- **Deps**: Remove direct dependence on `once_cell` (https://github.com/conduition/musig2/pull/11 https://github.com/conduition/secp/commit/f09e4397dd802946e0e1902f62aa63569cd02a3a)
- **Fixed panic**: Previously, if the third-party type `secp256k1::Scalar` was passed to any of the myriad methods of `musig2` which accept `impl Into<secp::Scalar>`, it would cause a panic when `secp256k1::Scalar::ZERO` is given. This was fixed upstream (https://github.com/conduition/secp/commit/84a9c4c1d23acc328a300270dcccbdc191b383a1) and applied in `musig2` in this commit (https://github.com/conduition/musig2/commit/a821f6129cee192579ee1a1765dd42e16835cb3d).

### Breaking Changes

The `musig2` API no longer accepts the third-party type `secp256k1::Scalar` in parameters which must implement `Into<secp::Scalar>`. This is because `secp256k1::Scalar` can be zero, but `secp::Scalar` cannot. This change was required to prevent panics.

## v0.4.0

- **DX**: New benchmarks for verification, signing and comparison against libsecp256k1.
- **SecNonce changes:** To fully comply with BIP-327, the `SecNonce` and `SecNonceBuilder` API have been changed (https://github.com/conduition/musig2/pull/17). The `SecNonce` data structure now includes the signer's public key. See below for migration instructions.
- **Security Improvement:** To align with BIP-327 security recommendations, we now validate the pubkey contained in `SecNonce` against the key provided by the signer in the `sign_partial` and `adaptor::sign_partial` functions, and if they do not align we return a new error enum member `SigningError::SecNoncePubkeyMismatch`. In the state-machine API, this can only happen if you pass in the secret key of a _different_ pubkey within the same `KeyAggContext` as passed to `FirstRound::new`.

### Breaking Changes

1. The `SecNonce` serialization format has been updated to comply with BIP327.

```diff
 /// The size of a serialized [`SecNonce`] in bytes.
-pub const SEC_NONCE_SIZE: usize = 64;
+pub const SEC_NONCE_SIZE: usize = 97;
```

This affects any downstream callers who store `SecNonce` out of band, and load it later (e.g long-lived signing sessions).

**Recommended Fix:** Add middleware code or perform database migration to append the signer's individual 33-byte public key before deserializing a `SecNonce` created by `musig2` version v0.3.1 or earlier.

2. The `SecNonceBuilder` API has changed.

```diff
 impl<'snb> SecNonceBuilder<'snb> {
-    pub fn new(nonce_seed: impl Into<NonceSeed>) -> SecNonceBuilder<'snb>;
-    pub fn with_pubkey(self, pubkey: impl Into<secp::Point>) -> SecNonceBuilder<'snb>;
-    pub fn with_seckey(self, seckey: impl Into<secp::Scalar>) -> SecNonceBuilder<'snb>;
+    pub fn from_pubkey(
+        nonce_seed: impl Into<NonceSeed>,
+        pubkey: impl Into<secp::Point>,
+    ) -> SecNonceBuilder<'snb>;
+    pub fn from_seckey(
+        nonce_seed: impl Into<NonceSeed>,
+        seckey: impl Into<secp::Scalar>,
+    ) -> SecNonceBuilder<'snb>;
 }
```

To comply with BIP-327, a public or secret key is now a mandatory parameter needed to build a `SecNonce`. As such, the `SecNonceBuilder::with_pubkey` and `SecNonceBuilder::with_seckey` methods have been removed, and the `SecNonceBuilder::new(nonce_seed)` constructor method has been replaced with two new constructors:

- `SecNonceBuilder::from_pubkey(nonce_seed, pubkey)`, which takes any type that converts to `secp::Point`.
- `SecNonceBuilder::from_seckey(nonce_seed, seckey)`, which takes any type that converts to `secp::Scalar`.

**Recommended Fix:** The state-machine API will handle this adjustment for you. If you use the state-machine API, no action should be needed. If you use the functional API, you will need to update your code to provide a public key, or if possible a secret key, when building a `SecNonce` using one of the two new constructors. Callers who wish to update a `SecNonceBuilder` with a secret key after calling a constructor may still do so, using the `SecNonceBuilder::with_spices` method, but beware this overwrites any public key (or secret key) set by the constructor.

3. The `SecNonce` API has changed.

```diff
 impl SecNonce {
-    pub fn new<T: Into<secp::Scalar>>(k1: T, k2: T) -> SecNonce;
-    pub fn build<'snb>(nonce_seed: impl Into<NonceSeed>) -> SecNonceBuilder<'snb>;
-    pub fn random<R>(rng: &mut R) -> SecNonce
+    pub fn new<T: Into<secp::Scalar>>(k1: T, k2: T, pubkey: impl Into<secp::Point>) -> SecNonce;
+    pub fn build_with_pubkey<'snb>(
+        nonce_seed: impl Into<NonceSeed>,
+        pubkey: impl Into<Point>,
+    ) -> SecNonceBuilder<'snb>;
+    pub fn build_with_seckey<'snb>(
+        nonce_seed: impl Into<NonceSeed>,
+        seckey: impl Into<Scalar>,
+    ) -> SecNonceBuilder<'snb>;
+    pub fn random<R>(rng: &mut R, pubkey: impl Into<secp::Point>) -> SecNonce
     where
         R: rand::RngCore + rand::CryptoRng;
 }
```

These changes are mostly a reflection of the above changes to the `SecNonceBuilder` API.

- The `SecNonce::new` constructor arguments have been extended with a mandatory public key parameter.
- The `SecNonce::build` shortcut method has been split into two new methods to reflect the new constructors for `SecNonceBuilder`:
  - `SecNonce::build_with_pubkey` is an alias to `SecNonceBuilder::from_pubkey`.
  - `SecNonce::build_with_seckey` is an alias to `SecNonceBuilder::from_seckey`.
- The `SecNonce::random` method arguments have been extended with a mandatory public key parameter.

**Recommended Fix:** The state-machine API will handle this adjustment for you. If you use the state-machine API, no action should be needed. If you use the functional API, you will need to update your code to provide a public or secret key when building a `SecNonce`.

4. `FirstRound::new` returns a new error type, `RoundSetupError`.

```diff
 impl FirstRound {
     pub fn new(
         key_agg_ctx: KeyAggContext,
         nonce_seed: impl Into<NonceSeed>,
         signer_index: usize,
         spices: SecNonceSpices<'_>,
-    ) -> Result<FirstRound, SignerIndexError>;
+    ) -> Result<FirstRound, RoundSetupError>;
 }
```

This change reflects a new check included in `FirstRound::new` which ensures any secret key provided in the `spices` parameter aligns with the public key implied by the `key_agg_ctx` and `signer_index` parameters.

See [the docs for `FirstRound::new`](https://docs.rs/musig2/latest/musig2/struct.FirstRound.html#method.new) for more info.

**Recommended Fix:** Adjust error handling code as needed. If you do not use the `seckey` field of `SecNonceSpices`, or if the `seckey` field is always guaranteed to match with the pubkey at `signer_index`, this doesn't affect you.
