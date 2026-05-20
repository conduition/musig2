# Changelog

## v0.4.0

- **DX**: New benchmarks for verification, signing and comparison against libsecp256k1.
- **SecNonce changes:** To fully comply with BIP327, the `SecNonce` and `SecNonceBuilder` API have been changed (https://github.com/conduition/musig2/pull/17). See below for migration instructions.

### Breaking Changes

1. The `SecNonce` serialization format has been updated to comply with BIP327.

```diff
diff --git a/src/nonces.rs b/src/nonces.rs
index 5aa2d9b..d90dfe3 100644
--- a/src/nonces.rs
+++ b/src/nonces.rs
@@ -6,7 +6,7 @@ use secp::{MaybePoint, MaybeScalar, Point, Scalar, G};
 use sha2::Digest as _;

 /// The size of a serialized [`SecNonce`] in bytes.
-pub const SEC_NONCE_SIZE: usize = 64;
+pub const SEC_NONCE_SIZE: usize = 97;
```

This affects any downstream callers who store `SecNonce` out of band, and load it later (e.g long-lived signing sessions).

**Recommended Fix:** Add middleware code or perform database migration to append the signer's individual 33-byte public key before deserializing a `SecNonce` created by `musig2` version v0.3.1 or earlier.

2. TODO: `SecNonceBuilder` API
3. TODO: `SecNonce` API
4. TODO: `FirstRound::new` returns new error type if `SecNonceSpices.seckey` is incorrect
