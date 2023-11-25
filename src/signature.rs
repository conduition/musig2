use secp::{MaybeScalar, Point};

use crate::errors::DecodeError;
use crate::BinaryEncoding;

/// The number of bytes in a binary-serialized Schnorr signature.
pub const SCHNORR_SIGNATURE_SIZE: usize = 64;

/// Represents a compacted Schnorr signature, either
/// from an aggregated signing session or a single signer.
///
/// It differs from [`LiftedSignature`] in that a `CompactSignature`
/// contains the X-only serialized coordinate of the signature's nonce
/// point `R`, whereas a [`LiftedSignature`] contains the parsed curve
/// point `R`.
///
/// Parsing a curve point from a byte array requires some computations which
/// can be optimized away during verification. This is why `CompactSignature`
/// is its own separate type.
///
/// Rules for when to use each signature type during verification:
///
/// - Prefer using [`CompactSignature`] when parsing and verifying single
///   signatures. That will produce faster results as you won't need to
///   lift the X-only coordinate of the nonce-point to verify the signature.
/// - Prefer using [`LiftedSignature`] when using batch verification,
///   because lifted signatures are required for batch verification
///   so you might as well keep the signatures in lifted form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactSignature {
    /// The X-only byte representation of the public nonce point `R`.
    pub rx: [u8; 32],

    /// The signature scalar which proves knowledge of the secret key and nonce.
    pub s: MaybeScalar,
}

impl CompactSignature {
    /// Constructs a `CompactSignature` from a signature pair `(R, s)`.
    pub fn new(R: impl Into<Point>, s: impl Into<MaybeScalar>) -> CompactSignature {
        CompactSignature {
            rx: R.into().serialize_xonly(),
            s: s.into(),
        }
    }

    /// Lifts the nonce point X coordinate to a proper point with even parity,
    /// returning an error if the coordinate was not on the curve.
    pub fn lift_nonce(&self) -> Result<LiftedSignature, secp::errors::InvalidPointBytes> {
        let R = Point::lift_x(&self.rx)?;
        Ok(LiftedSignature { R, s: self.s })
    }
}

/// A representation of a Schnorr signature point+scalar pair `(R, s)`.
///
/// Differs from [`CompactSignature`] in that a `LiftedSignature`
/// contains the full nonce point `R`, which is parsed as a valid
/// curve point.
///
/// Rules for when to use each signature type during verification:
///
/// - Prefer using [`CompactSignature`] when parsing and verifying single
///   signatures. That will produce faster results as you won't need to
///   lift the X-only coordinate of the nonce-point to verify the signature.
/// - Prefer using [`LiftedSignature`] when using batch verification,
///   because lifted signatures are required for batch verification
///   so you might as well keep the signatures in lifted form.
///
/// A `LiftedSignature` has the exact sime binary serialization
/// format as a [`CompactSignature`], because the Y-coordinate
/// of the nonce point is implicit - It is always assumed to be
/// the even-parity point.
///
/// To construct a `LiftedSignature`, use [`LiftedSignature::new`]
/// to ensure the Y-coordinate of the nonce point is always converted
/// to even-parity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiftedSignature {
    pub(crate) R: Point,
    pub(crate) s: MaybeScalar,
}

impl LiftedSignature {
    /// Constructs a new lifted signature by converting the nonce point `R`
    /// to even parity.
    ///
    /// Accepts any types which convert to a [`secp::Point`] and
    /// [`secp::MaybeScalar`].
    pub fn new(R: impl Into<Point>, s: impl Into<MaybeScalar>) -> LiftedSignature {
        LiftedSignature {
            R: R.into().to_even_y(),
            s: s.into(),
        }
    }

    /// Compact the finalized signature by serializing the
    /// nonce point as an X-coordinate-only byte array.
    pub fn compact(&self) -> CompactSignature {
        CompactSignature::new(self.R, self.s)
    }

    /// Unzip this signature pair into a tuple of any two types
    /// which convert from [`secp::Point`] and [`secp::MaybeScalar`].
    ///
    /// ```
    /// // This allows us to use `R` as a variable name.
    /// #![allow(non_snake_case)]
    ///
    /// let signature = "c1de0db357c5d780c69624d0ab266a3b6866301adc85b66cc9fce26d2a60b72c\
    ///                  659c15ed9bc81df681e1e0607cf44cc08e77396f74359de1e6e6ff365ca94dae"
    ///     .parse::<musig2::LiftedSignature>()
    ///     .unwrap();
    ///
    /// let (R, s): ([u8; 33], [u8; 32]) = signature.unzip();
    /// let (R, s): (secp::Point, secp::MaybeScalar) = signature.unzip();
    /// # #[cfg(feature = "k256")]
    /// # {
    /// let (R, s): (k256::PublicKey, k256::Scalar) = signature.unzip();
    /// # }
    /// # #[cfg(feature = "secp256k1")]
    /// # {
    /// let (R, s): (secp256k1::PublicKey, secp::MaybeScalar) = signature.unzip();
    /// # }
    /// ```
    pub fn unzip<P, S>(&self) -> (P, S)
    where
        P: From<Point>,
        S: From<MaybeScalar>,
    {
        (P::from(self.R), S::from(self.s))
    }
}

mod encodings {
    use super::*;

    impl BinaryEncoding for CompactSignature {
        type Serialized = [u8; SCHNORR_SIGNATURE_SIZE];

        /// Serializes the signature to a compact 64-byte encoding,
        /// including the X coordinate of the `R` point and the
        /// serialized `s` scalar.
        fn to_bytes(&self) -> Self::Serialized {
            let mut serialized = [0u8; SCHNORR_SIGNATURE_SIZE];
            serialized[..32].clone_from_slice(&self.rx);
            serialized[32..].clone_from_slice(&self.s.serialize());
            serialized
        }

        /// Deserialize a compact Schnorr signature from a byte slice. This
        /// slice must be exactly [`SCHNORR_SIGNATURE_SIZE`] bytes long.
        fn from_bytes(signature_bytes: &[u8]) -> Result<Self, DecodeError<Self>> {
            if signature_bytes.len() != SCHNORR_SIGNATURE_SIZE {
                return Err(DecodeError::bad_length(signature_bytes.len()));
            }
            let rx = <[u8; 32]>::try_from(&signature_bytes[..32]).unwrap();
            let s = MaybeScalar::try_from(&signature_bytes[32..])?;
            Ok(CompactSignature { rx, s })
        }
    }

    impl BinaryEncoding for LiftedSignature {
        type Serialized = [u8; SCHNORR_SIGNATURE_SIZE];

        /// Serializes the signature to a compact 64-byte encoding,
        /// including the X coordinate of the `R` point and the
        /// serialized `s` scalar.
        fn to_bytes(&self) -> Self::Serialized {
            CompactSignature::from(*self).to_bytes()
        }

        /// Deserialize a compact Schnorr signature from a byte slice. This
        /// slice must be exactly [`SCHNORR_SIGNATURE_SIZE`] bytes long.
        fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError<Self>> {
            let compact_signature = CompactSignature::from_bytes(bytes).map_err(|e| e.convert())?;
            Ok(compact_signature.lift_nonce()?)
        }
    }

    impl_encoding_traits!(CompactSignature, SCHNORR_SIGNATURE_SIZE);
    impl_encoding_traits!(LiftedSignature, SCHNORR_SIGNATURE_SIZE);

    impl_hex_display!(CompactSignature);
    impl_hex_display!(LiftedSignature);
}

mod internal_conversions {
    use super::*;

    impl TryFrom<CompactSignature> for LiftedSignature {
        type Error = secp::errors::InvalidPointBytes;

        /// Convert the compact signature into an `(R, s)` pair by lifting
        /// the nonce point's X-coordinate representation. Fails if the
        /// X-coordinate bytes do not represent a valid curve point.
        fn try_from(signature: CompactSignature) -> Result<Self, Self::Error> {
            signature.lift_nonce()
        }
    }

    impl From<LiftedSignature> for CompactSignature {
        /// Converts a pair `(R, s)` into a schnorr signature struct.
        fn from(signature: LiftedSignature) -> Self {
            signature.compact()
        }
    }
}

#[cfg(feature = "secp256k1")]
mod secp256k1_conversions {
    use super::*;

    impl TryFrom<secp256k1::schnorr::Signature> for CompactSignature {
        type Error = DecodeError<Self>;
        fn try_from(signature: secp256k1::schnorr::Signature) -> Result<Self, Self::Error> {
            Self::try_from(signature.serialize())
        }
    }

    impl TryFrom<secp256k1::schnorr::Signature> for LiftedSignature {
        type Error = DecodeError<Self>;
        fn try_from(signature: secp256k1::schnorr::Signature) -> Result<Self, Self::Error> {
            Self::try_from(signature.serialize())
        }
    }

    impl From<CompactSignature> for secp256k1::schnorr::Signature {
        fn from(signature: CompactSignature) -> Self {
            Self::from_slice(&signature.to_bytes()).unwrap() // Never fails
        }
    }

    impl From<LiftedSignature> for secp256k1::schnorr::Signature {
        fn from(signature: LiftedSignature) -> Self {
            Self::from_slice(&signature.to_bytes()).unwrap() // Never fails
        }
    }
}

#[cfg(feature = "k256")]
mod k256_conversions {
    use super::*;

    impl From<(k256::PublicKey, k256::Scalar)> for CompactSignature {
        fn from((R, s): (k256::PublicKey, k256::Scalar)) -> Self {
            CompactSignature::new(R, s)
        }
    }

    impl From<(k256::PublicKey, k256::Scalar)> for LiftedSignature {
        fn from((R, s): (k256::PublicKey, k256::Scalar)) -> Self {
            LiftedSignature::new(R, s)
        }
    }

    impl TryFrom<CompactSignature> for (k256::PublicKey, k256::Scalar) {
        type Error = secp::errors::InvalidPointBytes;
        fn try_from(signature: CompactSignature) -> Result<Self, Self::Error> {
            Ok(signature.lift_nonce()?.unzip())
        }
    }

    impl From<LiftedSignature> for (k256::PublicKey, k256::Scalar) {
        fn from(signature: LiftedSignature) -> Self {
            signature.unzip()
        }
    }

    impl From<LiftedSignature> for (k256::AffinePoint, k256::Scalar) {
        fn from(signature: LiftedSignature) -> Self {
            signature.unzip()
        }
    }

    #[cfg(feature = "k256")]
    impl From<CompactSignature> for k256::WideBytes {
        fn from(signature: CompactSignature) -> Self {
            <[u8; SCHNORR_SIGNATURE_SIZE]>::from(signature).into()
        }
    }

    #[cfg(feature = "k256")]
    impl From<LiftedSignature> for k256::WideBytes {
        fn from(signature: LiftedSignature) -> Self {
            <[u8; SCHNORR_SIGNATURE_SIZE]>::from(signature).into()
        }
    }
}
