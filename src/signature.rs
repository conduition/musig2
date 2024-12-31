use secp::{MaybePoint, MaybeScalar, Point, Scalar, G};

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

    /// Encrypts an existing valid signature by subtracting a given adaptor secret.
    pub fn encrypt(&self, adaptor_secret: impl Into<Scalar>) -> AdaptorSignature {
        AdaptorSignature::new(self.R, self.s).encrypt(adaptor_secret)
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

/// A representation of a Schnorr adaptor signature point+scalar pair `(R', s')`.
///
/// Differs from [`LiftedSignature`] in that an `AdaptorSignature` is explicitly
/// modified with by specific scalar offset called the _adaptor secret,_ so that
/// only by learning the adaptor secret can its holder convert it
/// into a valid BIP340 signature.
///
/// Since `AdaptorSignature` is not meant for on-chain consensus, the nonce
/// point `R` can have either even or odd parity, and so `AdaptorSignature`
/// is encoded as a 65 byte array which includes the compressed `R` point.
///
/// To learn more about adaptor signatures and how to use them, see the docs
/// in [the adaptor module][crate::adaptor].
///
/// To construct an `AdaptorSignature`, use [`LiftedSignature::encrypt`],
/// [`adaptor::sign_solo`][crate::adaptor::sign_solo], or
/// [`adaptor::aggregate_partial_signatures`][crate::adaptor::aggregate_partial_signatures].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptorSignature {
    pub(crate) R: MaybePoint,
    pub(crate) s: MaybeScalar,
}

impl AdaptorSignature {
    /// Constructs a new adaptor signature from a nonce and scalar pair.
    ///
    /// Accepts any types which convert to a [`secp::MaybePoint`] and
    /// [`secp::MaybeScalar`].
    pub fn new(R: impl Into<MaybePoint>, s: impl Into<MaybeScalar>) -> AdaptorSignature {
        AdaptorSignature {
            R: R.into(),
            s: s.into(),
        }
    }

    /// Adapts the signature into a lifted signature with a given adaptor secret.
    ///
    /// Returns `None` if the nonce resulting from adding the adaptor point is the
    /// point at infinity.
    ///
    /// The resulting signature is not guaranteed to be valid unless the
    ///`AdaptorSignature` was already verified with
    /// [`adaptor::verify_single`][crate::adaptor::verify_single].
    /// If not, make sure to verify the resulting lifted signature
    /// using [`verify_single`][crate::verify_single].
    pub fn adapt<T: From<LiftedSignature>>(
        &self,
        adaptor_secret: impl Into<MaybeScalar>,
    ) -> Option<T> {
        let adaptor_secret: MaybeScalar = adaptor_secret.into();
        let adapted_nonce = (self.R + adaptor_secret * G).into_option()?;
        let adapted_sig = self.s + adaptor_secret.negate_if(adapted_nonce.parity());
        Some(T::from(LiftedSignature::new(adapted_nonce, adapted_sig)))
    }

    /// Encrypts an existing adaptor signature again, by subtracting another adaptor secret.
    pub fn encrypt(&self, adaptor_secret: impl Into<Scalar>) -> AdaptorSignature {
        let adaptor_secret: Scalar = adaptor_secret.into();
        AdaptorSignature {
            R: self.R - adaptor_secret * G,
            s: self.s - adaptor_secret,
        }
    }

    /// Using a decrypted signature `final_sig`, this method computes the
    /// adaptor secret used to encrypt this signature.
    ///
    /// Returns `None` if `final_sig` is not related to this adaptor signature.
    pub fn reveal_secret<S>(&self, final_sig: &LiftedSignature) -> Option<S>
    where
        S: From<MaybeScalar>,
    {
        let t = final_sig.s - self.s;
        let T = t * G;

        if T == final_sig.R - self.R {
            Some(S::from(t))
        } else if T == final_sig.R + self.R {
            Some(S::from(-t))
        } else {
            None
        }
    }

    /// Unzip this signature pair into a tuple of any two types
    /// which convert from [`secp::MaybePoint`] and [`secp::MaybeScalar`].
    ///
    /// ```
    /// // This allows us to use `R` as a variable name.
    /// #![allow(non_snake_case)]
    ///
    /// let signature = "02c1de0db357c5d780c69624d0ab266a3b6866301adc85b66cc9fce26d2a60b72c\
    ///                  659c15ed9bc81df681e1e0607cf44cc08e77396f74359de1e6e6ff365ca94dae"
    ///     .parse::<musig2::AdaptorSignature>()
    ///     .unwrap();
    ///
    /// let (R, s): ([u8; 33], [u8; 32]) = signature.unzip();
    /// let (R, s): (secp::MaybePoint, secp::MaybeScalar) = signature.unzip();
    /// # #[cfg(feature = "k256")]
    /// # {
    /// let (R, s): (k256::AffinePoint, k256::Scalar) = signature.unzip();
    /// # }
    /// ```
    pub fn unzip<P, S>(&self) -> (P, S)
    where
        P: From<MaybePoint>,
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

    impl BinaryEncoding for AdaptorSignature {
        type Serialized = [u8; 65];

        /// Serializes the signature to a compressed 65-byte encoding,
        /// including the compressed `R` point and the serialized `s` scalar.
        fn to_bytes(&self) -> Self::Serialized {
            let mut serialized = [0u8; 65];
            serialized[..33].clone_from_slice(&self.R.serialize());
            serialized[33..].clone_from_slice(&self.s.serialize());
            serialized
        }

        /// Deserialize an adaptor signature from a byte slice. This
        /// slice must be exactly 65 bytes long.
        fn from_bytes(signature_bytes: &[u8]) -> Result<Self, DecodeError<Self>> {
            if signature_bytes.len() != 65 {
                return Err(DecodeError::bad_length(signature_bytes.len()));
            }
            let R = MaybePoint::try_from(&signature_bytes[..33])?;
            let s = MaybeScalar::try_from(&signature_bytes[33..])?;
            Ok(AdaptorSignature { R, s })
        }
    }

    impl_encoding_traits!(CompactSignature, SCHNORR_SIGNATURE_SIZE);
    impl_encoding_traits!(LiftedSignature, SCHNORR_SIGNATURE_SIZE);
    impl_encoding_traits!(AdaptorSignature, 65);

    impl_hex_display!(CompactSignature);
    impl_hex_display!(LiftedSignature);
    impl_hex_display!(AdaptorSignature);
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
            Self::try_from(signature.to_byte_array())
        }
    }

    impl TryFrom<secp256k1::schnorr::Signature> for LiftedSignature {
        type Error = DecodeError<Self>;
        fn try_from(signature: secp256k1::schnorr::Signature) -> Result<Self, Self::Error> {
            Self::try_from(signature.to_byte_array())
        }
    }

    impl From<CompactSignature> for secp256k1::schnorr::Signature {
        fn from(signature: CompactSignature) -> Self {
            Self::from_byte_array(signature.to_bytes())
        }
    }

    impl From<LiftedSignature> for secp256k1::schnorr::Signature {
        fn from(signature: LiftedSignature) -> Self {
            Self::from_byte_array(signature.to_bytes())
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
