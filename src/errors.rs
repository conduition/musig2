//! Various error types for different kinds of failures.

use crate::KeyAggContext;

use std::error::Error;
use std::fmt;

/// Returned when aggregating a collection of public keys with [`KeyAggContext`]
/// results in the point at infinity.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct KeyAggError;
impl fmt::Display for KeyAggError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("computed an invalid aggregated key from a collection of public keys")
    }
}
impl Error for KeyAggError {}
impl From<secp::errors::InfinityPointError> for KeyAggError {
    fn from(_: secp::errors::InfinityPointError) -> Self {
        KeyAggError
    }
}

/// Returned when tweaking a [`KeyAggContext`] results in the point
/// at infinity, or if using [`KeyAggContext::with_taproot_tweak`]
/// when the tweak input results in a hash which exceeds the curve
/// order (exceedingly unlikely)"
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct TweakError;
impl fmt::Display for TweakError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("tweak value is invalid")
    }
}
impl Error for TweakError {}
impl From<secp::errors::InfinityPointError> for TweakError {
    fn from(_: secp::errors::InfinityPointError) -> Self {
        TweakError
    }
}

/// Returned when passing a signer index which is out of range for a
/// group of signers
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct SignerIndexError {
    /// The index of the signer we did not expect to receive.
    pub index: usize,

    /// The total size of the signing group.
    pub n_signers: usize,
}
impl fmt::Display for SignerIndexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "signer index {} is out of range for group of {} signers",
            self.index, self.n_signers
        )
    }
}
impl Error for SignerIndexError {}

impl SignerIndexError {
    /// Construct a new `SignerIndexError` indicating we received an
    /// invalid index for the given group size of signers.
    pub(crate) fn new(index: usize, n_signers: usize) -> SignerIndexError {
        SignerIndexError { index, n_signers }
    }
}

/// Error returned when (partial) signing fails.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SigningError {
    /// Indicates an unknown secret key was provided when
    /// using [`sign_partial`][crate::sign_partial] or
    /// finalizing the [`FirstRound`][crate::FirstRound].
    UnknownKey,

    /// We could not verify the signature we produced.
    /// This may indicate a malicious actor attempted to make us
    /// produce a signature which could reveal our secret key. The
    /// signing session should be aborted and retried with new nonces.
    SelfVerifyFail,
}
impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "failed to create signature: {}",
            match self {
                Self::UnknownKey => "signing key is not a member of the group",
                Self::SelfVerifyFail => "failed to verify our own signature; something is wrong",
            }
        )
    }
}
impl Error for SigningError {}

/// Error returned when verification fails.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum VerifyError {
    /// Indicates a public key was provided which is not
    /// a member of the signing group, and thus partial
    /// signature verification on this key has no meaning.
    UnknownKey,

    /// The signature is not valid for the given key and message.
    BadSignature,
}
impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "failed to verify signature: {}",
            match self {
                Self::UnknownKey => "public key is not a member of the group",
                Self::BadSignature => "signature is invalid",
            }
        )
    }
}
impl Error for VerifyError {}

impl From<VerifyError> for SigningError {
    fn from(_: VerifyError) -> Self {
        SigningError::SelfVerifyFail
    }
}

/// Enumerates the causes for why receiving a contribution from a peer
/// might fail.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ContributionFaultReason {
    /// The signer's index is out of range for the given
    /// number of signers in the group. Embeds `n_signers`
    /// (the number of signers).
    OutOfRange(usize),

    /// Indicates we received different contribution values from
    /// this peer for the same round. If we receive the same
    /// nonce or signature from this peer more than once this is
    /// acceptable and treated as a no-op, but receiving inconsistent
    /// contributions from the same signer may indicate there is
    /// malicious behavior occurring.
    InconsistentContribution,

    /// Indicates we received an invalid partial signature. Only returned by
    /// [`SecondRound::receive_signature`][crate::SecondRound::receive_signature].
    InvalidSignature,
}

/// This error is returned by when a peer provides an invalid contribution
/// to one of the signing rounds.
///
/// This is either because the signer's index exceeds the maximum, or
/// because we received an invalid contribution from this signer.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RoundContributionError {
    /// The erroneous signer index.
    pub index: usize,

    /// The reason why the signer's contribution was rejected.
    pub reason: ContributionFaultReason,
}

impl RoundContributionError {
    /// Create a new out of range signer index error.
    pub fn out_of_range(index: usize, n_signers: usize) -> RoundContributionError {
        RoundContributionError {
            index,
            reason: ContributionFaultReason::OutOfRange(n_signers),
        }
    }

    /// Create an error caused by an inconsistent contribution.
    pub fn inconsistent_contribution(index: usize) -> RoundContributionError {
        RoundContributionError {
            index,
            reason: ContributionFaultReason::InconsistentContribution,
        }
    }

    /// Create a new error caused by an invalid partial signature.
    pub fn invalid_signature(index: usize) -> RoundContributionError {
        RoundContributionError {
            index,
            reason: ContributionFaultReason::InvalidSignature,
        }
    }
}

impl fmt::Display for RoundContributionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ContributionFaultReason::*;
        write!(
            f,
            "invalid signer index {}: {}",
            self.index,
            match self.reason {
                OutOfRange(n_signers) => format!("exceeds max index for {} signers", n_signers),
                InconsistentContribution =>
                    "received inconsistent contributions from same signer".to_string(),
                InvalidSignature => "received invalid partial signature from peer".to_string(),
            }
        )
    }
}

impl Error for RoundContributionError {}

/// Returned when finalizing [`FirstRound`][crate::FirstRound] or
/// [`SecondRound`][crate::SecondRound] fails.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RoundFinalizeError {
    /// Contributions from all signers in the group are required to finalize
    /// a signing round. This error is returned if attempting to finalize
    /// a round before all contributions are received.
    Incomplete,

    /// Indicates partial signing failed unexpectedly. This is likely because
    /// the wrong secret key was provided. Only returned by
    /// [`FirstRound::finalize`][crate::FirstRound::finalize].
    SigningError(SigningError),

    /// Indicates the final aggregated signature is invalid. Only returned by
    /// [`SecondRound::finalize`][crate::SecondRound::finalize].
    InvalidAggregatedSignature(VerifyError),
}

impl fmt::Display for RoundFinalizeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "cannot finalize round: {}",
            match self {
                Self::Incomplete => "not all signers have contributed".to_string(),
                Self::SigningError(e) => format!("signing failed, {}", e),
                Self::InvalidAggregatedSignature(e) =>
                    format!("could not verify aggregated signature: {}", e),
            }
        )
    }
}

impl Error for RoundFinalizeError {}

impl From<SigningError> for RoundFinalizeError {
    fn from(e: SigningError) -> Self {
        RoundFinalizeError::SigningError(e)
    }
}

impl From<VerifyError> for RoundFinalizeError {
    fn from(e: VerifyError) -> Self {
        RoundFinalizeError::InvalidAggregatedSignature(e)
    }
}

/// Enumerates the various reasons why binary or hex decoding
/// could fail.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DecodeFailureReason {
    /// The hex string's format was incorrect, which could mean
    /// it either was the wrong length or held invalid characters.
    BadHexFormat(base16ct::Error),

    /// The byte slice we tried to deserialize had the wrong length.
    BadLength(usize),

    /// The bytes contained coordinates to a point that is not on
    /// the secp256k1 curve.
    InvalidPoint,

    /// The bytes slice contained a representation of a scalar which
    /// is outside the required finite field's range.
    InvalidScalar,

    /// Custom error reason.
    Custom(String),
}

/// Returned when decoding a certain data structure of type `T` fails.
///
/// The type `T` only serves as a compile-time safety check; no
/// data of type `T` is actually owned by this error.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DecodeError<T> {
    /// The reason for the decoding failure.
    pub reason: DecodeFailureReason,
    phantom: std::marker::PhantomData<T>,
}

impl<T> DecodeError<T> {
    /// Construct a new decoding error for type `T` given a cause
    /// for the failure.
    pub fn new(reason: DecodeFailureReason) -> Self {
        DecodeError {
            reason,
            phantom: std::marker::PhantomData,
        }
    }

    /// Create a decoding error caused by an incorrect input byte
    /// slice length.
    pub fn bad_length(size: usize) -> Self {
        let reason = DecodeFailureReason::BadLength(size);
        DecodeError::new(reason)
    }

    /// Create a custom decoding failure.
    pub fn custom(s: impl fmt::Display) -> Self {
        let reason = DecodeFailureReason::Custom(s.to_string());
        DecodeError::new(reason)
    }

    /// Converts the decoding error for one type into that of another type.
    pub fn convert<U>(self) -> DecodeError<U> {
        DecodeError::new(self.reason)
    }
}

impl<T> fmt::Display for DecodeError<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DecodeFailureReason::*;

        write!(
            f,
            "error decoding {}: {}",
            std::any::type_name::<T>(),
            match &self.reason {
                BadHexFormat(e) => format!("hex decoding error: {}", e),
                BadLength(size) => format!("unexpected length {}", size),
                InvalidPoint => secp::errors::InvalidPointBytes.to_string(),
                InvalidScalar => secp::errors::InvalidScalarBytes.to_string(),
                Custom(s) => s.to_string(),
            }
        )
    }
}

impl<T> From<secp::errors::InvalidPointBytes> for DecodeError<T> {
    fn from(_: secp::errors::InvalidPointBytes) -> Self {
        DecodeError::new(DecodeFailureReason::InvalidPoint)
    }
}

impl<T> From<secp::errors::InvalidScalarBytes> for DecodeError<T> {
    fn from(_: secp::errors::InvalidScalarBytes) -> Self {
        DecodeError::new(DecodeFailureReason::InvalidScalar)
    }
}

impl<T> From<base16ct::Error> for DecodeError<T> {
    fn from(e: base16ct::Error) -> Self {
        DecodeError::new(DecodeFailureReason::BadHexFormat(e))
    }
}

impl From<KeyAggError> for DecodeError<KeyAggContext> {
    fn from(e: KeyAggError) -> Self {
        DecodeError::custom(e)
    }
}

impl From<TweakError> for DecodeError<KeyAggContext> {
    fn from(_: TweakError) -> Self {
        DecodeError::custom("serialized KeyAggContext contains an invalid tweak")
    }
}
