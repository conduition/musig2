#![doc = include_str!("../README.md")]
#![doc = include_str!("../doc/API.md")]
#![allow(non_snake_case)]
#![warn(missing_docs)]

#[cfg(all(not(feature = "secp256k1"), not(feature = "k256")))]
compile_error!("At least one of the `secp256k1` or `k256` features must be enabled.");

#[macro_use]
mod binary_encoding;

mod bip340;
mod key_agg;
mod key_sort;
mod nonces;
mod rounds;
mod sig_agg;
mod signature;
mod signing;

#[doc = include_str!("../doc/adaptor_signatures.md")]
pub mod adaptor {
    pub use crate::bip340::sign_solo_adaptor as sign_solo;
    pub use crate::bip340::verify_single_adaptor as verify_single;
    pub use crate::sig_agg::aggregate_partial_adaptor_signatures as aggregate_partial_signatures;
    pub use crate::signature::AdaptorSignature;
    pub use crate::signing::sign_partial_adaptor as sign_partial;
    pub use crate::signing::verify_partial_adaptor as verify_partial;
}

pub mod deterministic;
pub mod errors;
pub mod tagged_hashes;

pub use binary_encoding::*;
pub use bip340::{sign_solo, verify_single};
pub use key_agg::*;
pub use nonces::*;
pub use rounds::*;
pub use sig_agg::aggregate_partial_signatures;
pub use signature::*;
pub use signing::{
    compute_challenge_hash_tweak, sign_partial, verify_partial, PartialSignature,
    PARTIAL_SIGNATURE_SIZE,
};

#[cfg(test)]
pub(crate) mod testhex;

/// Re-export of the inner types used to represent curve points and scalars.
pub use secp;

#[cfg(feature = "secp256k1")]
pub use secp256k1;

#[cfg(feature = "k256")]
pub use k256;

#[cfg(any(test, feature = "rand"))]
pub use bip340::{verify_batch, BatchVerificationRow};
