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

pub mod errors;
pub mod tagged_hashes;

pub use binary_encoding::*;
pub use bip340::*;
pub use key_agg::*;
pub use nonces::*;
pub use rounds::*;
pub use sig_agg::*;
pub use signature::*;
pub use signing::*;

#[cfg(test)]
pub(crate) mod testhex;

/// Re-export of the inner types used to represent curve points and scalars.
pub use secp;

#[cfg(feature = "secp256k1")]
pub use secp256k1;

#[cfg(feature = "k256")]
pub use k256;
