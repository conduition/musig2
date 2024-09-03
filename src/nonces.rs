use crate::errors::DecodeError;
use crate::{tagged_hashes, BinaryEncoding};

use secp::{MaybePoint, MaybeScalar, Point, Scalar, G};

use sha2::Digest as _;

/// Represents the primary source of entropy for building a [`SecNonce`].
///
/// Often referred to as the variable `rand` in
/// [BIP-0327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki) and
/// [BIP-0340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
pub struct NonceSeed(pub [u8; 32]);

impl From<[u8; 32]> for NonceSeed {
    /// Converts a byte array to a `NonceSeed` by moving.
    fn from(bytes: [u8; 32]) -> Self {
        NonceSeed(bytes)
    }
}

impl From<&[u8; 32]> for NonceSeed {
    /// Converts a reference to a byte array to a `NonceSeed` by copying.
    fn from(bytes: &[u8; 32]) -> Self {
        NonceSeed(*bytes)
    }
}

#[cfg(any(test, feature = "rand"))]
impl<T: rand::RngCore + rand::CryptoRng> From<&mut T> for NonceSeed {
    /// This implementation draws a [`NonceSeed`] from a mutable reference
    /// to a CSPRNG. Panics if the RNG fails to fill the seed with 32
    /// random bytes.
    fn from(rng: &mut T) -> NonceSeed {
        let mut bytes = [0u8; 32];
        rng.try_fill_bytes(&mut bytes)
            .expect("error generating secure secret nonce seed");
        NonceSeed(bytes)
    }
}

pub(crate) fn xor_bytes<const SIZE: usize>(a: &[u8; SIZE], b: &[u8; SIZE]) -> [u8; SIZE] {
    let mut out = [0; SIZE];
    for i in 0..SIZE {
        out[i] = a[i] ^ b[i]
    }
    out
}

fn extra_input_length_check<T: AsRef<[u8]>>(extra_inputs: &[T]) {
    let total_len: usize = extra_inputs
        .iter()
        .map(|extra_input| extra_input.as_ref().len())
        .sum();
    assert!(
        total_len <= u32::MAX as usize,
        "excessive use of extra_input when building secnonce; max length is 2^32 bytes"
    );
}

/// A set of optional parameters which can be provided to _spice up_ the
/// entropy of the secret nonces generated for a signing session.
///
/// These parameters are not functionally required for any operations after
/// nonce generation - you can provide a different secret key in the `SecNonceSpices`
/// than you'll use for actual signing, and the signature will still be valid.
/// However, using the parameters appropriately will reduce the risk of
/// your code accidentally reusing a nonce and exposing your secret key.
///
/// This type is meant to be used as a parameter of the state-machine API available
/// via [`FirstRound`][crate::FirstRound] and [`SecondRound`][crate::SecondRound].
/// For standalone nonce generation, see [`SecNonceBuilder`] or [`SecNonce::generate`].
#[derive(Clone, Default)]
pub struct SecNonceSpices<'ns> {
    pub(crate) seckey: Option<Scalar>,
    pub(crate) message: Option<&'ns dyn AsRef<[u8]>>,
    pub(crate) extra_inputs: Vec<&'ns dyn AsRef<[u8]>>,
}

impl<'ns> SecNonceSpices<'ns> {
    /// Creates a new empty set of `SecNonceSpices`. Same as [`SecNonceSpices::default`].
    pub fn new() -> SecNonceSpices<'ns> {
        SecNonceSpices::default()
    }

    /// Add the secret key you intend to sign with to the spice rack.
    /// This doesn't _need_ to be the actual key you sign with, but
    /// for best efficacy that would be the recommended usage.
    pub fn with_seckey(self, seckey: impl Into<Scalar>) -> SecNonceSpices<'ns> {
        SecNonceSpices {
            seckey: Some(seckey.into()),
            ..self
        }
    }

    /// Spices up the nonce with the message you intend to sign. Similarly
    /// to [`SecNonceSpices::with_seckey`], this doesn't need to be the actual message
    /// you end up signing, but that would help.
    pub fn with_message<M: AsRef<[u8]>>(self, message: &'ns M) -> SecNonceSpices<'ns> {
        SecNonceSpices {
            message: Some(message),
            ..self
        }
    }

    /// Add some arbitrary extra input, any context-specific data you have on hand, to
    /// spice up the nonce generation process. This method is additive, appending
    /// further extra data on top of previous chunks, which will all be cumulatively
    /// hashed to produce the final secret nonce.
    ///
    /// ```
    /// let session_id = [0x11u8; 16];
    ///
    /// musig2::SecNonceSpices::new()
    ///     .with_extra_input(b"hello world")
    ///     .with_extra_input(&session_id)
    ///     .with_extra_input(&(42u32).to_be_bytes());
    /// ```
    pub fn with_extra_input<E: AsRef<[u8]>>(mut self, extra_input: &'ns E) -> SecNonceSpices<'ns> {
        self.extra_inputs.push(extra_input);
        extra_input_length_check(&self.extra_inputs);
        self
    }
}

/// A helper struct used to construct [`SecNonce`] instances.
///
/// `SecNonceBuilder` allows piecemeal salting of the resulting `SecNonce`
/// depending on what is available to the caller.
///
/// `SecNonce`s can be constructed in a variety of ways using different
/// input sources to increase their entropy. While simple random sampling
/// of `SecNonce` is acceptable in theory, RNGs can fail quietly sometimes.
/// If possible, it is highly recommended to also salt the nonce with
/// session-specific data, such as the message being signed, or the
/// public/secret key which will be used for signing.
///
/// At bare minimum, [`SecNonceBuilder::new`] requires only 32 random
/// input bytes. Chainable methods can be used thereafter to salt the resulting
/// nonce with additional data. The nonce can be finalized and returned by
/// [`SecNonceBuilder::build`].
///
///  If no other data is available, we highly recommend _at least_ salting the nonce
/// with the public key, as recommended by BIP327.
///
/// # Example
///
/// Here we construct a nonce which we intend to use to sign the byte string
/// `b"hello world"` with a specific public key.
///
/// ```
/// use secp::Point;
///
/// // in reality, this would be generated by a CSPRNG.
/// let nonce_seed = [0xAB; 32];
///
/// let secnonce = musig2::SecNonceBuilder::new(nonce_seed)
///     .with_pubkey(
///         "037eaef9ce945fbcef58c6ca818f433fad8275c09441b06a274a93aa5d69374f62"
///             .parse::<Point>()
///             .expect("fail")
///     )
///     .with_message(b"hello world")
///     .build();
///
/// assert_eq!(
///     secnonce,
///     "304e472f8028efc386eb305b496e49a9c71984fbddb915c04002764a98d77a82\
///      b2f29921753a6a05a1f91556debdaac4d20ad20519f91bcebf4a2d842a05b0bc"
///         .parse()
///         .unwrap()
/// );
/// ```
pub struct SecNonceBuilder<'snb> {
    nonce_seed_bytes: [u8; 32],
    seckey: Option<Scalar>,
    pubkey: Option<Point>,
    aggregated_pubkey: Option<Point>,
    message: Option<&'snb [u8]>,
    extra_inputs: Vec<&'snb dyn AsRef<[u8]>>,
}

impl<'snb> SecNonceBuilder<'snb> {
    /// Start building a nonce, seeded with the given random data
    /// source `nonce_seed`, which should either be
    ///
    /// - 32 bytes drawn from a cryptographically secure RNG, OR
    /// - a mutable reference to a secure RNG.
    ///
    /// ```
    /// use rand::RngCore as _;
    ///
    /// # #[cfg(feature = "rand")]
    /// // Sample the seed automatically
    /// let secnonce = musig2::SecNonceBuilder::new(&mut rand::rngs::OsRng)
    ///     .with_message(b"hello world!")
    ///     .build();
    ///
    /// // Sample the seed manually
    /// let mut nonce_seed = [0u8; 32];
    /// rand::rngs::OsRng.fill_bytes(&mut nonce_seed);
    /// let secnonce = musig2::SecNonceBuilder::new(nonce_seed)
    ///     .with_message(b"hello world!")
    ///     .build();
    /// ```
    ///
    /// # WARNING
    ///
    /// It is critical for the `nonce_seed` to be **sampled randomly,** and NOT
    /// constructed deterministically based on signing session data. Otherwise,
    /// the signer can be [tricked into reusing the same nonce for concurrent
    /// signing sessions, thus exposing their secret key.](
    #[doc = "https://medium.com/blockstream/musig-dn-schnorr-multisignatures\
             -with-verifiably-deterministic-nonces-27424b5df9d6#e3b6)"]
    pub fn new(nonce_seed: impl Into<NonceSeed>) -> SecNonceBuilder<'snb> {
        let NonceSeed(nonce_seed_bytes) = nonce_seed.into();
        SecNonceBuilder {
            nonce_seed_bytes,
            seckey: None,
            pubkey: None,
            aggregated_pubkey: None,
            message: None,
            extra_inputs: Vec::new(),
        }
    }

    /// Salt the resulting nonce with the public key expected to be used
    /// during the signing phase.
    ///
    /// The public key will be overwritten if [`SecNonceBuilder::with_seckey`]
    /// is used after this method.
    pub fn with_pubkey(self, pubkey: impl Into<Point>) -> SecNonceBuilder<'snb> {
        SecNonceBuilder {
            pubkey: Some(pubkey.into()),
            ..self
        }
    }

    /// Salt the resulting nonce with the secret key which the nonce should be
    /// used to protect during the signing phase.
    ///
    /// Overwrites any public key previously added by
    /// [`SecNonceBuilder::with_pubkey`], as we compute the public key
    /// of the given secret key and add it to the builder.
    pub fn with_seckey(self, seckey: impl Into<Scalar>) -> SecNonceBuilder<'snb> {
        let seckey: Scalar = seckey.into();
        SecNonceBuilder {
            seckey: Some(seckey),
            pubkey: Some(seckey * G),
            ..self
        }
    }

    /// Salt the resulting nonce with the message which we expect to be signing with
    /// the nonce.
    pub fn with_message<M: AsRef<[u8]>>(self, msg: &'snb M) -> SecNonceBuilder<'snb> {
        SecNonceBuilder {
            message: Some(msg.as_ref()),
            ..self
        }
    }

    /// Salt the resulting nonce with the aggregated public key which we expect to aggregate
    /// signatures for.
    pub fn with_aggregated_pubkey(
        self,
        aggregated_pubkey: impl Into<Point>,
    ) -> SecNonceBuilder<'snb> {
        SecNonceBuilder {
            aggregated_pubkey: Some(aggregated_pubkey.into()),
            ..self
        }
    }

    /// Salt the resulting nonce with arbitrary extra input bytes. This might be context-specific
    /// data like a signing session ID, the name of the protocol, the current timestamp, whatever
    /// you want, really.
    ///
    /// This method is additive; it does not overwrite the `extra_input` values added by previous
    /// invocations of itself. This allows the caller to salt the nonce with an arbitrary amount
    /// of extra entropy as desired, up to a limit of [`u32::MAX`] bytes (about 4GB). This method
    /// will panic if the sum of all extra inputs attached to the builder would exceed that limit.
    ///
    /// ```
    /// # let nonce_seed = [0xABu8; 32];
    /// let remote_ip = [127u8, 0, 0, 1];
    ///
    /// let secnonce = musig2::SecNonceBuilder::new(nonce_seed)
    ///     .with_extra_input(b"MyApp")
    ///     .with_extra_input(&remote_ip)
    ///     .with_extra_input(&String::from("What's up buttercup?"))
    ///     .build();
    /// ```
    pub fn with_extra_input<E: AsRef<[u8]>>(
        mut self,
        extra_input: &'snb E,
    ) -> SecNonceBuilder<'snb> {
        self.extra_inputs.push(extra_input);
        extra_input_length_check(&self.extra_inputs);
        self
    }

    /// Sprinkles in a set of [`SecNonceSpices`] to this nonce builder. Extra inputs in
    /// `spices` are appended to the builder (see [`SecNonceBuilder::with_extra_input`]).
    /// All other parameters will be merged with those in `spices`, preferring parameters
    /// in `spices` if they are present.
    pub fn with_spices(mut self, spices: SecNonceSpices<'snb>) -> SecNonceBuilder<'snb> {
        self.seckey = spices.seckey.or(self.seckey);
        self.message = spices.message.map(|msg| msg.as_ref()).or(self.message);

        let mut new_extra_inputs = spices.extra_inputs;
        self.extra_inputs.append(&mut new_extra_inputs);
        extra_input_length_check(&self.extra_inputs);

        self
    }

    /// Build the secret nonce by hashing all of the builder's inputs into two
    /// byte arrays, and reducing those byte arrays modulo the curve order into
    /// two scalars `k1` and `k2`. These form the `SecNonce` as the tuple `(k1, k2)`.
    ///
    /// If the reduction results in an output of zero for either scalar,
    /// we use a nonce of 1 instead for that scalar.
    ///
    /// This method matches the standard nonce generation algorithm specified in
    /// [BIP327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki),
    /// except in the extremely unlikely case of a hash reducing to zero.
    pub fn build(self) -> SecNonce {
        let seckey_bytes = match self.seckey {
            Some(seckey) => seckey.serialize(),
            None => [0u8; 32],
        };

        let nonce_seed_hash: [u8; 32] = tagged_hashes::MUSIG_AUX_TAG_HASHER
            .clone()
            .chain_update(self.nonce_seed_bytes)
            .finalize()
            .into();

        let mut hasher = tagged_hashes::MUSIG_NONCE_TAG_HASHER
            .clone()
            .chain_update(xor_bytes(&seckey_bytes, &nonce_seed_hash));

        // BIP327 doesn't allow the public key to be an optional argument,
        // but there is no hard reason for that other than 'the RNG might fail'.
        // For ergonomics we allow the pubkey to be omitted here in the same
        // fashion as the aggregated pubkey.
        match self.pubkey {
            None => hasher.update([0]),
            Some(pubkey) => {
                hasher.update([33]); // individual pubkey len
                hasher.update(pubkey.serialize());
            }
        }

        match self.aggregated_pubkey {
            None => hasher.update([0]),
            Some(aggregated_pubkey) => {
                hasher.update([32]); // aggregated pubkey len
                hasher.update(aggregated_pubkey.serialize_xonly());
            }
        };

        match self.message {
            None => hasher.update([0]),
            Some(message) => {
                hasher.update([1]);
                hasher.update((message.len() as u64).to_be_bytes());
                hasher.update(message);
            }
        };

        // We still write the extra input length if the caller provided empty extra info.
        if !self.extra_inputs.is_empty() {
            let extra_input_total_len: usize = self
                .extra_inputs
                .iter()
                .map(|extra_in| extra_in.as_ref().len())
                .sum();

            hasher.update((extra_input_total_len as u32).to_be_bytes());
            for extra_input in self.extra_inputs {
                hasher.update(extra_input.as_ref());
            }
        }

        // Cloning the hash engine state reduces the computations needed.
        let hash1 = <[u8; 32]>::from(hasher.clone().chain_update([0]).finalize());
        let hash2 = <[u8; 32]>::from(hasher.clone().chain_update([1]).finalize());

        let k1 = match MaybeScalar::reduce_from(&hash1) {
            MaybeScalar::Zero => Scalar::one(),
            MaybeScalar::Valid(k) => k,
        };
        let k2 = match MaybeScalar::reduce_from(&hash2) {
            MaybeScalar::Zero => Scalar::one(),
            MaybeScalar::Valid(k) => k,
        };
        SecNonce { k1, k2 }
    }
}

/// A pair of secret nonce scalars, used to conceal a secret key when
/// signing a message.
///
/// The secret nonce provides randomness, blinding a signer's private key when
/// signing. It is imperative that the same `SecNonce` is not used to sign more
/// than one message with the same key, as this would allow an observer to
/// compute the private key used to create both signatures.
///
/// `SecNonce`s can be constructed in a variety of ways using different
/// input sources to increase their entropy. See [`SecNonceBuilder`] and
/// [`SecNonce::build`] to explore secure nonce generation using
/// contextual entropy sources.
///
/// Ideally, `SecNonce`s should be generated with a cryptographically secure
/// random number generator via [`SecNonce::generate`].
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct SecNonce {
    pub(crate) k1: Scalar,
    pub(crate) k2: Scalar,
}

impl SecNonce {
    /// Construct a new `SecNonce` from the given individual nonce values.
    pub fn new<T: Into<Scalar>>(k1: T, k2: T) -> SecNonce {
        SecNonce {
            k1: k1.into(),
            k2: k2.into(),
        }
    }

    /// Constructs a new [`SecNonceBuilder`] from the given random nonce seed.
    ///
    /// See [`SecNonceBuilder::new`].
    pub fn build<'snb>(nonce_seed: impl Into<NonceSeed>) -> SecNonceBuilder<'snb> {
        SecNonceBuilder::new(nonce_seed)
    }

    /// Generates a `SecNonce` securely from the given input arguments.
    ///
    /// - `nonce_seed`: the primary source of entropy used to generate the nonce.
    ///   Can be any type that converts to [`NonceSeed`], such as
    ///   [`&mut rand::rngs::OsRng`][rand::rngs::OsRng] or `[u8; 32]`.
    /// - `seckey`: the secret key which will be used to sign the message.
    /// - `aggregated_pubkey`: the aggregated public key.
    /// - `message`: the message which will be signed.
    /// - `extra_input`: arbitrary context data used to increase the entropy
    ///    of the resulting nonces.
    ///
    /// This implementation matches the specfication of nonce generation in BIP327,
    /// and all arguments are required. If you cannot supply all arguments
    /// to the nonce generation algorithm, use [`SecNonceBuilder`].
    ///
    /// Panics if the extra input length is greater than [`u32::MAX`].
    pub fn generate(
        nonce_seed: impl Into<NonceSeed>,
        seckey: impl Into<Scalar>,
        aggregated_pubkey: impl Into<Point>,
        message: impl AsRef<[u8]>,
        extra_input: impl AsRef<[u8]>,
    ) -> SecNonce {
        Self::build(nonce_seed)
            .with_seckey(seckey)
            .with_aggregated_pubkey(aggregated_pubkey)
            .with_message(&message)
            .with_extra_input(&extra_input)
            .build()
    }

    /// Samples a random pair of secret nonces directly from a CSPRNG.
    ///
    /// Whenever possible, we recommended to use [`SecNonce::generate`] or
    /// [`SecNonceBuilder`] instead of this method. If the RNG fails silently for
    /// any reason, it may result in duplicate `SecNonce` values, which will lead
    /// to private key exposure if this same nonce is used in more than one signing
    /// session.
    ///
    /// [`SecNonce::generate`] is more secure because it combines multiple sources of
    /// entropy to compute the final nonce.
    #[cfg(any(test, feature = "rand"))]
    pub fn random<R>(rng: &mut R) -> SecNonce
    where
        R: rand::RngCore + rand::CryptoRng,
    {
        SecNonce {
            k1: Scalar::random(rng),
            k2: Scalar::random(rng),
        }
    }

    /// Returns the corresponding public nonce for this secret nonce. The public nonce
    /// is safe to share with other signers.
    pub fn public_nonce(&self) -> PubNonce {
        PubNonce {
            R1: self.k1 * G,
            R2: self.k2 * G,
        }
    }
}

/// Represents a public nonce derived from a secret nonce. It is composed
/// of two public points, `R1` and `R2`, derived by base-point multiplying
/// the two scalars in a `SecNonce`.
///
/// `PubNonce` can be derived from a [`SecNonce`] using [`SecNonce::public_nonce`],
/// or it can be constructed manually with [`PubNonce::new`].
#[derive(Debug, Eq, PartialEq, Clone, Hash, Ord, PartialOrd)]
pub struct PubNonce {
    #[allow(missing_docs)]
    pub R1: Point,
    #[allow(missing_docs)]
    pub R2: Point,
}

impl PubNonce {
    /// Construct a new `PubNonce` from the given pair of public nonce points.
    pub fn new<T: Into<Point>>(R1: T, R2: T) -> PubNonce {
        PubNonce {
            R1: R1.into(),
            R2: R2.into(),
        }
    }
}

/// Represents a aggregate sum of public nonces derived from secret nonces.
///
/// `AggNonce` can be created by summing a collection of `PubNonce` points
/// by using [`AggNonce::sum`] or by making use of the
/// [`std::iter::Sum`](#impl-Sum<P>-for-AggNonce) implementation. An aggregated
/// nonce can also be constructed directly by using [`AggNonce::new`].
///
/// An aggregated nonce's points are allowed to be infinity (AKA the zero point).
/// If this occurs, then likely at least one signer is being mischevious.
/// To allow honest signers to identify those responsible, signing is allowed
/// to continue, and dishonest signers will reveal themselves once they are
/// required to provide their partial signatures.
#[derive(Debug, Eq, PartialEq, Clone, Hash, Ord, PartialOrd)]
pub struct AggNonce {
    #[allow(missing_docs)]
    pub R1: MaybePoint,
    #[allow(missing_docs)]
    pub R2: MaybePoint,
}

impl AggNonce {
    /// Construct a new `AggNonce` from the given pair of public nonce points.
    pub fn new<T: Into<MaybePoint>>(R1: T, R2: T) -> AggNonce {
        AggNonce {
            R1: R1.into(),
            R2: R2.into(),
        }
    }

    /// Aggregates many partial public nonces together into an aggregated nonce.
    ///
    /// ```
    /// use musig2::{AggNonce, PubNonce};
    ///
    /// let nonces: [PubNonce; 2] = [
    ///     "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798\
    ///      032DE2662628C90B03F5E720284EB52FF7D71F4284F627B68A853D78C78E1FFE93"
    ///         .parse()
    ///         .unwrap(),
    ///     "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61\
    ///      037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9"
    ///         .parse()
    ///         .unwrap(),
    /// ];
    ///
    /// let expected =
    ///     "02aebee092fe428c3b4c53993c3f80eecbf88ca935469b5bfcaabecb7b2afbb1a6\
    ///      03c923248ac1f639368bc82345698dfb445dca6024b9ba5a9bafe971bb5813964b"
    ///         .parse::<AggNonce>()
    ///         .unwrap();
    ///
    /// assert_eq!(musig2::AggNonce::sum(&nonces), expected);
    /// assert_eq!(musig2::AggNonce::sum(nonces), expected);
    /// ```
    pub fn sum<T, I>(nonces: I) -> AggNonce
    where
        T: std::borrow::Borrow<PubNonce>,
        I: IntoIterator<Item = T>,
    {
        let (r1s, r2s): (Vec<Point>, Vec<Point>) = nonces
            .into_iter()
            .map(|pubnonce| (pubnonce.borrow().R1, pubnonce.borrow().R2))
            .unzip();

        AggNonce {
            R1: Point::sum(r1s),
            R2: Point::sum(r2s),
        }
    }

    /// Computes the nonce coefficient `b`, used to create the final nonce and signatures.
    ///
    /// Most use-cases will not need to invoke this method. Instead use
    /// [`sign_solo`][crate::sign_solo] or [`sign_partial`][crate::sign_partial]
    /// to create signatures.
    pub fn nonce_coefficient<S>(
        &self,
        aggregated_pubkey: impl Into<Point>,
        message: impl AsRef<[u8]>,
    ) -> S
    where
        S: From<MaybeScalar>,
    {
        let hash: [u8; 32] = tagged_hashes::MUSIG_NONCECOEF_TAG_HASHER
            .clone()
            .chain_update(self.R1.serialize())
            .chain_update(self.R2.serialize())
            .chain_update(aggregated_pubkey.into().serialize_xonly())
            .chain_update(message.as_ref())
            .finalize()
            .into();

        S::from(MaybeScalar::reduce_from(&hash))
    }

    /// Computes the final public nonce point, published with the aggregated signature.
    /// If this point winds up at infinity (probably due to a mischevious signer), we
    /// instead return the generator point `G`.
    ///
    /// Most use-cases will not need to invoke this method. Instead use
    /// [`sign_solo`][crate::sign_solo] or [`sign_partial`][crate::sign_partial]
    /// to create signatures.
    pub fn final_nonce<P>(&self, nonce_coeff: impl Into<MaybeScalar>) -> P
    where
        P: From<Point>,
    {
        let nonce_coeff: MaybeScalar = nonce_coeff.into();
        let aggnonce_sum = self.R1 + (nonce_coeff * self.R2);
        P::from(match aggnonce_sum {
            MaybePoint::Infinity => Point::generator(),
            MaybePoint::Valid(p) => p,
        })
    }
}

mod encodings {
    use super::*;

    impl BinaryEncoding for SecNonce {
        type Serialized = [u8; 64];

        /// Returns the binary serialization of `SecNonce`, which serializes
        /// both inner scalar values into a fixed-length 64-byte array.
        ///
        /// Note that this serialization differs from the format suggested
        /// in BIP327, in that we do not include a public key.
        fn to_bytes(&self) -> Self::Serialized {
            let mut serialized = [0u8; 64];
            serialized[..32].clone_from_slice(&self.k1.serialize());
            serialized[32..].clone_from_slice(&self.k2.serialize());
            serialized
        }

        /// Parses a `SecNonce` from a serialized byte slice.
        /// This byte slice should be 64 bytes long, and encode two
        /// non-zero 256-bit scalars.
        ///
        /// We also accept 97-byte long slices, to be compatible with BIP327's
        /// suggested serialization format of `SecNonce`.
        fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError<Self>> {
            if bytes.len() != 64 && bytes.len() != 97 {
                return Err(DecodeError::bad_length(bytes.len()));
            }
            let k1 = Scalar::from_slice(&bytes[..32])?;
            let k2 = Scalar::from_slice(&bytes[32..64])?;
            Ok(SecNonce { k1, k2 })
        }
    }

    impl BinaryEncoding for PubNonce {
        type Serialized = [u8; 66];

        /// Returns the binary serialization of `PubNonce`, which serializes
        /// both inner points into a fixed-length 66-byte array.
        fn to_bytes(&self) -> Self::Serialized {
            let mut bytes = [0u8; 66];
            bytes[..33].clone_from_slice(&self.R1.serialize());
            bytes[33..].clone_from_slice(&self.R2.serialize());
            bytes
        }

        /// Parses a `PubNonce` from a serialized byte slice. This byte slice should
        /// be 66 bytes long, and encode two compressed, non-infinity curve points.
        fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError<Self>> {
            if bytes.len() != 66 {
                return Err(DecodeError::bad_length(bytes.len()));
            }
            let R1 = Point::from_slice(&bytes[..33])?;
            let R2 = Point::from_slice(&bytes[33..])?;
            Ok(PubNonce { R1, R2 })
        }
    }

    impl BinaryEncoding for AggNonce {
        type Serialized = [u8; 66];

        /// Returns the binary serialization of `AggNonce`, which serializes
        /// both inner points into a fixed-length 66-byte array.
        fn to_bytes(&self) -> Self::Serialized {
            let mut serialized = [0u8; 66];
            serialized[..33].clone_from_slice(&self.R1.serialize());
            serialized[33..].clone_from_slice(&self.R2.serialize());
            serialized
        }

        /// Parses an `AggNonce` from a serialized byte slice. This byte slice should
        /// be 66 bytes long, and encode two compressed (possibly infinity) curve points.
        fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError<Self>> {
            if bytes.len() != 66 {
                return Err(DecodeError::bad_length(bytes.len()));
            }
            let R1 = MaybePoint::from_slice(&bytes[..33])?;
            let R2 = MaybePoint::from_slice(&bytes[33..])?;
            Ok(AggNonce { R1, R2 })
        }
    }

    impl_encoding_traits!(SecNonce, 64, 97);
    impl_encoding_traits!(PubNonce, 66);
    impl_encoding_traits!(AggNonce, 66);

    // Do not implement Display for SecNonce.
    impl_hex_display!(PubNonce);
    impl_hex_display!(AggNonce);
}

impl<P> std::iter::Sum<P> for AggNonce
where
    P: std::borrow::Borrow<PubNonce>,
{
    /// Implements summation of partial public nonces into an aggregated nonce.
    ///
    /// ```
    /// use musig2::{AggNonce, PubNonce};
    ///
    /// let nonces = [
    ///     "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798\
    ///      032DE2662628C90B03F5E720284EB52FF7D71F4284F627B68A853D78C78E1FFE93"
    ///         .parse::<PubNonce>()
    ///         .unwrap(),
    ///     "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61\
    ///      037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9"
    ///         .parse::<PubNonce>()
    ///         .unwrap(),
    /// ];
    ///
    /// let expected =
    ///     "02aebee092fe428c3b4c53993c3f80eecbf88ca935469b5bfcaabecb7b2afbb1a6\
    ///      03c923248ac1f639368bc82345698dfb445dca6024b9ba5a9bafe971bb5813964b"
    ///         .parse::<AggNonce>()
    ///         .unwrap();
    ///
    /// assert_eq!(nonces.iter().sum::<AggNonce>(), expected);
    /// assert_eq!(nonces.into_iter().sum::<AggNonce>(), expected);
    /// ```
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = P>,
    {
        let refs = iter.collect::<Vec<P>>();
        AggNonce::sum(refs.iter().map(|nonce| nonce.borrow()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{testhex, KeyAggContext};

    #[test]
    fn test_nonce_generation() {
        const NONCE_GEN_VECTORS: &[u8] = include_bytes!("test_vectors/nonce_gen_vectors.json");

        #[derive(serde::Deserialize)]
        struct NonceGenTestCase {
            #[serde(rename = "rand", deserialize_with = "testhex::deserialize")]
            nonce_seed: [u8; 32],

            #[serde(rename = "sk")]
            seckey: Scalar,

            #[serde(rename = "aggpk", deserialize_with = "testhex::deserialize")]
            aggregated_pubkey: [u8; 32],

            #[serde(rename = "msg", deserialize_with = "testhex::deserialize")]
            message: Vec<u8>,

            #[serde(rename = "extra_in", deserialize_with = "testhex::deserialize")]
            extra_input: Vec<u8>,

            expected_secnonce: SecNonce,
            expected_pubnonce: PubNonce,
        }

        #[derive(serde::Deserialize)]
        struct NonceGenVectors {
            test_cases: Vec<NonceGenTestCase>,
        }

        let vectors: NonceGenVectors = serde_json::from_slice(NONCE_GEN_VECTORS)
            .expect("failed to parse test vectors from nonce_gen_vectors.json");

        for test_case in vectors.test_cases {
            let aggregated_pubkey =
                Point::lift_x(&test_case.aggregated_pubkey).unwrap_or_else(|_| {
                    panic!(
                        "invalid aggregated xonly pubkey in test vector: {}",
                        base16ct::lower::encode_string(&test_case.aggregated_pubkey)
                    )
                });
            let secnonce = SecNonce::generate(
                test_case.nonce_seed,
                test_case.seckey,
                aggregated_pubkey,
                &test_case.message,
                &test_case.extra_input,
            );

            assert_eq!(secnonce, test_case.expected_secnonce);
            assert_eq!(secnonce.public_nonce(), test_case.expected_pubnonce);
        }
    }

    #[test]
    fn test_nonce_aggregation() {
        const NONCE_AGG_VECTORS: &[u8] = include_bytes!("test_vectors/nonce_agg_vectors.json");

        #[derive(serde::Deserialize)]
        struct NonceAggError {
            signer: usize,
        }

        #[derive(serde::Deserialize)]
        struct NonceAggErrorTestCase {
            #[serde(rename = "pnonce_indices")]
            public_nonce_indexes: Vec<usize>,
            error: NonceAggError,
        }

        #[derive(serde::Deserialize)]
        struct ValidNonceAggTestCase {
            #[serde(rename = "pnonce_indices")]
            public_nonce_indexes: Vec<usize>,
            #[serde(rename = "expected")]
            aggregated_nonce: AggNonce,
        }

        #[derive(serde::Deserialize)]
        struct NonceAggTestVectors {
            #[serde(deserialize_with = "testhex::deserialize_vec", rename = "pnonces")]
            public_nonces: Vec<Vec<u8>>,

            valid_test_cases: Vec<ValidNonceAggTestCase>,
            error_test_cases: Vec<NonceAggErrorTestCase>,
        }

        let vectors: NonceAggTestVectors = serde_json::from_slice(NONCE_AGG_VECTORS)
            .expect("failed to parse test vectors from nonce_agg_vectors.json");

        for test_case in vectors.valid_test_cases {
            let nonces: Vec<PubNonce> = test_case
                .public_nonce_indexes
                .into_iter()
                .map(|i| {
                    PubNonce::from_bytes(&vectors.public_nonces[i]).unwrap_or_else(|_| {
                        panic!(
                            "used invalid nonce in valid test case: {}",
                            base16ct::lower::encode_string(&vectors.public_nonces[i])
                        )
                    })
                })
                .collect();

            let aggregated_nonce = AggNonce::sum(&nonces);

            assert_eq!(aggregated_nonce, test_case.aggregated_nonce);
        }

        for test_case in vectors.error_test_cases {
            for (signer_index, i) in test_case.public_nonce_indexes.into_iter().enumerate() {
                let nonce_result = PubNonce::try_from(vectors.public_nonces[i].as_slice());
                if signer_index == test_case.error.signer {
                    assert_eq!(
                        nonce_result,
                        Err(DecodeError::from(secp::errors::InvalidPointBytes))
                    );
                } else {
                    nonce_result.unwrap_or_else(|_| {
                        panic!("unexpected pub nonce parsing error for signer {}", i)
                    });
                }
            }
        }
    }

    #[test]
    fn nonce_reuse_demo() {
        let alice_seckey = Scalar::try_from([0x11; 32]).unwrap();
        let bob_seckey = Scalar::try_from([0x22; 32]).unwrap();

        let alice_pubkey = alice_seckey * G;
        let bob_pubkey = bob_seckey * G;

        let key_agg_ctx = KeyAggContext::new([alice_pubkey, bob_pubkey]).unwrap();

        let message = b"you betta not sign this twice";

        let alice_secnonce = SecNonceBuilder::new([0xAA; 32]).build();
        let bob_secnonce_1 = SecNonceBuilder::new([0xB1; 32]).build();
        let bob_secnonce_2 = SecNonceBuilder::new([0xB2; 32]).build();
        let bob_secnonce_3 = SecNonceBuilder::new([0xB3; 32]).build();

        // First signature
        let aggnonce_1 =
            AggNonce::sum([alice_secnonce.public_nonce(), bob_secnonce_1.public_nonce()]);
        let s1: MaybeScalar = crate::sign_partial(
            &key_agg_ctx,
            alice_seckey,
            alice_secnonce.clone(),
            &aggnonce_1,
            message,
        )
        .unwrap();

        // Second signature
        let aggnonce_2 =
            AggNonce::sum([alice_secnonce.public_nonce(), bob_secnonce_2.public_nonce()]);
        let s2: MaybeScalar = crate::sign_partial(
            &key_agg_ctx,
            alice_seckey,
            alice_secnonce.clone(),
            &aggnonce_2,
            message,
        )
        .unwrap();

        // Third signature
        let aggnonce_3 =
            AggNonce::sum([alice_secnonce.public_nonce(), bob_secnonce_3.public_nonce()]);
        let s3: MaybeScalar = crate::sign_partial(
            &key_agg_ctx,
            alice_seckey,
            alice_secnonce.clone(),
            &aggnonce_3,
            message,
        )
        .unwrap();

        // Alice gives Bob `(s1, s2, s3)`.
        // Bob can now compute Alice's secret key.
        let a = key_agg_ctx.key_coefficient(alice_pubkey).unwrap();
        let aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey();

        let b1: MaybeScalar = aggnonce_1.nonce_coefficient(aggregated_pubkey, message);
        let b2: MaybeScalar = aggnonce_2.nonce_coefficient(aggregated_pubkey, message);
        let b3: MaybeScalar = aggnonce_3.nonce_coefficient(aggregated_pubkey, message);

        let e1: MaybeScalar = crate::compute_challenge_hash_tweak(
            &aggnonce_1.final_nonce::<Point>(b1).serialize_xonly(),
            &key_agg_ctx.aggregated_pubkey(),
            message,
        );
        let e2: MaybeScalar = crate::compute_challenge_hash_tweak(
            &aggnonce_2.final_nonce::<Point>(b2).serialize_xonly(),
            &key_agg_ctx.aggregated_pubkey(),
            message,
        );
        let e3: MaybeScalar = crate::compute_challenge_hash_tweak(
            &aggnonce_3.final_nonce::<Point>(b3).serialize_xonly(),
            &key_agg_ctx.aggregated_pubkey(),
            message,
        );

        let b2_diff = (b2 - b1).unwrap();
        let b3_diff = (b3 - b1).unwrap();

        let top = (s3 - s1) * b2_diff - (s2 - s1) * b3_diff;
        let bottom = a * ((e3 - e1) * b2_diff + (e1 - e2) * b3_diff);
        let extracted_key = (top / bottom.unwrap()).unwrap();

        assert_eq!(extracted_key, alice_seckey);
    }
}
