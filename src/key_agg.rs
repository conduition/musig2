use secp::{MaybePoint, MaybeScalar, Point, Scalar, G};
use std::collections::HashMap;

use crate::errors::{DecodeError, KeyAggError, TweakError};
use crate::{tagged_hashes, BinaryEncoding};

use sha2::Digest as _;
use subtle::ConstantTimeEq as _;

/// Represents an aggregated and tweaked public key.
///
/// A set of pubkeys can be aggregated into a `KeyAggContext` which
/// allows co-signers to cooperatively sign data.
///
/// `KeyAggContext` is essentially a sequence of pubkeys and tweaks
/// which determine a final aggregated key, with which the whole
/// cohort can cooperatively sign messages.
///
/// See [`KeyAggContext::with_tweak`] to learn
/// more about tweaking.
#[derive(Debug, Clone)]
pub struct KeyAggContext {
    /// The aggregated pubkey point `Q`.
    pub(crate) pubkey: Point,

    /// The component individual pubkeys in their original order.
    pub(crate) ordered_pubkeys: Vec<Point>,

    /// A map of pubkeys to their indexes in the [`ordered_pubkeys`][Self::ordered_pubkeys]
    /// field.
    pub(crate) pubkey_indexes: HashMap<Point, usize>,

    /// Cached key aggregation coefficients of individual pubkeys, in the
    /// same order as `ordered_pubkeys`.
    pub(crate) key_coefficients: Vec<MaybeScalar>,

    pub(crate) parity_acc: subtle::Choice, // false means g=1, true means g=n-1
    pub(crate) tweak_acc: MaybeScalar,     // None means zero.
}

impl KeyAggContext {
    /// Constructs a key aggregation context for a given set of pubkeys.
    /// The order in which the pubkeys are presented by the iterator will be preserved.
    /// A specific ordering of pubkeys will uniquely determine the aggregated public key.
    ///
    /// If the same keys are provided again in a different sorting order, a different
    /// aggregated pubkey will result. We recommended to sort keys ahead of time
    /// in some deterministic fashion before constructing a `KeyAggContext`.
    ///
    /// ```
    #[cfg_attr(feature = "secp256k1", doc = "use secp256k1::PublicKey;")]
    #[cfg_attr(
        all(feature = "k256", not(feature = "secp256k1")),
        doc = "use secp::Point as PublicKey;"
    )]
    /// use musig2::KeyAggContext;
    ///
    /// let mut pubkeys: [PublicKey; 3] = [
    ///     "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    ///         .parse()
    ///         .unwrap(),
    ///     "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
    ///         .parse()
    ///         .unwrap(),
    ///     "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66"
    ///         .parse()
    ///         .unwrap(),
    /// ];
    ///
    /// let key_agg_ctx = KeyAggContext::new(pubkeys)
    ///     .expect("error aggregating pubkeys");
    ///
    /// pubkeys.sort();
    /// let sorted_key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();
    ///
    /// let pk: PublicKey = key_agg_ctx.aggregated_pubkey();
    /// let pk_sorted: PublicKey = sorted_key_agg_ctx.aggregated_pubkey();
    /// assert_ne!(pk, pk_sorted);
    /// ```
    ///
    /// Multiple copies of the same public key are also accepted. They will
    /// be aggregated together and all signers will be expected to provide
    /// valid signatures from their key.
    ///
    /// Signers will be identified by their index from zero. The first key
    /// returned from the `pubkeys` iterator will be signer `0`. The second
    /// key will be index `1`, and so on. It is important that the caller can
    /// clearly identify every signer, so that they know who to blame if
    /// a signing contribution (e.g. a partial signature) is invalid.
    pub fn new<I, T>(pubkeys: I) -> Result<Self, KeyAggError>
    where
        I: IntoIterator<Item = T>,
        Point: From<T>,
    {
        let ordered_pubkeys: Vec<Point> = pubkeys.into_iter().map(Point::from).collect();
        assert!(ordered_pubkeys.len() > 0, "received empty set of pubkeys");
        assert!(
            ordered_pubkeys.len() <= u32::MAX as usize,
            "max number of pubkeys is u32::MAX"
        );

        // If all pubkeys are the same, `pk2` will be set to `None`, indicating
        // that every public key `X` should be tweaked with a coefficient `H_agg(L, X)`
        // to prevent collisions (See appendix B of the musig2 paper).
        let pk2: Option<&Point> = ordered_pubkeys[1..]
            .into_iter()
            .find(|pubkey| pubkey != &&ordered_pubkeys[0]);

        let pk_list_hash = hash_pubkeys(&ordered_pubkeys);

        let (tweaked_pubkeys, key_coefficients): (Vec<MaybePoint>, Vec<MaybeScalar>) =
            ordered_pubkeys
                .iter()
                .map(|&pubkey| {
                    let key_coeff =
                        compute_key_aggregation_coefficient(&pk_list_hash, &pubkey, pk2);
                    (pubkey * key_coeff, key_coeff)
                })
                .unzip();

        let aggregated_pubkey = MaybePoint::sum(tweaked_pubkeys).not_inf()?;

        let pubkey_indexes = HashMap::from_iter(
            ordered_pubkeys
                .iter()
                .copied()
                .enumerate()
                .map(|(i, pk)| (pk, i)),
        );

        Ok(KeyAggContext {
            pubkey: aggregated_pubkey,
            ordered_pubkeys,
            pubkey_indexes,
            key_coefficients,
            parity_acc: subtle::Choice::from(0),
            tweak_acc: MaybeScalar::Zero,
        })
    }

    /// Tweak the key aggregation context with a specific scalar tweak value.
    ///
    /// 'Tweaking' is the practice of committing a key to an agreed-upon scalar
    /// value, such as a SHA256 hash. In Bitcoin contexts, this is used for
    /// [taproot](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
    /// script commitments, or
    /// [BIP32 key derivation](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki).
    ///
    /// Signatures created using the resulting tweaked key aggregation context will be
    /// bound to this tweak value.
    ///
    /// A verifier can later prove that the signer(s) committed to this value
    /// if the `tweak` value was itself generated by committing to the public key,
    /// e.g. by hashing the aggregated public key.
    ///
    /// The `is_xonly` argument determines whether the tweak should be applied to
    /// the plain aggregated pubkey, or to the even-parity (i.e. x-only) aggregated
    /// pubkey. `is_xonly` should be true for applying Bitcoin taproot commitments,
    /// and false for applying BIP32 key derivation tweaks.
    ///
    /// Returns an error if the tweaked public key would be the point at infinity.
    ///
    /// ```
    #[cfg_attr(feature = "secp256k1", doc = "use secp256k1::{PublicKey, SecretKey};")]
    #[cfg_attr(
        all(feature = "k256", not(feature = "secp256k1")),
        doc = "use secp::{Point as PublicKey, Scalar as SecretKey};"
    )]
    /// use musig2::KeyAggContext;
    ///
    /// let pubkeys = [
    ///     "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    ///         .parse::<PublicKey>()
    ///         .unwrap(),
    ///     "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66"
    ///         .parse::<PublicKey>()
    ///         .unwrap(),
    /// ];
    ///
    /// let key_agg_ctx = KeyAggContext::new(pubkeys)
    ///     .unwrap()
    ///     .with_tweak(
    ///         "7931676703c0865d8b502dcdf1d956e86503796cfeabe33d12a918fbf408da05"
    ///             .parse::<SecretKey>()
    ///             .unwrap(),
    ///         false
    ///     )
    ///     .unwrap();
    ///
    /// let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey_untweaked();
    ///
    /// assert_eq!(
    ///     aggregated_pubkey.to_string(),
    ///     "0385eb6101982e142dba553cae437d08a82880fe9a22889c997f8e415a61b7a2d5"
    /// );
    pub fn with_tweak<T>(self, tweak: T, is_xonly: bool) -> Result<Self, TweakError>
    where
        Scalar: From<T>,
    {
        if is_xonly {
            self.with_xonly_tweak(tweak)
        } else {
            self.with_plain_tweak(tweak)
        }
    }

    /// Iteratively applies tweaks to the aggregated pubkey. See [`KeyAggContext::with_tweak`].
    pub fn with_tweaks<T>(
        mut self,
        tweaks: impl IntoIterator<Item = (T, bool)>,
    ) -> Result<Self, TweakError>
    where
        Scalar: From<T>,
    {
        for (tweak, is_xonly) in tweaks.into_iter() {
            self = self.with_tweak(tweak, is_xonly)?;
        }
        Ok(self)
    }

    /// Same as `self.with_tweak(tweak, false)`. See [`KeyAggContext::with_tweak`].
    pub fn with_plain_tweak<T>(self, tweak: T) -> Result<Self, TweakError>
    where
        Scalar: From<T>,
    {
        let tweak = Scalar::from(tweak);

        // Q' = Q + t*G
        let tweaked_pubkey = (self.pubkey + (tweak * G)).not_inf()?;

        // tacc' = t + tacc
        let new_tweak_acc = self.tweak_acc + tweak;

        Ok(KeyAggContext {
            pubkey: tweaked_pubkey,
            tweak_acc: new_tweak_acc,
            ..self
        })
    }

    /// Same as `self.with_tweak(tweak, true)`. See [`KeyAggContext::with_tweak`].
    pub fn with_xonly_tweak<T>(self, tweak: T) -> Result<Self, TweakError>
    where
        Scalar: From<T>,
    {
        // if has_even_y(Q): g = 1  (Same as a plain tweak.)
        // else: g = n - 1
        if self.pubkey.has_even_y() {
            return self.with_plain_tweak(tweak);
        }

        let tweak = Scalar::from(tweak);

        // Q' = g*Q + t*G
        //
        // Negating the pubkey point Q is the same as multiplying it
        // by (n-1), but is much faster.
        let tweaked_pubkey = (tweak * G - self.pubkey).not_inf()?;

        // tacc' = g*tacc + t
        //
        // Negating the tweak accumulator is the same as multiplying it
        // by (n-1), but is much faster.
        let new_tweak_acc = tweak - self.tweak_acc;

        Ok(KeyAggContext {
            pubkey: tweaked_pubkey,
            parity_acc: !self.parity_acc,
            tweak_acc: new_tweak_acc,
            ..self
        })
    }

    /// Tweak the key aggregation context with the given tapscript merkle tree root hash.
    ///
    /// This is used to commit the key aggregation context to a specific tree of Bitcoin
    /// taproot scripts, determined by the given `merkle_root` hash. Computing the merkle
    /// tree root is outside the scope of this package. See
    /// [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
    /// for details of how tapscript merkle trees are constructed.
    ///
    /// The tweak value `t` is computed as:
    ///
    /// ```notrust
    /// prefix = sha256(b"TapTweak")
    /// tweak_hash = sha256(
    ///     prefix,
    ///     prefix,
    ///     self.aggregated_pubkey().serialize_xonly(),
    ///     merkle_root
    /// )
    /// t = int(tweak_hash)
    /// ```
    ///
    /// Note that the _current tweaked aggregated pubkey_ is hashed, not
    /// the plain untweaked pubkey.
    pub fn with_taproot_tweak(self, merkle_root: &[u8; 32]) -> Result<Self, TweakError> {
        // t = int(H_taptweak(xbytes(P), k))
        let tweak_hash: [u8; 32] = tagged_hashes::TAPROOT_TWEAK_TAG_HASHER
            .clone()
            .chain_update(&self.pubkey.serialize_xonly())
            .chain_update(&merkle_root)
            .finalize()
            .into();

        let tweak = Scalar::try_from(tweak_hash).map_err(|_| TweakError)?;
        self.with_xonly_tweak(tweak)
    }

    /// Returns the aggregated public key, converted to a given type.
    ///
    /// ```
    #[cfg_attr(feature = "secp256k1", doc = "use secp256k1::PublicKey;")]
    #[cfg_attr(
        all(feature = "k256", not(feature = "secp256k1")),
        doc = "use secp::Point as PublicKey;"
    )]
    /// use musig2::KeyAggContext;
    ///
    /// let pubkeys: Vec<PublicKey> = vec![
    ///     /* ... */
    /// #   "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    /// #       .parse()
    /// #       .unwrap(),
    /// #   "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
    /// #       .parse()
    /// #       .unwrap(),
    /// #   "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66"
    /// #       .parse()
    /// #       .unwrap(),
    /// ];
    ///
    /// let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();
    /// let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
    /// assert_eq!(
    ///     aggregated_pubkey.to_string(),
    ///     "0290539eede565f5d054f32cc0c220126889ed1e5d193baf15aef344fe59d4610c"
    /// )
    /// ```
    ///
    /// If any tweaks have been applied to the `KeyAggContext`, the the pubkey
    /// returned by this method will be the tweaked aggregate public key, and
    /// not the plain aggregated key.
    pub fn aggregated_pubkey<T: From<Point>>(&self) -> T {
        T::from(self.pubkey)
    }

    /// Returns the aggregated pubkey without any tweaks.
    ///
    /// ```
    #[cfg_attr(feature = "secp256k1", doc = "use secp256k1::{PublicKey, SecretKey};")]
    #[cfg_attr(
        all(feature = "k256", not(feature = "secp256k1")),
        doc = "use secp::{Point as PublicKey, Scalar as SecretKey};"
    )]
    /// use musig2::KeyAggContext;
    ///
    /// let pubkeys = [
    ///     /* ... */
    /// #   "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    /// #       .parse::<PublicKey>()
    /// #       .unwrap(),
    /// #   "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66"
    /// #       .parse::<PublicKey>()
    /// #       .unwrap(),
    /// ];
    ///
    /// let key_agg_ctx = KeyAggContext::new(pubkeys)
    ///     .unwrap()
    ///     .with_xonly_tweak(
    ///         "7931676703c0865d8b502dcdf1d956e86503796cfeabe33d12a918fbf408da05"
    ///             .parse::<SecretKey>()
    ///             .unwrap()
    ///     )
    ///     .unwrap();
    ///
    /// let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey_untweaked();
    ///
    /// assert_eq!(
    ///     aggregated_pubkey,
    ///     KeyAggContext::new(pubkeys).unwrap().aggregated_pubkey(),
    /// )
    /// ```
    pub fn aggregated_pubkey_untweaked<T: From<Point>>(&self) -> T {
        let untweaked = (self.pubkey - self.tweak_acc * G).negate_if(self.parity_acc);
        T::from(untweaked.unwrap()) // Can never be infinity
    }

    /// Returns the sum of all tweaks applied so far to this `KeyAggContext`.
    /// Returns `None` if the tweak sum is zero i.e. if no tweaks have been
    /// applied, or if the tweaks canceled each other out (by summing to zero).
    pub fn tweak_sum<T: From<Scalar>>(&self) -> Option<T> {
        self.tweak_acc.into_option().map(T::from)
    }

    /// Returns a read-only reference to the ordered set of public keys
    /// which this `KeyAggContext` was created with.
    pub fn pubkeys(&self) -> &[Point] {
        &self.ordered_pubkeys
    }

    /// Looks up the index of a given pubkey in the key aggregation group.
    /// Returns `None` if the key is not a member of the group.
    pub fn pubkey_index<P>(&self, pubkey: P) -> Option<usize>
    where
        Point: From<P>,
    {
        self.pubkey_indexes.get(&Point::from(pubkey)).copied()
    }

    /// Returns the public key for a given signer's index.
    ///
    /// Keys are best identified by their index from zero, because
    /// MuSig allows more than one signer to share the same public key.
    pub fn get_pubkey<T: From<Point>>(&self, index: usize) -> Option<T> {
        self.ordered_pubkeys.get(index).copied().map(T::from)
    }

    /// Finds the key coefficient for a given public key. Returns `None` if
    /// the given `pubkey` is not part of the aggregated key. This coefficient
    /// is the same for any two copies of the same public key.
    ///
    /// Key coefficients are multiplicative tweaks applied to each public key
    /// in an aggregated MuSig key. They prevent rogue key attacks by ensuring that
    /// signers cannot effectively compute their public key as a function of the
    /// pubkeys of other signers.
    ///
    /// The key coefficient is computed by hashing the public key `X` with a hash of
    /// the ordered set of all public keys in the signing group, denoted `L`.
    /// `KeyAggContext` caches these coefficients on instantiation.
    pub(crate) fn key_coefficient(&self, pubkey: &Point) -> Option<MaybeScalar> {
        self.ordered_pubkeys
            .iter()
            .zip(&self.key_coefficients)
            .find_map(|(candidate_pk, coeff)| {
                if candidate_pk == pubkey {
                    Some(*coeff)
                } else {
                    None
                }
            })
    }
}

fn hash_pubkeys<P: std::borrow::Borrow<Point>>(ordered_pubkeys: &[P]) -> [u8; 32] {
    let mut h = tagged_hashes::KEYAGG_LIST_TAG_HASHER.clone();
    for pubkey in ordered_pubkeys {
        h.update(&pubkey.borrow().serialize());
    }
    h.finalize().into()
}

fn compute_key_aggregation_coefficient(
    pk_list_hash: &[u8; 32],
    pubkey: &Point,
    pk2: Option<&Point>,
) -> MaybeScalar {
    if pk2.is_some_and(|pk2| pubkey == pk2) {
        return MaybeScalar::one();
    }

    let hash: [u8; 32] = tagged_hashes::KEYAGG_COEFF_TAG_HASHER
        .clone()
        .chain_update(&pk_list_hash)
        .chain_update(&pubkey.serialize())
        .finalize()
        .into();

    MaybeScalar::reduce_from(&hash)
}

impl PartialEq for KeyAggContext {
    fn eq(&self, other: &Self) -> bool {
        self.ordered_pubkeys == other.ordered_pubkeys
            && bool::from(self.parity_acc.ct_eq(&other.parity_acc))
            && self.tweak_acc == other.tweak_acc
    }
}

impl Eq for KeyAggContext {}

impl BinaryEncoding for KeyAggContext {
    type Serialized = Vec<u8>;

    /// Serializes a key aggregation context object into binary format.
    ///
    /// This is a variable-length encoding of the following fields:
    ///
    /// - `header_byte` (1 byte)
    ///     - Lowest order bit is set if the parity of the aggregated pubkey should
    ///     be negated upon deserialization (due to use of "x-only" tweaks).
    ///     - Second lowest order bit is set if there is an accumulated tweak value
    ///       present in the serialization.
    /// - `tweak_acc` \[optional\] (32 bytes)
    ///     - A non-zero scalar representing the accumulated value of prior tweaks.
    ///     - Present only if `header_byte & 0b10 != 0`.
    /// - `n_pubkey` (4 bytes)
    ///     - Big-endian encoded `u32`, describing the number of pubkeys which are
    ///       to follow.
    /// - `ordered_pubkeys` (33 * `n_pubkey` bytes)
    ///     - The public keys needed to reconstruct the `KeyAggContext`, in the same
    ///       order in which they were originally presented.
    ///
    /// This is a custom data format, not drawn from any standards. An identical
    /// `KeyAggContext` can be reconstructed from this binary representation using
    /// [`KeyAggContext::from_bytes`].
    ///
    /// This is also the serialization implemented for [`serde::Serialize`] and
    /// [`serde::Deserialize`] if the `serde` feature of this crate is enabled.
    fn to_bytes(&self) -> Self::Serialized {
        let parity_acc_bit = self.parity_acc.unwrap_u8();
        let tweak_acc_bit = u8::from(!self.tweak_acc.is_zero());

        let n_pubkey = self.ordered_pubkeys.len();
        let total_len = 1 + 4 + (32 * (tweak_acc_bit as usize)) + (n_pubkey * 33);

        let mut serialized = Vec::<u8>::with_capacity(total_len);

        let header_byte = (tweak_acc_bit << 1) | parity_acc_bit;
        serialized.push(header_byte);

        if tweak_acc_bit != 0 {
            serialized.extend_from_slice(&self.tweak_acc.serialize());
        }

        serialized.extend_from_slice(&(n_pubkey as u32).to_be_bytes());
        for pubkey in self.ordered_pubkeys.iter() {
            serialized.extend_from_slice(&pubkey.serialize());
        }

        serialized
    }

    /// Deserializes a `KeyAggContext` from its binary serialization.
    /// See [`KeyAggContext::to_bytes`] for a description of the
    /// expected binary format.
    fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError<Self>> {
        // minimum length: 1 byte header + 4 byte n_pubkey + 33 byte pubkey
        if bytes.len() < 38 {
            return Err(DecodeError::bad_length(bytes.len()));
        }

        let header_byte = bytes[0];
        let parity_acc = subtle::Choice::from(header_byte & 1);
        let mut cursor: usize = 1;

        // Decode 32-byte tweak_acc if present
        let tweak_acc = if header_byte & 0b10 != 0 {
            // only non-zero tweak accumulators are accepted in deserialization
            let tweak_acc = Scalar::from_slice(&bytes[cursor..cursor + 32])?;
            cursor += 32;
            MaybeScalar::Valid(tweak_acc)
        } else {
            MaybeScalar::Zero
        };

        let n_pubkey_bytes = <[u8; 4]>::try_from(&bytes[cursor..cursor + 4]).unwrap();
        let n_pubkey = u32::from_be_bytes(n_pubkey_bytes) as usize;
        cursor += 4;

        // wrong number of bytes remaining for the specified number of pubkeys.
        if bytes.len() - cursor != n_pubkey * 33 {
            return Err(DecodeError::bad_length(bytes.len()));
        }

        let pubkeys: Vec<Point> = bytes[cursor..]
            .chunks_exact(33)
            .map(Point::from_slice)
            .collect::<Result<_, _>>()?;

        let mut key_agg_ctx = KeyAggContext::new(pubkeys)?;
        key_agg_ctx.parity_acc = parity_acc;

        if bool::from(parity_acc) {
            key_agg_ctx.pubkey = -key_agg_ctx.pubkey;
        }

        match tweak_acc {
            MaybeScalar::Zero => Ok(key_agg_ctx),
            MaybeScalar::Valid(t) => Ok(key_agg_ctx.with_plain_tweak(t)?),
        }
    }
}

impl_encoding_traits!(KeyAggContext);
impl_hex_display!(KeyAggContext);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhex;

    #[test]
    fn test_key_aggregation() {
        const KEY_AGGREGATION_VECTORS: &[u8] = include_bytes!("test_vectors/key_agg_vectors.json");

        #[derive(serde::Deserialize)]
        struct ValidTestCase {
            pub key_indices: Vec<usize>,

            #[serde(deserialize_with = "testhex::deserialize")]
            pub expected: [u8; 32],
        }

        #[derive(serde::Deserialize)]
        struct KeyAggregationVectors {
            #[serde(deserialize_with = "testhex::deserialize_vec")]
            pub pubkeys: Vec<[u8; 33]>,

            pub valid_test_cases: Vec<ValidTestCase>,
        }

        let vectors: KeyAggregationVectors = serde_json::from_slice(KEY_AGGREGATION_VECTORS)
            .expect("failed to load key aggregation test vectors");

        for test_case in vectors.valid_test_cases {
            let pubkeys: Vec<Point> = test_case
                .key_indices
                .into_iter()
                .map(|i| {
                    Point::try_from(&vectors.pubkeys[i])
                        .expect("failed to parse valid public key string")
                })
                .collect();

            let aggregated_pubkey: Point = KeyAggContext::new(pubkeys)
                .expect("failed to aggregated valid pubkeys")
                .aggregated_pubkey();

            assert_eq!(aggregated_pubkey.serialize_xonly(), test_case.expected);
        }
    }

    #[test]
    fn test_aggregation_context_tweaks() {
        let pubkeys: [Point; 3] = [
            "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"
                .parse()
                .unwrap(),
            "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
                .parse()
                .unwrap(),
            "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
                .parse()
                .unwrap(),
        ];

        let ctx = KeyAggContext::new(pubkeys)
            .expect("failed to generate key aggregation context")
            .with_xonly_tweak(
                "E8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BB"
                    .parse::<Scalar>()
                    .unwrap(),
            )
            .expect("error while tweaking KeyAggContext")
            .with_xonly_tweak(
                "AE2EA797CC0FE72AC5B97B97F3C6957D7E4199A167A58EB08BCAFFDA70AC0455"
                    .parse::<Scalar>()
                    .unwrap(),
            )
            .expect("error while tweaking KeyAggContext")
            .with_plain_tweak(
                "F52ECBC565B3D8BEA2DFD5B75A4F457E54369809322E4120831626F290FA87E0"
                    .parse::<Scalar>()
                    .unwrap(),
            )
            .expect("error while tweaking KeyAggContext")
            .with_plain_tweak(
                "1969AD73CC177FA0B4FCED6DF1F7BF9907E665FDE9BA196A74FED0A3CF5AEF9D"
                    .parse::<Scalar>()
                    .unwrap(),
            )
            .expect("error while tweaking KeyAggContext");

        assert_eq!(
            ctx.pubkey,
            "0269434B39A026A4AAC9E6C1AEBDD3993FFA581C8F7F21B6FAAE15608057F5CE85"
                .parse::<Point>()
                .unwrap()
        );
        assert_eq!(bool::from(ctx.parity_acc), true);
        assert_eq!(
            ctx.tweak_acc,
            "A5BEB2D09000E2391E98EEBC8AA80CD4FB13845DC75B673D8466609410627D0B"
                .parse()
                .unwrap()
        );
    }
    #[test]
    fn key_agg_ctx_serialization() {
        struct KeyAggSerializationTest {
            pubkeys: Vec<&'static str>,
            tweaks: Vec<(&'static str, bool)>,
            serialized_hex: &'static str,
        }

        let serialization_tests = [
            KeyAggSerializationTest {
                pubkeys: vec!["03d6f09ede845037a2396b9877bd6105be437488fad29dcac6576cdb3610f3ab66"],
                tweaks: vec![],
                serialized_hex:
                    "000000000103d6f09ede845037a2396b9877bd6105be437488fad29dcac6576cdb3610f3ab66",
            },
            KeyAggSerializationTest {
                pubkeys: vec![
                    "0368288652632d5402d5ae3cb8d4094cb006aa2940156ff5dc4735d1445dfe1b34",
                    "02c65e684ab27c879f46f47064acf80f2c4590fb6edf7932a79b973246c7edd331",
                    "02d1b04674aaf6966af91201307b31501c56e6fdc41cd146b9e33912ec6e5182a2",
                ],
                tweaks: vec![],
                serialized_hex:
                    "00000000030368288652632d5402d5ae3cb8d4094cb006aa2940156ff5dc4735d1445dfe1b\
                     3402c65e684ab27c879f46f47064acf80f2c4590fb6edf7932a79b973246c7edd33102d1b0\
                     4674aaf6966af91201307b31501c56e6fdc41cd146b9e33912ec6e5182a2",
            },
            KeyAggSerializationTest {
                pubkeys: vec![
                    "032dd0f586175a1aa4c2fb9d01ec8d883de009d994f0db6a1f8ff75c4362e50c8a",
                    "03b68eede67797f8bd6b7d4adf6138942f344c2973e3e88ad254aedece82a144da",
                ],
                tweaks: vec![(
                    "79441652a4864a0545fa1588af4e8dd7895ddb45c1cf15a7e05d3e0d9fb86c9b",
                    true,
                )],
                serialized_hex:
                    "0279441652a4864a0545fa1588af4e8dd7895ddb45c1cf15a7e05d3e0d9fb86c9b00000002\
                     032dd0f586175a1aa4c2fb9d01ec8d883de009d994f0db6a1f8ff75c4362e50c8a03b68eed\
                     e67797f8bd6b7d4adf6138942f344c2973e3e88ad254aedece82a144da",
            },
            KeyAggSerializationTest {
                pubkeys: vec![
                    "025027dab744f11eafb6529c8f7cb4b2390883b55a76cf412bf49c5e39df755c3e",
                    "030413712ed74027795832e78457020aeff0e73624327c6d321737881078b780dd",
                ],
                tweaks: vec![
                    (
                        "d0f447289a190a50832e5daf723b0d01a58441ca465743d2db8d3c4baae37cc8",
                        false,
                    ),
                    (
                        "cd9aa8433e17b3c07c3241592e62e7169aa7ee98cb14e95ec47f41ea4eda9ddf",
                        false,
                    ),
                ],
                serialized_hex:
                    "029e8eef6bd830be10ff609f08a09df419857d537c62238cf5e03a1fa92987d96600000002\
                     025027dab744f11eafb6529c8f7cb4b2390883b55a76cf412bf49c5e39df755c3e030413712\
                     ed74027795832e78457020aeff0e73624327c6d321737881078b780dd",
            },
            KeyAggSerializationTest {
                pubkeys: vec![
                    "0355d7de59c20355f9d8b14ccb60998983e9d73b38f64c9b9f2c4f868c0a7ac02f",
                    "039582f6f17f99784bc6de6e5664ef5f69eb1bf0dc151d824b19481ab0717c0cd5",
                ],
                tweaks: vec![
                    (
                        "55542efaf2708bbde8d36dec4b2ac4a698d30d2320ea4e373e31b79d803a8633",
                        true,
                    ),
                    (
                        "09a7200a86d56e24ca0d23b64eb25ba4458b2834ceaa6506319e10e4e605e2db",
                        false,
                    ),
                    (
                        "5dc0cf7ce9bf937ccbf6167d0c1ba02b9ae2a615ff52142e3b932d332ab699f4",
                        true,
                    ),
                    (
                        "42cc20f9df78fc1ca2fa83d03942bae507f74716d68304d008c54eade89cafd4",
                        false,
                    ),
                ],
                serialized_hex:
                    "034191a1714ff295b6bc1008aaab813ac5c47bb7d4e64065c0d488b35ead12e0ba\
                     000000020355d7de59c20355f9d8b14ccb60998983e9d73b38f64c9b9f2c4f868c\
                     0a7ac02f039582f6f17f99784bc6de6e5664ef5f69eb1bf0dc151d824b19481ab0717c0cd5",
            },
            KeyAggSerializationTest {
                pubkeys: vec![
                    "0317aec4eea8a2b02c38e6b67c26015d16c82a3a44abc28d1def124c1f79786fc5",
                    "02947f02de710d51280b861c101bcee4e06f09a5a119694677818dce59354b62a8",
                    "023b89ea0ef047b6f6a2aa826e869c9538fe2f011f4df5a5422af4c24c19f22856",
                ],
                tweaks: vec![
                    (
                        "ffa540e2d3df158dfb202fc1a2cbb20c4920ba35e8f75bb11101bfa47d71449a",
                        true,
                    ),
                    (
                        "fdc5d9e884851a8a5dd1e8c2015b15e9aed45807d05eea1b897421770351e09e",
                        true,
                    ),
                    (
                        "2743a21ac21cc46843e478ce094663c08103f9ab88c53850f4b3280ded4d75c1",
                        true,
                    ),
                ],
                serialized_hex:
                    "0229d8874f69b8944feaf2604a651f9bc7fe6ca13b2e0032fbd9e2040c0cf6d30b0000000\
                     30317aec4eea8a2b02c38e6b67c26015d16c82a3a44abc28d1def124c1f79786fc502947f\
                     02de710d51280b861c101bcee4e06f09a5a119694677818dce59354b62a8023b89ea0ef04\
                     7b6f6a2aa826e869c9538fe2f011f4df5a5422af4c24c19f22856",
            },
        ];

        for test_case in serialization_tests {
            let pubkeys: Vec<Point> = test_case
                .pubkeys
                .into_iter()
                .map(|s| s.parse().unwrap())
                .collect();

            let tweaks: Vec<(Scalar, bool)> = test_case
                .tweaks
                .into_iter()
                .map(|(s, is_xonly)| (s.parse().unwrap(), is_xonly))
                .collect();

            let expected_serialization =
                base16ct::mixed::decode_vec(test_case.serialized_hex).unwrap();

            let key_agg_ctx = KeyAggContext::new(pubkeys)
                .unwrap()
                .with_tweaks(tweaks)
                .unwrap();

            let serialized_ctx = key_agg_ctx.to_bytes();
            assert_eq!(
                serialized_ctx, expected_serialization,
                "serialized KeyAggContext does not match expected"
            );

            let deserialized_ctx = KeyAggContext::from_bytes(&serialized_ctx)
                .expect("error deserializing KeyAggContext");

            assert_eq!(
                deserialized_ctx, key_agg_ctx,
                "deserialized KeyAggContext does not match original"
            );

            // Test serde deserialization
            let _: KeyAggContext =
                serde_json::from_str(&format!("\"{}\"", test_case.serialized_hex))
                    .expect("failed to deserialize KeyAggContext with serde");
        }
    }
}
