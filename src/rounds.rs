use crate::errors::{RoundContributionError, RoundFinalizeError, SignerIndexError, SigningError};
use crate::{
    aggregate_partial_signatures, sign_partial, verify_partial, AggNonce, KeyAggContext,
    LiftedSignature, NonceSeed, PartialSignature, PubNonce, SecNonce, SecNonceSpices,
};

use secp::{Point, Scalar};

/// A simple state-machine which receives values of a given type `T` and
/// stores them in a vector at given indices. Returns an error if attempting
/// to fill a slot which is already taken by a different (not-equal) value.
struct Slots<T: Clone + Eq> {
    slots: Vec<Option<T>>,
    open_slots: Vec<usize>,
}

impl<T: Clone + Eq> Slots<T> {
    /// Create a new set of slots.
    fn new(expected_size: usize) -> Slots<T> {
        let mut slots = Vec::new();
        slots.resize(expected_size, None);
        let open_slots = Vec::from_iter(0..expected_size);
        Slots { slots, open_slots }
    }

    /// Add an item to a specific slot, returning an error if the
    /// slot is already taken by a different item. Idempotent.
    fn place(&mut self, value: T, index: usize) -> Result<(), RoundContributionError> {
        if index >= self.slots.len() {
            return Err(RoundContributionError::out_of_range(
                index,
                self.slots.len(),
            ));
        }

        // Support idempotence. Callers can place the same value into the same
        // slot index, which should be a no-op.
        if let Some(ref existing) = self.slots[index] {
            if &value == existing {
                return Ok(());
            } else {
                return Err(RoundContributionError::inconsistent_contribution(index));
            }
        }

        self.slots[index] = Some(value);
        self.open_slots
            .remove(self.open_slots.binary_search(&index).unwrap());
        Ok(())
    }

    /// Returns a slice listing all remaining open slots.
    fn remaining(&self) -> &[usize] {
        self.open_slots.as_ref()
    }

    /// Returns the full array of slot values in order.
    /// Returns `None` if any slot is not yet filled.
    fn finalize(self) -> Result<Vec<T>, RoundFinalizeError> {
        self.slots
            .into_iter()
            .map(|opt| opt.ok_or(RoundFinalizeError::Incomplete))
            .collect()
    }
}

/// A state machine which manages the first round of a MuSig2 signing session.
///
/// Its task is to collect [`PubNonce`]s one by one until all signers have provided
/// one, at which point a partial signature can be created on a message using an
/// internally cached [`SecNonce`].
///
/// By preventing cloning or copying, and by consuming itself after creating a
/// partial signature, `FirstRound`'s API is written to encourage that a
/// [`SecNonce`] should **never be reused.** Take care not to shoot yourself in
/// the foot by attempting to work around this restriction.
pub struct FirstRound {
    key_agg_ctx: KeyAggContext,
    signer_index: usize, // Our key's index in `key_agg_ctx`
    secnonce: SecNonce,  // Our secret nonce.
    pubnonce_slots: Slots<PubNonce>,
}

impl FirstRound {
    /// Start the first round of a MuSig2 signing session.
    ///
    /// Generates the nonce using the given random seed value, which can
    /// be any type that converts to `NonceSeed`. Usually this would
    /// either be a `[u8; 32]` or any type that implements [`rand::RngCore`]
    /// and [`rand::CryptoRng`], such as [`rand::rngs::OsRng`].
    /// If a static byte array is used as the seed, it should be generated
    /// using a cryptographically secure RNG and discarded after the `FirstRound`
    /// is created. Prefer using a [`rand::CryptoRng`] if possible, so that
    /// there is no possibility of reusing the same nonce seed in a new signing
    /// session.
    ///
    /// Returns an error if the given signer index is out of range.
    pub fn new<N>(
        key_agg_ctx: KeyAggContext,
        nonce_seed: N,
        signer_index: usize,
        spices: SecNonceSpices<'_>,
    ) -> Result<FirstRound, SignerIndexError>
    where
        NonceSeed: From<N>,
    {
        let signer_pubkey: Point = key_agg_ctx
            .get_pubkey(signer_index)
            .ok_or_else(|| SignerIndexError::new(signer_index, key_agg_ctx.pubkeys().len()))?;
        let aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey();

        let secnonce = SecNonce::build(nonce_seed)
            .with_pubkey(signer_pubkey)
            .with_aggregated_pubkey(aggregated_pubkey)
            .with_extra_input(&(signer_index as u32).to_be_bytes())
            .with_spices(spices)
            .build();

        let pubnonce = secnonce.public_nonce();

        let mut pubnonce_slots = Slots::new(key_agg_ctx.pubkeys().len());
        pubnonce_slots.place(pubnonce, signer_index).unwrap(); // never fails

        Ok(FirstRound {
            key_agg_ctx,
            secnonce,
            signer_index,
            pubnonce_slots,
        })
    }

    /// Returns the public nonce which should be shared with other signers.
    pub fn our_public_nonce(&self) -> PubNonce {
        self.secnonce.public_nonce()
    }

    /// Returns a slice of all signer indexes who we have yet to receive a
    /// [`PubNonce`] from. Note that since our nonce is generated and cached
    /// internally, this slice will never contain the signer index provided to
    /// [`FirstRound::new`]
    pub fn holdouts(&self) -> &[usize] {
        self.pubnonce_slots.remaining()
    }

    /// Adds a [`PubNonce`] to the internal state, registering it to a specific
    /// signer at a given index. Returns an error if the signer index is out
    /// of range, or if we already have a different nonce on-file for that signer.
    pub fn receive_nonce(
        &mut self,
        signer_index: usize,
        pubnonce: PubNonce,
    ) -> Result<(), RoundContributionError> {
        self.pubnonce_slots.place(pubnonce, signer_index)
    }

    /// Returns true once all public nonces have been received from every signer.
    pub fn is_complete(&self) -> bool {
        self.holdouts().len() == 0
    }

    /// Finishes the first round once all nonces are received, combining nonces
    /// into an aggregated nonce, and creating a partial signature using `seckey`
    /// on a given `message`, both of which are stored in the returned `SecondRound`.
    ///
    /// See [`SecondRound::aggregated_nonce`] to access the aggregated nonce,
    /// and [`SecondRound::our_signature`] to access the partial signature.
    ///
    /// This method intentionally consumes the `FirstRound`, to avoid accidentally
    /// reusing a secret-nonce.
    ///
    /// This method should only be invoked once [`is_complete`][Self::is_complete]
    /// returns true, otherwise it will fail. Can also return an error if partial
    /// signing fails, probably because the wrong secret key was given.
    ///
    /// For all partial signatures to be valid, everyone must naturally be signing the
    /// same message.
    pub fn finalize<S, M>(self, seckey: S, message: M) -> Result<SecondRound<M>, RoundFinalizeError>
    where
        Scalar: From<S>,
        M: AsRef<[u8]>,
    {
        let pubnonces: Vec<PubNonce> = self.pubnonce_slots.finalize()?;
        let aggnonce = pubnonces.iter().sum();

        let partial_signature = sign_partial(
            &self.key_agg_ctx,
            seckey,
            self.secnonce,
            &aggnonce,
            &message,
        )?;

        let mut partial_signature_slots = Slots::new(pubnonces.len());
        partial_signature_slots
            .place(partial_signature, self.signer_index)
            .unwrap(); // never fails

        let second_round = SecondRound {
            key_agg_ctx: self.key_agg_ctx,
            signer_index: self.signer_index,
            pubnonces,
            aggnonce,
            message,
            partial_signature_slots,
        };

        Ok(second_round)
    }

    /// As an alternative to collecting nonces and partial signatures one-by-one from
    /// everyone in the group, signers can opt instead to nominate an _aggregator node_
    /// whose duty is to collect nonces and signatures from all other signers, and
    /// then broadcast the aggregated signature once they receive all partial signatures.
    /// Doing this dramatically decreases the number of network round-trips required
    /// for large groups of signers, and doesn't require any trust in the aggregator node
    /// beyond the possibility that they may refuse to reveal the final signature.
    ///
    /// To use this API with a single aggregator node:
    ///
    /// - Instantiate the `FirstRound`.
    /// - Send the output of [`FirstRound::our_public_nonce`] to the aggregator.
    /// - The aggregator node should reply with an [`AggNonce`].
    /// - Once you receive the aggregated nonce, use [`FirstRound::sign_for_aggregator`]
    ///   instead of [`finalize`][Self::finalize] to consume the `FirstRound` and return a partial signature.
    /// - Send this partial signature to the aggregator.
    /// - The aggregator (if they are honest) will reply with the aggregated Schnorr signature, which
    ///   can be verified with [`verify_single`][crate::verify_single]
    ///
    /// [See the top-level crate documentation for an example](.#single-aggregator).
    pub fn sign_for_aggregator<S, M, T>(
        self,
        seckey: S,
        message: M,
        aggregated_nonce: &AggNonce,
    ) -> Result<T, SigningError>
    where
        Scalar: From<S>,
        M: AsRef<[u8]>,
        T: From<PartialSignature>,
    {
        sign_partial(
            &self.key_agg_ctx,
            seckey,
            self.secnonce,
            aggregated_nonce,
            &message,
        )
    }
}

/// A state machine to manage second round of a MuSig2 signing session.
///
/// This round handles collecting partial signatures one by one. Once
/// all signers have provided a signature, it can be finalized into
/// an aggregated Schnorr signature valid for the group's aggregated key.
pub struct SecondRound<M: AsRef<[u8]>> {
    key_agg_ctx: KeyAggContext,
    signer_index: usize,
    pubnonces: Vec<PubNonce>,
    aggnonce: AggNonce,
    message: M,
    partial_signature_slots: Slots<PartialSignature>,
}

impl<M: AsRef<[u8]>> SecondRound<M> {
    /// Returns the aggregated nonce built from the nonces provided in the first round.
    /// Signers who find themselves in an aggregator role can distribute this aggregated
    /// nonce to other signers to that they can produce an aggregated signature without
    /// 1:1 communication between every pair of signers.
    pub fn aggregated_nonce(&self) -> &AggNonce {
        &self.aggnonce
    }

    /// Returns the partial signature created during finalization of the first round.
    pub fn our_signature<T: From<PartialSignature>>(&self) -> T {
        self.partial_signature_slots.slots[self.signer_index]
            .map(T::from)
            .unwrap() // never fails
    }

    /// Returns a slice of all signer indexes from whom we have yet to receive a
    /// [`PartialSignature`]. Note that since our signature was constructed
    /// at the end of the first round, this slice will never contain the signer
    /// index provided to [`FirstRound::new`].
    pub fn holdouts(&self) -> &[usize] {
        self.partial_signature_slots.remaining()
    }

    /// Adds a [`PartialSignature`] to the internal state, registering it to a specific
    /// signer at a given index. Returns an error if the signature is not valid, or if
    /// the given signer index is out of range, or if we already have a different partial
    /// signature on-file for that signer.
    pub fn receive_signature<S>(
        &mut self,
        signer_index: usize,
        partial_signature: S,
    ) -> Result<(), RoundContributionError>
    where
        PartialSignature: From<S>,
    {
        let partial_signature = PartialSignature::from(partial_signature);
        let signer_pubkey: Point = self.key_agg_ctx.get_pubkey(signer_index).ok_or_else(|| {
            RoundContributionError::out_of_range(signer_index, self.key_agg_ctx.pubkeys().len())
        })?;

        verify_partial::<PartialSignature, _>(
            &self.key_agg_ctx,
            partial_signature,
            &self.aggnonce,
            signer_pubkey,
            &self.pubnonces[signer_index],
            &self.message,
        )
        .map_err(|_| RoundContributionError::invalid_signature(signer_index))?;

        self.partial_signature_slots
            .place(partial_signature, signer_index)?;

        Ok(())
    }

    /// Returns true once we have all partial signatures from the group.
    pub fn is_complete(&self) -> bool {
        self.holdouts().len() == 0
    }

    /// Finishes the second round once all partial signatures are received,
    /// combining signatures into an aggregated signature on the `message`
    /// given to [`FirstRound::finalize`].
    ///
    /// See [`SecondRound::aggregated_nonce`] to access the aggregated nonce,
    /// and [`SecondRound::our_signature`] to access the partial signature.
    ///
    /// This method intentionally consumes the `FirstRound`, to avoid accidentally
    /// reusing a secret-nonce.
    ///
    /// This method should only be invoked once [`is_complete`][Self::is_complete]
    /// returns true, otherwise it will fail. Can also return an error if partial
    /// signature aggregation fails, but if [`receive_signature`][Self::receive_signature]
    /// didn't complain, then finalizing will succeed with overwhelming probability.
    pub fn finalize<T>(self) -> Result<T, RoundFinalizeError>
    where
        T: From<LiftedSignature>,
    {
        let partial_signatures: Vec<PartialSignature> = self.partial_signature_slots.finalize()?;
        let final_signature = aggregate_partial_signatures(
            &self.key_agg_ctx,
            &self.aggnonce,
            partial_signatures,
            &self.message,
        )?;
        Ok(final_signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{verify_single, LiftedSignature};

    #[test]
    fn test_rounds_api() {
        // SETUP phase: key aggregation
        let seckeys = [
            "c52be0df73ef4354b2953deb9fdf77749b86946132176a33146f95d46fb065f3"
                .parse::<Scalar>()
                .unwrap(),
            "c731a6d52303c68f3efc6c4262c99269140809c39f651196d7264d225c25360d"
                .parse::<Scalar>()
                .unwrap(),
            "10e7721a3aa6de7a98cecdbd7c706c836a907ca46a43235a7b498b12498f98f0"
                .parse::<Scalar>()
                .unwrap(),
        ];

        let pubkeys = seckeys.iter().map(|sk| sk.base_point_mul());
        let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();

        // ROUND 1: nonces

        let message = "hello interwebz!";

        let mut first_rounds: Vec<FirstRound> = seckeys
            .iter()
            .enumerate()
            .map(|(i, &sk)| {
                FirstRound::new(
                    key_agg_ctx.clone(),
                    [0xAC; 32],
                    i,
                    SecNonceSpices::new().with_seckey(sk).with_message(&message),
                )
                .expect(&format!(
                    "failed to construct FirstRound machine for signer {}",
                    i
                ))
            })
            .collect();

        // Nobody's round should be complete right after it was created.
        for (i, round) in first_rounds.iter().enumerate() {
            assert!(
                !round.is_complete(),
                "round should not be complete without any nonces"
            );

            let mut expected_holdouts: Vec<usize> = (0..seckeys.len()).collect();
            expected_holdouts.remove(i);
            assert_eq!(
                round.holdouts(),
                expected_holdouts,
                "expected holdouts list to contain all other signers"
            )
        }

        let pubnonces: Vec<PubNonce> = first_rounds
            .iter()
            .map(|first_round| first_round.our_public_nonce())
            .collect();

        // Distribute the pubnonces.
        for (i, nonce) in pubnonces.iter().enumerate() {
            for round in first_rounds.iter_mut() {
                round
                    .receive_nonce(i, nonce.clone())
                    .expect(&format!("should receive nonce {} OK", i));

                let mut expected_holdouts: Vec<usize> = (0..seckeys.len()).collect();
                expected_holdouts.retain(|&j| j != round.signer_index && j > i);
                assert_eq!(round.holdouts(), expected_holdouts);

                // Confirm the round completes only once all nonces are received
                if expected_holdouts.len() == 0 {
                    assert!(
                        round.is_complete(),
                        "first round should have completed after signer {} receiving nonce {}",
                        round.signer_index,
                        i
                    );
                } else {
                    assert!(
                        !round.is_complete(),
                        "first round should not have completed after signer {} receiving nonce {}",
                        round.signer_index,
                        i
                    );
                }
            }
        }

        // The first round of nonce sharing should be complete now.
        for round in first_rounds.iter() {
            assert!(round.is_complete());
        }

        assert_eq!(
            first_rounds[0].receive_nonce(2, pubnonces[1].clone()),
            Err(RoundContributionError::inconsistent_contribution(2)),
            "receiving a different nonce at a previously used index should fail"
        );
        assert_eq!(
            first_rounds[0].receive_nonce(pubnonces.len() + 1, pubnonces[1].clone()),
            Err(RoundContributionError::out_of_range(
                pubnonces.len() + 1,
                pubnonces.len()
            )),
            "receiving a nonce at an invalid index should fail"
        );

        // ROUND 2: signing

        let mut second_rounds: Vec<SecondRound<&str>> = first_rounds
            .into_iter()
            .enumerate()
            .map(|(i, first_round)| -> SecondRound<&str> {
                first_round
                    .finalize(seckeys[i], message)
                    .expect(&format!("failed to finalize first round for signer {}", i))
            })
            .collect();

        for round in second_rounds.iter() {
            assert!(
                !round.is_complete(),
                "second round should not be complete yet"
            );
        }

        // Invalid partial signatures should be automatically rejected.
        {
            let wrong_nonce = SecNonce::build([0xCC; 32]).build();
            let invalid_partial_signature: PartialSignature = sign_partial(
                &key_agg_ctx,
                seckeys[0],
                wrong_nonce,
                &second_rounds[0].aggnonce,
                message,
            )
            .unwrap();

            assert_eq!(
                second_rounds[1].receive_signature(0, invalid_partial_signature),
                Err(RoundContributionError::invalid_signature(0)),
                "partial signature with invalid nonce should be rejected"
            );
        }

        let partial_signatures: Vec<PartialSignature> = second_rounds
            .iter()
            .map(|round| round.our_signature())
            .collect();

        // Distribute the partial signatures.
        for (i, &partial_signature) in partial_signatures.iter().enumerate() {
            for (receiver_index, round) in second_rounds.iter_mut().enumerate() {
                round
                    .receive_signature(i, partial_signature)
                    .expect(&format!("should receive partial signature {} OK", i));

                let mut expected_holdouts: Vec<usize> = (0..seckeys.len()).collect();
                expected_holdouts.retain(|&j| j != receiver_index && j > i);
                assert_eq!(round.holdouts(), expected_holdouts);

                // Confirm the round completes only once all signatures are received
                if expected_holdouts.len() == 0 {
                    assert!(
                        round.is_complete(),
                        "second round should have completed after signer {} receiving partial signature {}",
                        receiver_index,
                        i
                    );
                } else {
                    assert!(
                        !round.is_complete(),
                        "second round should not have completed after signer {} receiving partial signature {}",
                        receiver_index,
                        i
                    );
                }
            }
        }

        // The second round should be complete now that everyone has each
        // other's partial signatures.
        for round in second_rounds.iter() {
            assert!(round.is_complete());
        }

        // Test supplying signatures at wrong indices
        assert_eq!(
            second_rounds[0].receive_signature(2, partial_signatures[1].clone()),
            Err(RoundContributionError::invalid_signature(2)),
            "receiving a valid partial signature for the wrong signer should fail"
        );
        assert_eq!(
            second_rounds[0]
                .receive_signature(partial_signatures.len() + 1, partial_signatures[1].clone()),
            Err(RoundContributionError::out_of_range(
                partial_signatures.len() + 1,
                partial_signatures.len()
            )),
            "receiving a partial signature at an invalid index should fail"
        );

        // FINALIZATION: signatures can now be aggregated.
        let mut signatures: Vec<LiftedSignature> = second_rounds
            .into_iter()
            .enumerate()
            .map(|(i, round)| {
                round
                    .finalize()
                    .expect(&format!("failed to finalize second round for signer {}", i))
            })
            .collect();

        let last_sig = signatures.pop().unwrap();

        // All signers should output the same aggregated signature.
        for sig in signatures {
            assert_eq!(
                sig, last_sig,
                "some signers created different aggregated signatures"
            );
        }

        // and of course, the sig should be verifiable as a standard schnorr signature.
        let aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey();
        verify_single(aggregated_pubkey, last_sig, message)
            .expect("aggregated signature should be valid");
    }
}
