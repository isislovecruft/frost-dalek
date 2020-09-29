// -*- mode: rust; -*-
//
// This file is part of dalek-frost.
// Copyright (c) 2020 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! FROST signatures and their creation.

#[cfg(feature = "alloc")]
use alloc::collections::HashMap;
#[cfg(feature = "alloc")]
use alloc::collections::hash_map::Values;

#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(feature = "std")]
use std::collections::hash_map::Values;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use sha2::Digest;
use sha2::Sha512;

use crate::keygen::GroupKey;
use crate::keygen::PublicShare as IndividualPublicKey;
use crate::keygen::SecretKey;
use crate::parameters::Parameters;
use crate::precomputation::CommitmentShare;

// assume central aggregator does coordination

// nonces should be explicitly drop()ed from memory (and probably even zeroed
// first)

// XXX Nonce reuse is catastrophic and results in obtaining an individual
//     signer's long-term secret key; it must be prevented at all costs.

/// An individual signer in the threshold signature scheme.
// XXX need sorting method
// XXX need a constructor
pub struct Signer {
    /// The participant index of this signer.
    pub participant_index: u32,
    /// One of the commitments that were published by each signing participant
    /// in the pre-computation phase.
    pub published_commitment_share: (RistrettoPoint, RistrettoPoint),
}

/// A partially-constructed threshold signature, made by each participant in the
/// signing protocol during the first phase of a signature creation.
pub struct PartialThresholdSignature {
    pub(crate) index: u32,
    pub(crate) z: Scalar,
}

/// A complete, aggregated threshold signature.
pub struct ThresholdSignature(pub(crate) Scalar, pub(crate) Scalar);

// XXX I hate this so much.
//
// XXX TODO there might be a more efficient way to optimise this data structure
//     and its algorithms?
struct SignerRs (pub(crate) HashMap<u32, RistrettoPoint>);

impl SignerRs {
    pub(crate) fn new() -> Self {
        SignerRs(Hashmap::new())
    }

    // XXX [CFRG] Since the sorting order matters for the public API, both it
    // and the canonicalisation of the participant indices needs to be
    // specified.
    pub(crate) fn insert(&mut self, index: &u32, point: &RistrettoPoint) {
        self.0.insert(index.to_be_bytes(), point);
    }

    pub(crate) fn get(&self, index: &u32) -> Option<RistrettoPoint> {
        self.0.get(index.to_be_bytes())
    }

    pub(crate) fn sorted(&self) -> Vec<(u32, RistrettoPoint)> {
        let mut sorted: Vec<(u32, RistrettoPoint)> = Vec::with_capacity(self.0.len());

        for (i, point) in self.0.iter() {
            let index = u32::from_be_bytes(&i);
            sorted.insert(index, (index, point));
        }
        sorted
    }

    pub(crate) fn values(&self) -> Values<'_, u32, RistrettoPoint> {
        self.0.values()
    }
}

fn compute_binding_factors_and_group_commitment(
    message: &[u8],
    signers: &Vec<Signer>,
) -> (Vec<Scalar>, SignerRs)
{
	let mut binding_factors: Vec<Scalar> = Vec::with_capacity(signers.len());
    let mut Rs: SignerRs = SignerRs::new(); // XXX can we optimise size?

    for signer in signers.iter() {
        let hiding = signer.published_commitment_share.0;
        let binding = signer.published_commitment_share.1;

        // XXX [CFRG] Should the hash function be hardcoded in the RFC or should
        // we instead specify the output/block size?
        //
        // XXX [PAPER] Does the proof still work with sponges?
        let mut h1 = Sha512::new();

        // [DIFFERENT_TO_PAPER] I added a context string.
        h1.update(b"FROST-SHA512");
        h1.update(signer.participant_index.to_be_bytes());
        h1.update(message);
        h1.update(hiding.compress().as_bytes());
        h1.update(binding.compress().as_bytes());

        let binding_factor = Scalar::from_hash(h1);

        // THIS IS THE MAGIC STUFF ↓↓↓
        Rs.insert(signer.participant_index, hiding + (binding_factor * binding));

	    binding_factors.push(binding_factor);
    }

    (binding_factors, Rs)
}

fn compute_challenge(message: &[u8], R: &RistrettoPoint) -> Scalar {
    let mut h2 = Sha512::new();

    h2.update(message);
    h2.update(R.compress().as_bytes());

    Scalar::from_hash(h2)
}

/// Compute an individual signer's [`PartialThresholdSignature`] contribution to
/// a [`ThresholdSignature`] on a `message`.
///
/// # Inputs
///
/// * The `message` to be signed by every individual signer,
/// * This signer's [`SecretKey`],
/// * This signer's [`CommitmentShare`] being used in this instantiation, and
/// * The list of all the currently participating [`Signer`]s.
///
/// # Returns
///
/// A [`PartialThresholdSignature`], which should be sent to the Signature
/// Aggregator.
// XXX How/when can this method ever fail?
pub fn sign(
    message: &[u8],
    my_secret_key: &SecretKey,
    my_commitment_share: &CommitmentShare,
    signers: &Vec<Signer>,
) -> PartialThresholdSignature
{
    let (binding_factors, Rs) = compute_binding_factors_and_group_commitment(&message, &signers);
    let R = Rs.iter().map(|x| x.1).collect().sum();
    let challenge = compute_challenge(&message, &R);

    // XXX We can't use the participant index to index into the binding factors
    // here because the list of actual signers might be different than the total
    // number of possible participants.  This means we need to waste a few
    // cycles recomputing our own blinding factor. :(
    let mut h3 = Sha512::new();

    // [DIFFERENT_TO_PAPER] I added a context string.
    h3.update(b"FROST-SHA512");
    h3.update(my_secret_key.index.to_be_bytes());
    h3.update(message);
    h3.update(my_commitment_share.hiding.sealed.compress().as_bytes());
    h3.update(my_commitment_share.binding.sealed.compress().as_bytes());

    let my_binding_factor = Scalar::from_hash(h3);

    // XXX [PAPER] Why are we adding yet another context for all the signers
    // here when we already have the context in R and the challenge?
    let lambda: Scalar = binding_factors.iter().sum();
    let z = my_commitment_share.hiding.nonce +
        (my_commitment_share.binding.nonce * my_binding_factor) +
        (lambda * my_secret_key.key * challenge); // XXX no likey lambda but ok

    // XXX [DIFFERENT_TO_PAPER] TODO Need to instead pass in the commitment
    // share list and zero-out the used commitment share, which means the
    // signature aggregator needs to tell us somehow which one they picked from
    // our published list.
    //
    // XXX ... I.... don't really love this API?

    PartialThresholdSignature { index: my_secret_key.index, z }
}

/// A signature aggregator is an untrusted party who coalesces all of the
/// participating signers' published commitment shares and their
/// [`PartialThresholdSignature`] and creates the final [`ThresholdSignature`].
/// The signature aggregator may even be one of the `t` participants in this
/// signing operation.
pub struct SignatureAggregator<'sa> {
    /// The protocol instance parameters.
    pub(crate) parameters: Parameters,
    /// The set of signing participants for this round.
    pub(crate) signers: Vec<Signer>,
    /// The signer's public keys for verifying their [`PartialThresholdSignature`].
    pub(crate) public_keys: Vec<IndividualPublicKey>,
    /// The message to be signed.
    pub(crate) message: &'sa [u8],
}

impl SignatureAggregator {
    /// Construct a new signature aggregator from some protocol instantiation
    /// `parameters` and a `message` to be signed.
    pub fn new<'sa>(parameters: Parameters, message: &'sa [u8]) -> SignatureAggregator<'sa> {
        // XXX Can t here be some t' s.t. t ≤ t' ≤ n from the parameters?
        let signers: Vec<Signer> = Vec::with_capacity(parameters.t as usize);
        let public_keys: Vec<IndividualPublicKey> = Vec::with_capacity(parameters.t as usize);

        SignatureAggregator { parameters, signers, public_keys, message }
    }

    /// Include a signer in the protocol.
    pub fn include_signer(&mut self, signer: Signer, public_key: IndividualPublicKey) {
        self.signers.push(signer);
        self.public_keys.push(public_key);
    }

    /// Aggregate a set of partial signatures
    pub fn aggregate(
        &mut self,
        partial_signatures: &Vec<PartialThresholdSignature>
    ) -> Result<ThresholdSignature, Vec<u32>>
    {
        //self.signers.sort(); // XXX need signers.sort() impl
        
        let (binding_factors, Rs) = compute_binding_factors_and_group_commitment(&self.message, &self.signers);
        let R = Rs.values().sum();
        let challenge = compute_challenge(&self.message, &R);
        let lambda: Scalar = binding_factors.iter().sum();

        let misbehaving_participants: Vec<u32> = Vec::new();

        for signer in self.signers.iter() {
            // XXX wrong index, impl on hashmap
            let check = &RISTRETTO_BASEPOINT_TABLE * partial_signatures.get(signer.participant_index);
            // XXX wrong index, impl on hashmap
            let Y_i = public_keys.get(signer.participant_index);

            match Rs.get(signer.participant_index) {
                Some(R_i) => {
                    match check == R_i + &(&Y_i * (challenge * lambda)) { // XXX lambda why???
                        true  => continue,
                        false => misbehaving_participants.push(signer.participant_index),
                    }
                },
                // XXX [DIFFERENT_TO_PAPER] We're reporting missing signers
                //     (possibly the fault of the aggregator) as well as
                //     misbehaved participants.
                None => misbehaving_participants.push(signer.participant_index),
            }
        }

        unimplemented!()
    }
}

impl ThresholdSignature {
    /// Verify this [`ThresholdSignature`].
    ///
    /// # Returns
    ///
    /// A `Result` whose `Ok` value is an empty tuple if the threshold signature
    /// was successfully verified, otherwise a vector of the participant indices
    /// of any misbehaving participants.
    pub fn verify(&self, group_key: &GroupKey) -> Result<(), Vec<u32>> {
        unimplemented!()
    }
}
