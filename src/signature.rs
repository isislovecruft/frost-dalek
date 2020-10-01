// -*- mode: rust; -*-
//
// This file is part of dalek-frost.
// Copyright (c) 2020 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! FROST signatures and their creation.

#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(feature = "std")]
use std::collections::hash_map::Values;
#[cfg(feature = "std")]
use std::cmp::Ordering;
#[cfg(feature = "std")]
use std::vec::Vec;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use sha2::Digest;
use sha2::Sha512;

use crate::keygen::GroupKey;
use crate::keygen::IndividualPublicKey;
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
#[derive(Debug, Eq)]
pub struct Signer {
    /// The participant index of this signer.
    pub participant_index: u32,
    /// One of the commitments that were published by each signing participant
    /// in the pre-computation phase.
    pub published_commitment_share: (RistrettoPoint, RistrettoPoint),
}

impl Ord for Signer {
    fn cmp(&self, other: &Signer) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl PartialOrd for Signer {
    fn partial_cmp(&self, other: &Signer) -> Option<Ordering> {
        match self.participant_index.cmp(&other.participant_index) {
            Ordering::Less => Some(Ordering::Less),
            // WARNING: Participants cannot have identical indices, so dedup() MUST be called.
            Ordering::Equal => Some(Ordering::Equal),
            Ordering::Greater => Some(Ordering::Greater),
        }
    }
}

impl PartialEq for Signer {
    fn eq(&self, other: &Signer) -> bool {
        self.participant_index == other.participant_index
    }
}

/// A partially-constructed threshold signature, made by each participant in the
/// signing protocol during the first phase of a signature creation.
pub struct PartialThresholdSignature {
    pub(crate) index: u32,
    pub(crate) z: Scalar,
}

/// A complete, aggregated threshold signature.
pub struct ThresholdSignature {
    pub(crate) z: Scalar,
    pub(crate) c: Scalar,
}

macro_rules! impl_indexed_hashmap {
    (Type = $type:ident, Item = $item:ident) => {

impl $type {
    pub(crate) fn new() -> $type {
        $type(HashMap::new())
    }

    // XXX [CFRG] Since the sorting order matters for the public API, both it
    // and the canonicalisation of the participant indices needs to be
    // specified.
    pub(crate) fn insert(&mut self, index: &u32, point: $item) {
        self.0.insert(index.to_be_bytes(), point);
    }

    pub(crate) fn get(&self, index: &u32) -> Option<&$item> {
        self.0.get(&index.to_be_bytes())
    }

    #[allow(unused)]
    pub(crate) fn sorted(&self) -> Vec<(u32, $item)> {
        let mut sorted: Vec<(u32, $item)> = Vec::with_capacity(self.0.len());

        for (i, point) in self.0.iter() {
            let index = u32::from_be_bytes(*i);
            sorted.insert(index as usize, (index, *point));
        }
        sorted
    }

    #[allow(unused)]
    pub(crate) fn values(&self) -> Values<'_, [u8; 4], $item> {
        self.0.values()
    }
}

}} // END macro_rules! impl_indexed_hashmap

/// A struct for storing signers' R values with the signer's participant index.
// XXX I hate this so much.
//
// XXX TODO there might be a more efficient way to optimise this data structure
//     and its algorithms?
struct SignerRs(pub(crate) HashMap<[u8; 4], RistrettoPoint>);

impl_indexed_hashmap!(Type = SignerRs, Item = RistrettoPoint);

/// A type for storing signers' partial threshold signatures along with the
/// respective signer participant index.
pub(crate) struct PartialThresholdSignatures(pub(crate) HashMap<[u8; 4], Scalar>);

impl_indexed_hashmap!(Type = PartialThresholdSignatures, Item = Scalar);

/// A type for storing signers' individual public keys along with the respective
/// signer participant index.
pub(crate) struct IndividualPublicKeys(pub(crate) HashMap<[u8; 4], RistrettoPoint>);

impl_indexed_hashmap!(Type = IndividualPublicKeys, Item = RistrettoPoint);

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
        Rs.insert(&signer.participant_index, hiding + (binding_factor * binding));

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
    let R = Rs.values().sum();
    let challenge = compute_challenge(&message, &R);

    // XXX We can't use the participant index to index into the binding factors
    // here because the list of actual signers might be different than the total
    // number of possible participants.  This means we need to waste a few
    // cycles recomputing our own blinding factor. :(
    //
    // XXX FIXME Signers contains the participant index so we should return it from compute_binding..()
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
    pub(crate) public_keys: IndividualPublicKeys,
    /// The message to be signed.
    pub(crate) message: &'sa [u8],
    /// The partial signatures from individual participants which have been
    /// collected thus far.
    pub(crate) partial_signatures: PartialThresholdSignatures,
}

impl SignatureAggregator<'_> {
    /// Construct a new signature aggregator from some protocol instantiation
    /// `parameters` and a `message` to be signed.
    pub fn new<'sa>(parameters: Parameters, message: &'sa [u8]) -> SignatureAggregator<'sa> {
        // XXX Can t here be some t' s.t. t ≤ t' ≤ n from the parameters?
        let signers: Vec<Signer> = Vec::with_capacity(parameters.t as usize);
        let public_keys = IndividualPublicKeys::new();
        let partial_signatures = PartialThresholdSignatures::new();

        SignatureAggregator { parameters, signers, public_keys, message, partial_signatures }
    }

    /// Include a signer in the protocol.
    ///
    /// # Panics
    ///
    /// If the `signer.participant_index` doesn't match the `public_key.index`.
    pub fn include_signer(
        &mut self,
        participant_index: u32,
        published_commitment_share: (RistrettoPoint, RistrettoPoint),
        public_key: IndividualPublicKey)
    {
        assert_eq!(participant_index, public_key.index,
                   "Tried to add signer with participant index {}, but public key is for participant with index {}",
                   participant_index, public_key.index);

        self.signers.push(Signer { participant_index, published_commitment_share });
        self.public_keys.insert(&public_key.index, public_key.share);
    }

    /// Get the list of partipating signers.
    ///
    /// # Returns
    ///
    /// A `Vec<Signer>` of the participating signers in this round.
    pub fn get_signers<'sa>(&'sa mut self) -> &'sa Vec<Signer> {
        self.signers.dedup();
        self.signers.sort();

        &self.signers
    }

    /// Add a [`PartialThresholdSignature`] to be included in the aggregation.
    pub fn include_partial_signature(&mut self, partial_signature: PartialThresholdSignature) {
        self.partial_signatures.insert(&partial_signature.index, partial_signature.z);
    }

    /// Aggregate a set of partial signatures
    pub fn aggregate(&mut self) -> Result<ThresholdSignature, Vec<u32>> {
        self.signers.sort();
        self.signers.dedup();

        let mut misbehaving_participants: Vec<u32> = Vec::new();
        
        if self.signers.len() != self.parameters.t as usize {
            return Err(misbehaving_participants);
        }

        let (binding_factors, Rs) = compute_binding_factors_and_group_commitment(&self.message, &self.signers);
        let R = Rs.values().sum();
        let c = compute_challenge(&self.message, &R);
        let lambda: Scalar = binding_factors.iter().sum();
        let mut z = Scalar::zero();

        for signer in self.signers.iter() {
            // XXX [DIFFERENT_TO_PAPER] We're reporting missing partial
            //     signatures which could possibly be the fault of the aggregator.
            let partial_sig = match self.partial_signatures.get(&signer.participant_index) {
                Some(x) => x,
                None => {
                    misbehaving_participants.push(signer.participant_index);
                    continue;
                },
            };
            let check = &RISTRETTO_BASEPOINT_TABLE * &partial_sig;

            // XXX TODO maybe we should be reporting strings so that we know the
            // reason someone was "misbehaving".
            let Y_i = match self.public_keys.get(&signer.participant_index) {
                Some(x) => x,
                None => {
                    misbehaving_participants.push(signer.participant_index);
                    continue;
                }
            };

            match Rs.get(&signer.participant_index) {
                Some(R_i) => {
                    match check == R_i + &(Y_i * (c * lambda)) { // XXX lambda why???
                        true  => z += partial_sig,
                        false => misbehaving_participants.push(signer.participant_index),
                    }
                },
                // XXX [DIFFERENT_TO_PAPER] We're reporting missing signers
                //     (possibly the fault of the aggregator) as well as
                //     misbehaved participants.
                None => misbehaving_participants.push(signer.participant_index),
            }
        }

        match misbehaving_participants.len() > 0 {
            true => Err(misbehaving_participants),
            false => Ok(ThresholdSignature {z, c}),
        }
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
    pub fn verify(&self, group_key: &GroupKey, message: &[u8]) -> Result<(), ()> {
        let R_prime = (&RISTRETTO_BASEPOINT_TABLE * &self.z) + (group_key.0 * &-self.c);
        let c_prime = compute_challenge(&message, &R_prime);

        match self.c == c_prime {
            true => Ok(()),
            false => {
                println!("c       is {:?}\nc_prime is {:?}", self.c, c_prime);
                return Err(());
            },
        }
    }
}
