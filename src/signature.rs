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
    pub(crate) R: RistrettoPoint,
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

/// Compute a Sha-512 hash of a message.
pub fn compute_message_hash(context_string: &[u8], message: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();

    h.update(context_string);
    h.update(message);

    let mut output = [0u8; 64];

    output.copy_from_slice(h.finalize().as_slice());
    output
}

fn compute_binding_factors_and_group_commitment(
    message_hash: &[u8; 64],
    signers: &Vec<Signer>,
) -> (HashMap<u32, Scalar>, SignerRs)
{
	let mut binding_factors: HashMap<u32, Scalar> = HashMap::with_capacity(signers.len());
    let mut Rs: SignerRs = SignerRs::new(); // XXX can we optimise size?

    // XXX [CFRG] Should the hash function be hardcoded in the RFC or should
    // we instead specify the output/block size?
    //
    // XXX [PAPER] Does the proof still work with sponges?
    let mut h = Sha512::new();

    // [DIFFERENT_TO_PAPER] I added a context string and reordered to hash
    // constants like the message first.
    h.update(b"FROST-SHA512");
    h.update(message_hash);

    // [DIFFERENT_TO_PAPER] I added the set of participants (in the paper
    // B = <(i, D_{ij}, E_(ij))> i \E S) here to avoid rehashing them over and
    // over again.
    for signer in signers.iter() {
        let hiding = signer.published_commitment_share.0;
        let binding = signer.published_commitment_share.1;

        h.update(signer.participant_index.to_be_bytes());
        h.update(hiding.compress().as_bytes());
        h.update(binding.compress().as_bytes());
    }

    for signer in signers.iter() {
        let hiding = signer.published_commitment_share.0;
        let binding = signer.published_commitment_share.1;

        let mut h1 = h.clone();

        // [DIFFERENT_TO_PAPER] I put in the participant index last to finish
        // their unique calculation of rho.
        h1.update(signer.participant_index.to_be_bytes());

        let binding_factor = Scalar::from_hash(h1); // This is rho in the paper.

        // THIS IS THE MAGIC STUFF ↓↓↓
        Rs.insert(&signer.participant_index, hiding + (binding_factor * binding));
	    binding_factors.insert(signer.participant_index, binding_factor);
    }
    (binding_factors, Rs)
}

fn compute_challenge(message_hash: &[u8; 64], R: &RistrettoPoint) -> Scalar {
    let mut h2 = Sha512::new();

    h2.update(b"FROST-SHA512");
    h2.update(message_hash);
    h2.update(R.compress().as_bytes());

    Scalar::from_hash(h2)
}

/// Calculate using Lagrange's method the interpolation of a polynomial.
///
/// # Note
///
/// isis stole some of this from Chelsea and Ian, but they stole it from
/// Lagrange, so who can really say.
fn calculate_lagrange_coefficients(
    participant_index: &u32,
    all_participant_indices: &Vec<u32>,
) -> Result<Scalar, &'static str>
{
    let mut num = Scalar::one();
    let mut den = Scalar::one();

    let mine = Scalar::from(*participant_index);

    for j in all_participant_indices.iter() {
        if j == participant_index {
            continue;
        }
        let s = Scalar::from(*j);

        num *= s;
        den *= s - mine; // Check to ensure that one person isn't trying to sign twice.
    }

    if den == Scalar::zero() {
        return Err("Duplicate shares provided");
    }
    Ok(num * den.invert())
}

/// Compute an individual signer's [`PartialThresholdSignature`] contribution to
/// a [`ThresholdSignature`] on a `message`.
///
/// # Inputs
///
/// * The `message_hash` to be signed by every individual signer, this should be
///   the `Sha512` digest of the message, optionally along with some application-specific
///   context string.
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
    message_hash: &[u8; 64],
    my_secret_key: &SecretKey,
    my_commitment_share: &CommitmentShare,
    signers: &Vec<Signer>,
) -> Result<PartialThresholdSignature, &'static str>
{
    let (binding_factors, Rs) = compute_binding_factors_and_group_commitment(&message_hash, &signers);
    let R = Rs.values().sum();
    let challenge = compute_challenge(&message_hash, &R);
    let my_binding_factor = binding_factors.get(&my_secret_key.index).unwrap(); // XXX error handling
    let all_participant_indices = signers.iter().map(|x| x.participant_index).collect();
    let lambda: Scalar = calculate_lagrange_coefficients(&my_secret_key.index, &all_participant_indices)?;
    let z = my_commitment_share.hiding.nonce +
        (my_commitment_share.binding.nonce * my_binding_factor) +
        (lambda * my_secret_key.key * challenge);

    // XXX [DIFFERENT_TO_PAPER] TODO Need to instead pass in the commitment
    // share list and zero-out the used commitment share, which means the
    // signature aggregator needs to tell us somehow which one they picked from
    // our published list.
    //
    // XXX ... I.... don't really love this API?

    Ok(PartialThresholdSignature { index: my_secret_key.index, z })
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
        let signers: Vec<Signer> = Vec::with_capacity(parameters.t as usize);
        let public_keys = IndividualPublicKeys::new();
        let partial_signatures = PartialThresholdSignatures::new();

        SignatureAggregator { parameters, signers, public_keys, message, partial_signatures }
    }

    /// Include a signer in the protocol.
    ///
    /// # Warning
    ///
    /// If this method is called for a specific participant, then that
    /// participant MUST provide a partial signature to give to
    /// [`SignatureAggregator.include_partial_signature`], otherwise the signing
    /// procedure will fail.
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
        // .sort() must be called before .dedup() because the latter only
        // removes consecutive repeated elements.
        self.signers.sort();
        self.signers.dedup();

        &self.signers
    }

    /// Add a [`PartialThresholdSignature`] to be included in the aggregation.
    pub fn include_partial_signature(&mut self, partial_signature: PartialThresholdSignature) {
        self.partial_signatures.insert(&partial_signature.index, partial_signature.z);
    }

    /// Aggregate a set of previously-collected partial signatures.
    ///
    /// # Returns
    ///
    /// A Result whose Ok() value is a [`ThresholdSignature`], otherwise a
    /// `Hashmap<u32, &'static str>` containing the participant indices of the misbehaving
    /// signers and a description of their misbehaviour.
    ///
    /// If the Hashmap is empty, the aggregator did not have \(( t' \)) partial signers
    /// s.t. \(( t \le t' \le n \)).
    pub fn aggregate(&mut self) -> Result<ThresholdSignature, HashMap<u32, &'static str>> {
        // .sort() must be called before .dedup() because the latter only
        // removes consecutive repeated elements.
        self.signers.sort();
        self.signers.dedup();

        let mut misbehaving_participants: HashMap<u32, &'static str> = HashMap::new();
        
        // XXX TODO Should actually check that the indices match.
        if self.signers.len() < self.parameters.t as usize {
            return Err(misbehaving_participants);
        }

        // XXX TODO allow application specific context strings.
        let message_hash = compute_message_hash(b"XXX MAKE A REAL CONTEXT STRING", &self.message);
        let (_, Rs) = compute_binding_factors_and_group_commitment(&message_hash, &self.signers);
        let R = Rs.values().sum();
        let c = compute_challenge(&message_hash, &R);
        let all_participant_indices = self.signers.iter().map(|x| x.participant_index).collect();
        let mut z = Scalar::zero();

        for signer in self.signers.iter() {
            // XXX [DIFFERENT_TO_PAPER] We're not just pulling lambda out of our
            // ass, instead to get the correct algebraic properties to allow for
            // partial signature aggregation with t <= #participant <= n, we
            // have to do Langrangian polynomial interpolation.
            //
            // XXX [DIFFERENT_TO_PAPER] Also, we're reporting attempted
            // duplicate signers from the calulation of the Lagrange
            // coefficients as being misbehaving users.
            let lambda = match calculate_lagrange_coefficients(&signer.participant_index, &all_participant_indices) {
                Ok(x)  => x,
                Err(_) => {
                    misbehaving_participants.insert(signer.participant_index, "Could not calculate lambda");
                    continue;
                }
            };

            // XXX [DIFFERENT_TO_PAPER] We're reporting missing partial
            //     signatures which could possibly be the fault of the aggregator.
            let partial_sig = match self.partial_signatures.get(&signer.participant_index) {
                Some(z_i) => z_i,
                None => {
                    misbehaving_participants.insert(signer.participant_index, "Missing partial signature");
                    continue;
                },
            };

            let Y_i = match self.public_keys.get(&signer.participant_index) {
                Some(x) => x,
                None => {
                    misbehaving_participants.insert(signer.participant_index, "Missing public key");
                    continue;
                }
            };

            let check = &RISTRETTO_BASEPOINT_TABLE * &partial_sig;

            match Rs.get(&signer.participant_index) {
                Some(R_i) => {
                    if check == R_i + &(Y_i * (c * lambda)) {
                        z += partial_sig;
                    } else {
                        misbehaving_participants.insert(signer.participant_index, "Incorrect partial signature");
                    }
                },
                // XXX [DIFFERENT_TO_PAPER] We're reporting missing signers
                //     (possibly the fault of the aggregator) as well as
                //     misbehaved participants.
                None => {
                    misbehaving_participants.insert(signer.participant_index, "Missing signer that aggregator expected");
                },
            }
        }

        match misbehaving_participants.len() > 0 {
            true => Err(misbehaving_participants),
            false => Ok(ThresholdSignature {z, R}),
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
    pub fn verify(&self, group_key: &GroupKey, message_hash: &[u8; 64]) -> Result<(), ()> {
        let c_prime = compute_challenge(&message_hash, &self.R);
        let R_prime = (&RISTRETTO_BASEPOINT_TABLE * &self.z) - (group_key.0 * &c_prime);

        match self.R.compress() == R_prime.compress() {
            true => Ok(()),
            false => {
                println!("r       is {:?}\nr_prime is {:?}", self.R.compress(), R_prime.compress());
                return Err(());
            },
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::keygen::Participant;
    use crate::keygen::{DistributedKeyGeneration, RoundOne, RoundTwo};
    use crate::precomputation::generate_commitment_share_lists;

    use rand::rngs::OsRng;

    #[test]
    fn signing_and_verification_single_party() {
        let params = Parameters { n: 1, t: 1 };

        let (p1, p1coeffs) = Participant::new(&params, 1);

        p1.proof_of_secret_key.verify(&p1.index, &p1.commitments[0]).unwrap();

        let mut p1_other_participants: Vec<Participant> = Vec::new();
        let p1_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                 &p1.index,
                                                                 &p1coeffs,
                                                                 &mut p1_other_participants).unwrap();
        let p1_their_secret_shares = p1_state.their_secret_shares().unwrap();
        let p1_my_secret_shares = Vec::new();
        let p1_state = p1_state.to_round_two(p1_my_secret_shares).unwrap();

        // XXX make a method for getting the public key share/commitment
        let result = p1_state.finish(p1.public_key());

        assert!(result.is_ok());

        let (group_key, p1_sk) = result.unwrap();

        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);

        let mut aggregator = SignatureAggregator::new(params, &message[..]);

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());

        let signers = aggregator.get_signers();

        let message_hash = compute_message_hash(b"XXX MAKE A REAL CONTEXT STRING", &message[..]);

        // XXX TODO SecretCommitmentShareList doesn't need to store the index
        let p1_partial = sign(&message_hash, &p1_sk, &p1_secret_comshares.commitments[0], signers).unwrap();

        aggregator.include_partial_signature(p1_partial);

        // XXX TODO aggregator should be a new type here to ensure we have proper state.
        let signing_result = aggregator.aggregate();

        assert!(signing_result.is_ok());

        let threshold_signature = signing_result.unwrap();

        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        println!("{:?}", verification_result);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn signing_and_verification_1_out_of_1() {
        let params = Parameters { n: 1, t: 1 };

        let (p1, p1coeffs) = Participant::new(&params, 1);

        let mut p1_other_participants: Vec<Participant> = Vec::with_capacity(0);
        let p1_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                 &p1.index,
                                                                 &p1coeffs,
                                                                 &mut p1_other_participants).unwrap();
        let p1_their_secret_shares = p1_state.their_secret_shares().unwrap();
        let p1_my_secret_shares = Vec::with_capacity(0);
        let p1_state = p1_state.to_round_two(p1_my_secret_shares).unwrap();

        let (group_key, p1_sk) = p1_state.finish(p1.public_key()).unwrap();

        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);

        let mut aggregator = SignatureAggregator::new(params, &message[..]);

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());

        let signers = aggregator.get_signers();

        let message_hash = compute_message_hash(b"XXX MAKE A REAL CONTEXT STRING", &message[..]);

        // XXX TODO SecretCommitmentShareList doesn't need to store the index
        let p1_partial = sign(&message_hash, &p1_sk, &p1_secret_comshares.commitments[0], signers).unwrap();

        aggregator.include_partial_signature(p1_partial);

        // XXX TODO aggregator should be a new type here to ensure we have proper state.
        let threshold_signature = aggregator.aggregate().unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn signing_and_verification_1_out_of_2() {
        let params = Parameters { n: 2, t: 1 };

        let (p1, p1coeffs) = Participant::new(&params, 1);
        let (p2, p2coeffs) = Participant::new(&params, 2);

        let mut p1_other_participants: Vec<Participant> = vec!(p2.clone());
        let p1_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                 &p1.index,
                                                                 &p1coeffs,
                                                                 &mut p1_other_participants).unwrap();
        let p1_their_secret_shares = p1_state.their_secret_shares().unwrap();

        let mut p2_other_participants: Vec<Participant> = vec!(p1.clone());
        let p2_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                 &p2.index,
                                                                 &p2coeffs,
                                                                 &mut p2_other_participants).unwrap();
        let p2_their_secret_shares = p2_state.their_secret_shares().unwrap();

        let p1_my_secret_shares = vec!(p2_their_secret_shares[0].clone()); // XXX FIXME indexing
        let p2_my_secret_shares = vec!(p1_their_secret_shares[0].clone());

        let p1_state = p1_state.to_round_two(p1_my_secret_shares).unwrap();
        let p2_state = p2_state.to_round_two(p2_my_secret_shares).unwrap();

        let (group_key, p1_sk) = p1_state.finish(p1.public_key()).unwrap();
        let (_, p2_sk) = p2_state.finish(p2.public_key()).unwrap();

        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);

        let mut aggregator = SignatureAggregator::new(params, &message[..]);

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());

        let signers = aggregator.get_signers();

        let message_hash = compute_message_hash(b"XXX MAKE A REAL CONTEXT STRING", &message[..]);

        // XXX TODO SecretCommitmentShareList doesn't need to store the index
        let p1_partial = sign(&message_hash, &p1_sk, &p1_secret_comshares.commitments[0], signers).unwrap();

        aggregator.include_partial_signature(p1_partial);

        // XXX TODO aggregator should be a new type here to ensure we have proper state.
        let threshold_signature = aggregator.aggregate().unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn signing_and_verification_3_out_of_5() {
        let params = Parameters { n: 5, t: 3 };

        let (p1, p1coeffs) = Participant::new(&params, 1);
        let (p2, p2coeffs) = Participant::new(&params, 2);
        let (p3, p3coeffs) = Participant::new(&params, 3);
        let (p4, p4coeffs) = Participant::new(&params, 4);
        let (p5, p5coeffs) = Participant::new(&params, 5);

        let mut p1_other_participants: Vec<Participant> = vec!(p2.clone(), p3.clone(), p4.clone(), p5.clone());
        let p1_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                 &p1.index,
                                                                 &p1coeffs,
                                                                 &mut p1_other_participants).unwrap();
        let p1_their_secret_shares = p1_state.their_secret_shares().unwrap();

        let mut p2_other_participants: Vec<Participant> = vec!(p1.clone(), p3.clone(), p4.clone(), p5.clone());
        let p2_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                 &p2.index,
                                                                 &p2coeffs,
                                                                 &mut p2_other_participants).unwrap();
        let p2_their_secret_shares = p2_state.their_secret_shares().unwrap();

        let mut p3_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p4.clone(), p5.clone());
        let p3_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                 &p3.index,
                                                                 &p3coeffs,
                                                                 &mut p3_other_participants).unwrap();
        let p3_their_secret_shares = p3_state.their_secret_shares().unwrap();

        let mut p4_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone(), p5.clone());
        let p4_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                 &p4.index,
                                                                 &p4coeffs,
                                                                 &mut p4_other_participants).unwrap();
        let p4_their_secret_shares = p4_state.their_secret_shares().unwrap();

        let mut p5_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone(), p4.clone());
        let p5_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                 &p5.index,
                                                                 &p5coeffs,
                                                                 &mut p5_other_participants).unwrap();
        let p5_their_secret_shares = p5_state.their_secret_shares().unwrap();

        let p1_my_secret_shares = vec!(p2_their_secret_shares[0].clone(), // XXX FIXME indexing
                                       p3_their_secret_shares[0].clone(),
                                       p4_their_secret_shares[0].clone(),
                                       p5_their_secret_shares[0].clone());

        let p2_my_secret_shares = vec!(p1_their_secret_shares[0].clone(),
                                       p3_their_secret_shares[1].clone(),
                                       p4_their_secret_shares[1].clone(),
                                       p5_their_secret_shares[1].clone());

        let p3_my_secret_shares = vec!(p1_their_secret_shares[1].clone(),
                                       p2_their_secret_shares[1].clone(),
                                       p4_their_secret_shares[2].clone(),
                                       p5_their_secret_shares[2].clone());

        let p4_my_secret_shares = vec!(p1_their_secret_shares[2].clone(),
                                       p2_their_secret_shares[2].clone(),
                                       p3_their_secret_shares[2].clone(),
                                       p5_their_secret_shares[3].clone());

        let p5_my_secret_shares = vec!(p1_their_secret_shares[3].clone(),
                                       p2_their_secret_shares[3].clone(),
                                       p3_their_secret_shares[3].clone(),
                                       p4_their_secret_shares[3].clone());

        let p1_state = p1_state.to_round_two(p1_my_secret_shares).unwrap();
        let p2_state = p2_state.to_round_two(p2_my_secret_shares).unwrap();
        let p3_state = p3_state.to_round_two(p3_my_secret_shares).unwrap();
        let p4_state = p4_state.to_round_two(p4_my_secret_shares).unwrap();
        let p5_state = p5_state.to_round_two(p5_my_secret_shares).unwrap();

        // XXX make a method for getting the public key share/commitment
        let (group_key, p1_sk) = p1_state.finish(p1.public_key()).unwrap();
        let (_, _) = p2_state.finish(p2.public_key()).unwrap();
        let (_, p3_sk) = p3_state.finish(p3.public_key()).unwrap();
        let (_, p4_sk) = p4_state.finish(p4.public_key()).unwrap();
        let (_, _) = p5_state.finish(p5.public_key()).unwrap();

        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (p3_public_comshares, p3_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 3, 1);
        let (p4_public_comshares, p4_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 4, 1);

        let mut aggregator = SignatureAggregator::new(params, &message[..]);

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());
        aggregator.include_signer(3, p3_public_comshares.commitments[0], (&p3_sk).into());
        aggregator.include_signer(4, p4_public_comshares.commitments[0], (&p4_sk).into());

        let signers = aggregator.get_signers();

        let message_hash = compute_message_hash(b"XXX MAKE A REAL CONTEXT STRING", &message[..]);

        // XXX TODO SecretCommitmentShareList doesn't need to store the index
        let p1_partial = sign(&message_hash, &p1_sk, &p1_secret_comshares.commitments[0], signers).unwrap();
        let p3_partial = sign(&message_hash, &p3_sk, &p3_secret_comshares.commitments[0], signers).unwrap();
        let p4_partial = sign(&message_hash, &p4_sk, &p4_secret_comshares.commitments[0], signers).unwrap();

        aggregator.include_partial_signature(p1_partial);
        aggregator.include_partial_signature(p3_partial);
        aggregator.include_partial_signature(p4_partial);

        // XXX TODO aggregator should be a new type here to ensure we have proper state.
        let threshold_signature = aggregator.aggregate().unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn signing_and_verification_2_out_of_3() {
        fn do_keygen() -> Result<(Parameters, SecretKey, SecretKey, SecretKey, GroupKey), ()> {
            let params = Parameters { n: 3, t: 2 };

            let (p1, p1coeffs) = Participant::new(&params, 1);
            let (p2, p2coeffs) = Participant::new(&params, 2);
            let (p3, p3coeffs) = Participant::new(&params, 3);

            p2.proof_of_secret_key.verify(&p2.index, &p2.commitments[0])?;
            p3.proof_of_secret_key.verify(&p3.index, &p3.commitments[0])?;

            let mut p1_other_participants: Vec<Participant> = vec!(p2.clone(), p3.clone());
            let p1_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                     &p1.index,
                                                                     &p1coeffs,
                                                                     &mut p1_other_participants).or(Err(()))?;
            let p1_their_secret_shares = p1_state.their_secret_shares()?;

            let mut p2_other_participants: Vec<Participant> = vec!(p1.clone(), p3.clone());
            let p2_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                     &p2.index,
                                                                     &p2coeffs,
                                                                     &mut p2_other_participants).or(Err(()))?;
            let p2_their_secret_shares = p2_state.their_secret_shares()?;

            let mut p3_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone());
            let  p3_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                      &p3.index,
                                                                      &p3coeffs,
                                                                      &mut p3_other_participants).or(Err(()))?;
            let p3_their_secret_shares = p3_state.their_secret_shares()?;

            let p1_my_secret_shares = vec!(p2_their_secret_shares[0].clone(), // XXX FIXME indexing
                                           p3_their_secret_shares[0].clone());
            let p2_my_secret_shares = vec!(p1_their_secret_shares[0].clone(),
                                           p3_their_secret_shares[1].clone());
            let p3_my_secret_shares = vec!(p1_their_secret_shares[1].clone(),
                                           p2_their_secret_shares[1].clone());

            let p1_state = p1_state.to_round_two(p1_my_secret_shares)?;
            let p2_state = p2_state.to_round_two(p2_my_secret_shares)?;
            let p3_state = p3_state.to_round_two(p3_my_secret_shares)?;

            // XXX make a method for getting the public key share/commitment
            let (p1_group_key, p1_secret_key) = p1_state.finish(p1.public_key())?;
            let (p2_group_key, p2_secret_key) = p2_state.finish(p2.public_key())?;
            let (p3_group_key, p3_secret_key) = p3_state.finish(p3.public_key())?;

            assert!(p1_group_key.0.compress() == p2_group_key.0.compress());
            assert!(p2_group_key.0.compress() == p3_group_key.0.compress());

            Ok((params, p1_secret_key, p2_secret_key, p3_secret_key, p1_group_key))
        }
        let keygen_protocol = do_keygen();

        assert!(keygen_protocol.is_ok());

        let (params, p1_sk, p2_sk, p3_sk, group_key) = keygen_protocol.unwrap();

        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (p2_public_comshares, p2_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 2, 1);

        let mut aggregator = SignatureAggregator::new(params, &message[..]);

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());
        aggregator.include_signer(2, p2_public_comshares.commitments[0], (&p2_sk).into());

        let signers = aggregator.get_signers();

        let message_hash = compute_message_hash(b"XXX MAKE A REAL CONTEXT STRING", &message[..]);

        // XXX TODO SecretCommitmentShareList doesn't need to store the index
        let p1_partial = sign(&message_hash, &p1_sk, &p1_secret_comshares.commitments[0], signers).unwrap();
        let p2_partial = sign(&message_hash, &p2_sk, &p2_secret_comshares.commitments[0], signers).unwrap();

        aggregator.include_partial_signature(p1_partial);
        aggregator.include_partial_signature(p2_partial);

        // XXX TODO aggregator should be a new type here to ensure we have proper state.
        let signing_result = aggregator.aggregate();

        assert!(signing_result.is_ok());

        let threshold_signature = signing_result.unwrap();

        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        println!("{:?}", verification_result);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn aggregator_get_signers() {
        let params = Parameters { n: 3, t: 2 };
        let message = b"This is a test of the tsunami alert system. This is only a test.";

        let (p1_public_comshares, p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (p2_public_comshares, p2_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 2, 1);

        let mut aggregator = SignatureAggregator::new(params, &message[..]);

        let p1_sk = SecretKey{ index: 1, key: Scalar::random(&mut OsRng) };
        let p2_sk = SecretKey{ index: 2, key: Scalar::random(&mut OsRng) };

        aggregator.include_signer(2, p2_public_comshares.commitments[0], (&p2_sk).into());
        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());
        aggregator.include_signer(2, p2_public_comshares.commitments[0], (&p2_sk).into());

        let signers = aggregator.get_signers();

        // The signers should be deduplicated.
        assert!(signers.len() == 2);

        // The indices should match and be in sorted order.
        assert!(signers[0].participant_index == 1);
        assert!(signers[1].participant_index == 2);

        // Participant 1 should have the correct precomputed shares.
        assert!(signers[0].published_commitment_share.0 == p1_public_comshares.commitments[0].0);
        assert!(signers[0].published_commitment_share.1 == p1_public_comshares.commitments[0].1);

        // Same for participant 2.
        assert!(signers[1].published_commitment_share.0 == p2_public_comshares.commitments[0].0);
        assert!(signers[1].published_commitment_share.1 == p2_public_comshares.commitments[0].1);
    }
}
