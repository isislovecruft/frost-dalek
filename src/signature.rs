// -*- mode: rust; -*-
//
// This file is part of dalek-frost.
// Copyright (c) 2020 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! FROST signatures and their creation.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use sha2::Digest;
use sha2::Sha512;

use crate::keygen::SecretKey;
use crate::precomputation::CommitmentShare;

// assume central aggregator does coordination

// nonces should be explicitly drop()ed from memory (and probably even zeroed
// first)

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
pub struct PartialThresholdSignature(pub(crate) Scalar);

/// A complete, aggregated threshold signature.
pub struct ThresholdSignature(pub(crate) Scalar, pub(crate) Scalar);


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
	let mut binding_factors: Vec<Scalar> = Vec::with_capacity(signers.len());
    let mut R: RistrettoPoint = RistrettoPoint::identity();

    for signer in signers.iter() {
        let hiding = signer.published_commitment_share.0;
        let binding = signer.published_commitment_share.1;

        let mut h1 = Sha512::new();

        h1.update(signer.participant_index.to_be_bytes());
        h1.update(message);
        h1.update(hiding.compress().as_bytes());
        h1.update(binding.compress().as_bytes());

        let binding_factor = Scalar::from_hash(h1);

        // THIS IS THE MAGIC STUFF ↓↓↓
        R += hiding + (binding_factor * binding);

	    binding_factors.push(binding_factor);
    }

    let mut h2 = Sha512::new();

    h2.update(message);
    h2.update(R.compress().as_bytes());

    let challenge = Scalar::from_hash(h2);

    // XXX We can't use the participant index to index into the binding factors
    // here because the list of actual signers might be different than the total
    // number of possible participants.  This means we need to waste a few
    // cycles recomputing our own blinding factor. :(
    let mut h3 = Sha512::new();

    h3.update(my_secret_key.index.to_be_bytes());
    h3.update(message);
    h3.update(my_commitment_share.hiding.sealed.compress().as_bytes());
    h3.update(my_commitment_share.binding.sealed.compress().as_bytes());

    let my_binding_factor = Scalar::from_hash(h3);

    // XXX Why are we adding yet another context for all the signers here when
    // we already have the context in R and the challenge?
    let lambda: Scalar = binding_factors.iter().sum();
    let z = my_commitment_share.hiding.nonce +
        (my_commitment_share.binding.nonce * my_binding_factor) +
        (lambda * my_secret_key.key * challenge); // XXX no likey lambda but ok

    PartialThresholdSignature(z)
}
