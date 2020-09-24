// -*- mode: rust; -*-
//
// This file is part of dalek-frost.
// Copyright (c) 2020 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! FROST signatures and their creation.

use rand::rngs::OsRng;

use sha2::Sha512;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct NoncePair(pub(crate) Scalar, pub(crate) Scalar);

impl NoncePair {
    pub fn new<C>(csprng: &mut C) -> Self
    where
        C: CryptoRng + RngCore,
    {
        NoncePair(Scalar::random(&mut csprng), Scalar::random(&mut csprng))
    }
}

impl From<NoncePair> for CommitmentShare {
    fn from(&self) -> CommitmentShare {
        let x = &RISTRETTO_BASEPOINT_TABLE * &self.0;
        let y = &RISTRETTO_BASEPOINT_TABLE * &self.1;

        CommitmentShare((self.0, x), (self.1, y))
    }
}

/// A pair of a nonce and a commitment to it.
// XXX need zeroize impl
#[derive(Debug, Clone)]
pub struct Commitment {
    /// The nonce.
    pub(crate) nonce: Scalar,
    /// The commitment.
    pub sealed: RistrettoPoint,
}

/// A precomputed commitment share.
pub struct CommitmentShare {
    /// The hiding commitment.
    pub(crate) hiding: Commitment,
    /// The binding commitment.
    pub(crate) binding: Commitment,
}


impl CommitmentShare {
    pub fn publish(&self) -> (RistrettoPoint, RistrettoPoint) {
        (self.hiding.sealed, self.binding.sealed)
    }

    // pub fn generate(amount: u32) -> Vec
}

pub struct CommitmentShareList {
    pub participant_index: u32,
    pub commitments: Vec<(RistrettoPoint, RistrettoPoint)>,
}

impl CommitmentShareList {
    /// number_of_shares denotes the number of commitments published at a time
    pub fn generate(participant_index: &u32, number_of_shares: &u32)
    -> Vec<CommitmentShare>
    {
        let mut rng = OsRng;

        let shares: Vec<CommitmentShare> = Vec::with_capacity(number_of_shares as usize);
        for _ in number_of_shares {
            shares.push(CommitmentShare::from(NoncePair::new(&mut rng));
        }
        shares
    }

    // pub fn publish(&
}

// ---------------------------------------------
// signing
// ---------------------------------------------

// assume central aggregator does coordination

// nonces should be explicitly drop()ed from memory (and probably even zeroed
// first)

pub struct Signature(Scalar, Scalar);

pub fn sign(
    message: &[u8],
    commitments: &Vec<(u32, RistrettoPoint, RistrettoPoint)>, // these are commitments that were published by each signing participant in an earlier phase
) -> Signature
{

	let binding_factors: Vec<Scalar> = Vec::with_capacity(commitments.len());
            let mut R: RistrettoPoint = RistrettoPoint::identity();
	for commitment in commitments.iter() {
                let H = Sha512::new();
	    let binding_factor = H(commitment.index, m, B); // TODO actually do hashing
	    binding.factors.push(binding_factor);

                // THIS IS THE MAGIC STUFF ↓↓↓
                R += commitment.0 + binding_factor * commitment.1; 
}
	
}
