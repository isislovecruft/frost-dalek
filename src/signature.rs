// -*- mode: rust; -*-
//
// This file is part of dalek-frost.
// Copyright (c) 2020 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! FROST signatures and their creation.

use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_TABLE},
    ristretto::RistrettoPoint,
    scalar::Scalar,
    traits::Identity,
};

use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};

use zeroize::Zeroize;

use digest::Digest;
use sha2::Sha512;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct NoncePair(pub(crate) Scalar, pub(crate) Scalar);

impl NoncePair {
    pub fn new<C>(csprng: &mut C) -> Self
    where
        C: CryptoRng + RngCore,
    {
        NoncePair(Scalar::random(csprng), Scalar::random(csprng))
    }
}

impl From<NoncePair> for CommitmentShare {
    fn from(p: NoncePair) -> CommitmentShare {
        let x = &RISTRETTO_BASEPOINT_TABLE * &p.0;
        let y = &RISTRETTO_BASEPOINT_TABLE * &p.1;

        CommitmentShare {
            hiding: Commitment {
                nonce: p.0,
                sealed: x,
            },
            binding: Commitment {
                nonce: p.1,
                sealed: y,
            },
        }
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
    pub fn generate(participant_index: &u32, number_of_shares: &u32) -> Vec<CommitmentShare> {
        let mut rng = OsRng;

        let mut shares: Vec<CommitmentShare> = Vec::with_capacity(*number_of_shares as usize);
        for _ in 0..*number_of_shares {
            shares.push(CommitmentShare::from(NoncePair::new(&mut rng)));
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
    // these are commitments that were published by each signing participant in an earlier phase
    commitments: &Vec<(u32, RistrettoPoint, RistrettoPoint)>,
) -> Signature {
    let mut binding_factors: Vec<Scalar> = Vec::with_capacity(commitments.len());
    let mut R: RistrettoPoint = RistrettoPoint::identity();
    for commitment in commitments.iter() {
        let binding_factor = Scalar::from_hash(
            Sha512::new()
                .chain(commitment.0.to_le_bytes())
                .chain(message)
                .chain(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes()),
        );
        binding_factors.push(binding_factor);

        // THIS IS THE MAGIC STUFF ↓↓↓
        R += commitment.1 + binding_factor * commitment.2;
    }

    unimplemented!()
}
