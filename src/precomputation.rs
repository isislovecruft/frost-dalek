// -*- mode: rust; -*-
//
// This file is part of dalek-frost.
// Copyright (c) 2020 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Precomputation for one-round signing.

#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use rand::CryptoRng;
use rand::Rng;

use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
pub(crate) struct NoncePair(pub(crate) Scalar, pub(crate) Scalar);

impl NoncePair {
    pub fn new(mut csprng: impl CryptoRng + Rng) -> Self {
        NoncePair(Scalar::random(&mut csprng), Scalar::random(&mut csprng))
    }
}

impl From<NoncePair> for CommitmentShare {
    fn from(other: NoncePair) -> CommitmentShare {
        let x = &RISTRETTO_BASEPOINT_TABLE * &other.0;
        let y = &RISTRETTO_BASEPOINT_TABLE * &other.1;

        CommitmentShare {
            hiding: Commitment {
                nonce: other.0,
                sealed: x,
            },
            binding: Commitment {
                nonce: other.1,
                sealed: y,
            },
        }
    }
}

/// A pair of a nonce and a commitment to it.
#[derive(Debug, Clone)]
pub(crate) struct Commitment {
    /// The nonce.
    pub(crate) nonce: Scalar,
    /// The commitment.
    pub(crate) sealed: RistrettoPoint,
}

impl Zeroize for Commitment {
    fn zeroize(&mut self) {
        self.nonce.zeroize();
        self.sealed = RistrettoPoint::identity();
    }
}

impl Drop for Commitment {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A precomputed commitment share.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct CommitmentShare {
    /// The hiding commitment.
    pub(crate) hiding: Commitment,
    /// The binding commitment.
    pub(crate) binding: Commitment,
}


impl CommitmentShare {
    /// Publish the public commitments in this [`CommitmentShare`].
    pub fn publish(&self) -> (RistrettoPoint, RistrettoPoint) {
        (self.hiding.sealed, self.binding.sealed)
    }
}

/// A secret commitment share list, containing the revealed nonces for the
/// hiding and binding commitments.
pub struct SecretCommitmentShareList {
    /// The participant's index.
    pub participant_index: u32,
    /// The secret commitment shares.
    pub commitments: Vec<CommitmentShare>,
}

/// A public commitment share list, containing only the hiding and binding
/// commitments, *not* their committed-to nonce values.
///
/// This should be published somewhere before the signing protocol takes place
/// for the other signing participants to obtain.
pub struct PublicCommitmentShareList {
    /// The participant's index.
    pub participant_index: u32,
    /// The published commitments.
    pub commitments: Vec<(RistrettoPoint, RistrettoPoint)>,
}

impl PublicCommitmentShareList {
    /// Pre-compute a list of [`CommitmentShares`] for single-round threshold signing.
    ///
    /// # Inputs
    ///
    /// * `participant_index` is the index of the threshold signing
    ///   [`Participant`] who is publishing this share.
    /// * `number_of_shares` denotes the number of commitments published at a time.
    ///
    /// # Returns
    ///
    /// A tuple of `(PublicCommitmentShareList, SecretCommitmentShareList)`
    pub fn generate(
        mut csprng: impl CryptoRng + Rng,
        participant_index: u32,
        number_of_shares: usize,
    ) -> (PublicCommitmentShareList, SecretCommitmentShareList)
    {
        let mut commitments: Vec<CommitmentShare> = Vec::with_capacity(number_of_shares);

        for _ in 0..number_of_shares {
            commitments.push(CommitmentShare::from(NoncePair::new(&mut csprng)));
        }

        let mut published: Vec<(RistrettoPoint, RistrettoPoint)> = Vec::with_capacity(number_of_shares);

        for n in 0..number_of_shares {
            published.push(commitments[n].publish());
        }

        (PublicCommitmentShareList { participant_index, commitments: published },
         SecretCommitmentShareList { participant_index, commitments })
    }
}
