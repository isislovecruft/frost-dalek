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

use subtle::Choice;
use subtle::ConstantTimeEq;

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
#[derive(Clone, Debug)]
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

/// Test equality in constant-time.
impl ConstantTimeEq for Commitment {
    fn ct_eq(&self, other: &Commitment) -> Choice {
        self.nonce.ct_eq(&other.nonce) &
            self.sealed.compress().ct_eq(&other.sealed.compress())
    }
}

/// A precomputed commitment share.
#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct CommitmentShare {
    /// The hiding commitment.
    pub(crate) hiding: Commitment,
    /// The binding commitment.
    pub(crate) binding: Commitment,
}

/// Test equality in constant-time.
impl ConstantTimeEq for CommitmentShare {
    fn ct_eq(&self, other: &CommitmentShare) -> Choice {
        self.hiding.ct_eq(&other.hiding) & self.binding.ct_eq(&other.binding)
    }
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
/// A tuple of `(PublicCommitmentShareList, SecretCommitmentShareList)`.
pub fn generate_commitment_share_lists(
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

impl SecretCommitmentShareList {
    /// Drop a used [`CommitmentShare`] from our secret commitment share list
    /// and ensure that it is wiped from memory.
    pub fn drop_share(&mut self, share: &CommitmentShare) {
        let mut index = -1;

        // This is not constant-time in that the number of commitment shares in
        // the list may be discovered via side channel, as well as the index of
        // share to be deleted, as well as whether or not the share was in the
        // list, but none of this gives any adversary that I can think of any
        // advantage.
        for (i, s) in self.commitments.iter().enumerate() {
            if s.ct_eq(share).into() {
                index = i as isize;
            }
        }
        if index >= 0 {
            drop(self.commitments.remove(index as usize));
        }
        drop(share);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use rand::rngs::OsRng;

    #[test]
    fn nonce_pair() {
        let nonce_pair = NoncePair::new(&mut OsRng);
    }

    #[test]
    fn nonce_pair_into_commitment_share() {
        let commitment_share: CommitmentShare = NoncePair::new(&mut OsRng).into();
    }

    #[test]
    fn commitment_share_list_generate() {
        let (public_share_list, secret_share_list) = generate_commitment_share_lists(&mut OsRng, 0, 5);

        assert_eq!(public_share_list.commitments[0].0.compress(),
                   (&secret_share_list.commitments[0].hiding.nonce * &RISTRETTO_BASEPOINT_TABLE).compress());
    }

    #[test]
    fn drop_used_commitment_shares() {
        let (public_share_list, mut secret_share_list) = generate_commitment_share_lists(&mut OsRng, 3, 8);

        assert!(secret_share_list.commitments.len() == 8);

        let used_share = secret_share_list.commitments[0].clone();

        secret_share_list.drop_share(&used_share);

        assert!(secret_share_list.commitments.len() == 7);
    }
}
