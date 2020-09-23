// -*- mode: rust; -*-
//
// This file is part of dalek-frost.
// Copyright (c) 2020 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! A variation of Pedersen's distributed key generation (DKG) protocol.

use std::boxed::Box;
use std::vec::Vec;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand::rngs::OsRng;

use zeroize::Zeroize;

use crate::nizk::NizkOfSecretKey;
use crate::Parameters;

/// A struct for holding a shard of the shared secret, in order to ensure that
/// the shard is overwritten with zeroes when it falls out of scope.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Coefficients(pub(crate) Vec<Scalar>);

/// A participant in a threshold signing.
pub struct Participant {
    /// The index of this participant, to keep the participants in order.
    pub index: u32,
    /// A vector of Pedersen commitments to the coefficients of this
    /// participant's private polynomial.
    pub commitments: Vec<RistrettoPoint>,
    /// The zero-knowledge proof of knowledge of the secret key (a.k.a. the
    /// first coefficient in the private polynomial).  It is constructed as a
    /// Schnorr signature using \(( a_{i0} \)) as the signing key.
    pub proof_of_secret_key: NizkOfSecretKey,
}

impl Participant {
    /// Construct a new participant for the distributed key generation protocol.
    ///
    /// # Inputs
    ///
    /// * The protocol instance [`Parameters`], and
    /// * This participant's `index`.
    ///
    /// # Usage
    ///
    /// After a new participant is constructed, the `participant.index`,
    /// `participant.commitments`, and `participant.proof_of_secret_key` should
    /// be sent to every other participant in the protocol.
    ///
    /// # Returns
    ///
    /// A distributed key generation protocol [`Participant`] and that
    /// participant's secret polynomial `Coefficients` which must be kept
    /// private.
    pub fn new(parameters: &Parameters, index: u32) -> (Self, Coefficients) {
        // Step 1: Every participant P_i samples t random values (a_{i0}, ..., a_{i(t-1)})
        //         uniformly in ZZ_q, and uses these values as coefficients to define a
        //         polynomial f_i(x) = \sum_{j=0}^{t-1} a_{ij} x^{j} of degree t-1 over
        //         ZZ_q.
        let t: usize = parameters.t as usize;
        let mut rng: OsRng = OsRng;
        let mut coefficients: Vec<Scalar> = Vec::with_capacity(t);
        let mut commitments: Vec<RistrettoPoint> = Vec::with_capacity(t);

        for _ in 0..t {
            coefficients.push(Scalar::random(&mut rng));
        }

        let coefficients = Coefficients(coefficients);

        // Step 3: Every participant P_i computes a public commitment
        //         C_i = [\phi_{i0}, ..., \phi_{i(t-1)}], where \phi_{ij} = g^{a_{ij}},
        //         0 ≤ j ≤ t-1.
        for j in 0..t {
            commitments.push(&coefficients.0[j] * &RISTRETTO_BASEPOINT_TABLE);
        }

        // Yes, I know the steps are out of order.  It saves one scalar multiplication.

        // Step 2: Every P_i computes a proof of knowledge to the corresponding secret
        //         a_{i0} by calculating a Schnorr signature \alpha_i = (s, R).  (In
        //         the FROST paper: \alpha_i = (\mu_i, c_i), but we stick with Schnorr's
        //         original notation here.)
        let proof: NizkOfSecretKey = NizkOfSecretKey::prove(&index, &coefficients, &commitments[0]);

        // Step 4: Every participant P_i broadcasts C_i, \alpha_i to all other participants.
        (Participant { index, commitments, proof_of_secret_key: proof }, coefficients)
    }
}

// impl PartialOrd for Participant {
//     fn partial_cmp(&self, other: &Participant) -> Option<Ordering> {
//         match self.index.cmp(other.index) {
//             Ordering::Less => Some(Ordering::Less),
//             Ordering::Equal => None,  // Participants cannot have identical indices.
//             Ordering::Greater => Some(Ordering::Greater),
//         }
//     }
// }
// 
// impl PartialEq for Participant {
//     fn eq(&self, other: &Participant) -> bool {
//         self.index == other.index
//     }
// }

/// Module to implement trait sealing so that `DkgState` cannot be
/// implemented for externally declared types.
mod private {
    pub trait Sealed {}

    impl Sealed for super::RoundOne {}
    impl Sealed for super::RoundTwo {}
}

/// State machine structures for holding intermediate values during a
/// distributed key generation protocol run, to prevent misuse.
pub struct DistributedKeyGeneration<S: DkgState> {
    state: Box<ActualState>,
    data: S,
}

/// Shared state which occurs across all rounds of a threshold signing protocol run.
struct ActualState {
    /// The parameters for this instantiation of a threshold signature.
    parameters: Parameters,
    /// A vector of tuples containing the index of each participant and that
    /// respective participant's commitments to their private polynomial
    /// coefficients.
    their_commitments: Vec<(u32, Vec<RistrettoPoint>)>,
    /// A secret share for this participant.
    my_secret_share: SecretShare,
    /// The secret shares this participant has calculated for all the other participants.
    their_secret_shares: Option<Vec<SecretShare>>,
    /// The secret shares this participant has received from all the other participants.
    my_secret_shares: Option<Vec<SecretShare>>,
}

/// Marker trait to designate valid rounds in the distributed key generation
/// protocol's state machine.  It is implemented using the [sealed trait design
/// pattern][sealed] pattern to prevent external types from implementing further
/// valid states.
///
/// [sealed]: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait DkgState: private::Sealed {}

impl DkgState for RoundOne {}
impl DkgState for RoundTwo {}

/// Marker trait to designate valid variants of [`RoundOne`] in the distributed
/// key generation protocol's state machine.  It is implemented using the
/// [sealed trait design pattern][sealed] pattern to prevent external types from
/// implementing further valid states.
///
/// [sealed]: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait Round1: private::Sealed {}

/// Marker trait to designate valid variants of [`RoundTwo`] in the distributed
/// key generation protocol's state machine.  It is implemented using the
/// [sealed trait design pattern][sealed] pattern to prevent external types from
/// implementing further valid states.
///
/// [sealed]: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait Round2: private::Sealed {}

impl Round1 for RoundOne {}
impl Round2 for RoundTwo {}

/// Every participant in the distributed key generation has sent a vector of
/// commitments and a zero-knowledge proof of a secret key to every other
/// participant in the protocol.  During round one, each participant checks the
/// zero-knowledge proofs of secret keys of all other participants.
pub struct RoundOne {}

impl DistributedKeyGeneration<RoundOne> {
    /// Check the zero-knowledge proofs of knowledge of secret keys of all the
    /// other participants.
    ///
    /// # Note
    ///
    /// The `participants` will be sorted by their indices.
    ///
    /// # Returns
    ///
    /// An updated state machine for the distributed key generation protocol if
    /// all of the zero-knowledge proofs verified successfully, otherwise a
    /// vector of participants whose zero-knowledge proofs were incorrect.
    pub fn new(
        parameters: &Parameters,
        my_index: &u32,
        my_coefficients: &Coefficients,
        other_participants: &mut Vec<Participant>,
    ) -> Result<Self, Vec<u32>>
    {
        let mut their_commitments: Vec<(u32, Vec<RistrettoPoint>)> = Vec::with_capacity(parameters.t as usize);
        let mut misbehaving_participants: Vec<u32> = Vec::new();

        // Bail if we didn't get enough participants.
        if other_participants.len() != parameters.t as usize {
            return Err(misbehaving_participants);
        }

        // Step 5: Upon receiving C_l, \alpha_l from participants 1 ≤ l ≤ n, l ≠ i,
        //         participant P_i verifies \alpha_l = (s_l, r_l), by checking:
        //
        //         r_l ?= H(l, \Phi, \phi_{l0}, g^{\mu_l} \mdot \phi_{l0}^{-r_i})
        for p in other_participants.iter() {
            let public_key = match p.commitments.get(0) {
                Some(key) => key,
                None      => {
                    misbehaving_participants.push(p.index);
                    continue;
                }
            };
            match p.proof_of_secret_key.verify(&p.index, &public_key) {
                Ok(_)  => their_commitments.push((p.index, p.commitments.clone())),
                Err(_) => misbehaving_participants.push(p.index),
            }
        }

        // [DIFFERENT_TO_PAPER] If any participant was misbehaving, return their indices.
        if misbehaving_participants.len() > 0 {
            return Err(misbehaving_participants);
        }

        // [DIFFERENT_TO_PAPER] We pre-calculate the secret shares from Round 2
        // Step 1 here since it doesn't require additional online activity.
        //
        // Round 2
        // Step 1: Each P_i securely sends to each other participant P_l a secret share
        //         (l, f_i(l)) and keeps (i, f_i(i)) for themselves.
        let mut their_secret_shares: Vec<SecretShare> = Vec::with_capacity(parameters.t as usize);

        for p in other_participants.iter() {
            their_secret_shares.push(SecretShare::evaluate_polynomial(&p.index, my_coefficients));
        }

        let my_secret_share = SecretShare::evaluate_polynomial(my_index, my_coefficients);
        let state = ActualState {
            parameters: *parameters,
            their_commitments,
            my_secret_share,
            their_secret_shares: Some(their_secret_shares),
            my_secret_shares: None,
        };

        Ok(DistributedKeyGeneration::<RoundOne> {
            state: Box::new(state),
            data: RoundOne {},
        })
    }

    /// Retrieve a secret share for each other participant, to be given to them
    /// at the end of `DistributedKeyGeneration::<RoundOne>`.
    pub fn their_secret_shares(&self) -> Result<&Vec<SecretShare>, ()> {
        self.state.their_secret_shares.as_ref().ok_or(())
    }

    /// Progress to round two of the DKG protocol once we have sent each share
    /// from `DistributedKeyGeneration::<RoundOne>.their_secret_shares()` to its
    /// respective other participant, and collected our shares from the other
    /// participants in turn.
    pub fn to_round_two(
        mut self,
        my_secret_shares: Vec<SecretShare>,
    ) -> Result<DistributedKeyGeneration<RoundTwo>, ()>
    {
        // Zero out the other participants secret shares from memory.
        for their_share in self.state.their_secret_shares.as_mut_ref().iter() {
            their_share.zeroize()
        }
        // XXX Does setting this to None here effectively call drop()? If so, how effectively?
        self.state.their_secret_shares = None;

        // Step 2: Each P_i verifies their shares by calculating:
        //         g^{f_l(i)} ?= \Prod_{k=0}^{t-1} \phi_{lk}^{i^{k} mod q},
        //         aborting if the check fails.
        for share in my_secret_shares.iter() {
            // XXX TODO implement sorting for SecretShare and also for a new Commitment type
            for (index, commitments) in self.state.their_commitments.iter() {
                if index == &share.index {
                    share.verify(&commitments)?;
                }
            }
        }
        self.state.my_secret_shares = Some(my_secret_shares);

        Ok(DistributedKeyGeneration::<RoundTwo> {
            state: self.state,
            data: RoundTwo {},
        })
    }
}

/// A secret share calculated by evaluating a polynomial with secret
/// coefficients for some indeterminant.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretShare {
    /// The participant index that this secret share was calculated for.
    pub index: u32,
    /// The final evaluation of the polynomial for the participant-respective
    /// indeterminant.
    pub(crate) polynomial_evaluation: Scalar,
}

impl SecretShare {
    /// Evaluate the polynomial, `f(x)` for the secret coefficients at the value of `x`.
    pub(crate) fn evaluate_polynomial(index: &u32, coefficients: &Coefficients) -> SecretShare {
        let mut term: Scalar = (*index).into();
        let mut sum: Scalar = coefficients.0[0]; // The first one is multiplied by index^0 = 1.

        for i in 1..coefficients.0.len() {
            sum += coefficients.0[i] * term;
            term += term;
        }
        SecretShare { index: *index, polynomial_evaluation: sum }
    }

    /// Verify that this secret share was correctly computed w.r.t. some secret
    /// polynomial coefficients attested to by some `commitments`.
    pub(crate) fn verify(&self, commitments: &Vec<RistrettoPoint>) -> Result<(), ()> {
        let lhs = &RISTRETTO_BASEPOINT_TABLE * &self.polynomial_evaluation;
        let mut term: Scalar = self.index.into();
        let mut rhs: RistrettoPoint = commitments[0];

        for i in 1..commitments.len() {
            rhs += commitments[i] * term;
            term += term;
        }

        match lhs.compress() == rhs.compress() {
            true => Ok(()),
            false => Err(()),
        }
    }
}

/// During round two each participant verifies their secret shares they received
/// from each other participant.
pub struct RoundTwo {}

impl DistributedKeyGeneration<RoundTwo> {
    /// Calculate this threshold signing protocol participant's long-lived
    /// secret signing keyshare and the group's public verification key.
    pub fn finish(self) -> Result<(GroupKey, SecretKey), ()> {


        // XXX remember to zeroize secret parts of the state
        unimplemented!()
    }
}

/// XXX DOCDOC
pub struct PublicShare {
    /// XXX DOCDOC
    pub index: u32,
    /// XXX DOCDOC
    pub(crate) share: RistrettoPoint,
}

impl PublicShare {
    /// XXX DOCDOC
    pub fn verify(&self, commitments: &Vec<RistrettoPoint>) -> Result<(), ()> {
        unimplemented!()
    }
}

/// A secret key, used by one participant in a threshold signature scheme, to sign a message.
pub struct SecretKey(pub(crate) Scalar);

/// A public key, used to verify a signature made by a threshold of a group of participants.
pub struct GroupKey(pub(crate) RistrettoPoint);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn nizk_of_secret_key() {
        let params = Parameters { n: 3, t: 2 };
        let (p, _) = Participant::new(&params, 0);
        let result = p.proof_of_secret_key.verify(&p.index, &p.commitments[0]);

        assert!(result.is_ok());
    }
}
