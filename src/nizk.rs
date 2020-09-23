// -*- mode: rust; -*-
//
// This file is part of dalek-frost.
// Copyright (c) 2020 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Zero-knowledge proofs.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand::rngs::OsRng;

use sha2::Digest;
use sha2::Sha512;

use crate::ProofError;
use crate::keygen::Coefficients;

/// A proof of knowledge of a secret key, created by making a Schnorr signature
/// with the secret key.
pub struct NizkOfSecretKey {
    /// The scalar portion of the Schnorr signature encoding the context.
    s: Scalar,
    /// The scalar portion of the Schnorr signature which is the actual signature.
    r: Scalar,
}

impl NizkOfSecretKey {
    /// Prove knowledge of a secret key.
    ///
    /// This proof is created by making a Schnorr signature,
    /// \\( \alpha_i = (s_i, r_i) \\) using \\( a_{i0} \\) (from `DkgRoundOne::compute_share`)
    /// as the secret key, such that \\( k \gets^{$} \mathbb{Z}_q \\),
    /// \\( M_i = g^k \\), \\( s_i = H(i, \phi, g^{a_{i0}}, M_i) \\),
    /// \\( r_i = k + a_{i0} \mdot s_i \\).
    pub fn prove(index: &u32, coefficients: &Coefficients, public_key: &RistrettoPoint) -> Self {
        let mut rng: OsRng = OsRng;
        let k: Scalar = Scalar::random(&mut rng);
        let M: RistrettoPoint = &k * &RISTRETTO_BASEPOINT_TABLE;

        let mut hram = Sha512::new();

        hram.update(index.to_be_bytes());
        hram.update("Φ");
        hram.update(public_key.compress().as_bytes());
        hram.update(M.compress().as_bytes());

        let s = Scalar::from_hash(hram);
        let r = k + (coefficients.0[0] * s);

        NizkOfSecretKey { s, r }
    }

    /// Verify that the prover does indeed know the secret key.
    pub fn verify(&self, index: &u32, public_key: &RistrettoPoint) -> Result<(), ProofError> {
        let M_prime: RistrettoPoint = (&RISTRETTO_BASEPOINT_TABLE * &self.r) + (public_key * -&self.s);

        let mut hram = Sha512::new();

        hram.update(index.to_be_bytes());
        hram.update("Φ");
        hram.update(public_key.compress().as_bytes());
        hram.update(M_prime.compress().as_bytes());

        let s_prime = Scalar::from_hash(hram);

        if self.s == s_prime {
            return Ok(());
        }

        Err(ProofError)
    }
}
