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

use rand::CryptoRng;
use rand::Rng;

use sha2::Digest;
use sha2::Sha512;

/// A proof of knowledge of a secret key, created by making a Schnorr signature
/// with the secret key.
///
/// This proof is created by making a pseudo-Schnorr signature,
/// \\( \sigma\_i = (s\_i, r\_i) \\) using \\( a\_{i0} \\) (from
/// `frost_dalek::keygen::DistributedKeyGeneration::<RoundOne>::compute_share`)
/// as the secret key, such that \\( k \stackrel{\\$}{\leftarrow} \mathbb{Z}\_q \\),
/// \\( M\_i = g^k \\), \\( s\_i = \mathcal{H}(i, \phi, g^{a\_{i0}}, M\_i) \\),
/// \\( r\_i = k + a\_{i0} \cdot s\_i \\).
///
/// Verification is done by calculating \\(M'\_i = g^r + A\_i^{-s}\\),
/// where \\(A\_i = g^{a_i}\\), and using it to compute
/// \\(s'\_i = \mathcal{H}(i, \phi, A\_i, M'\_i)\\), then finally
/// \\(s\_i \stackrel{?}{=} s'\_i\\).
#[derive(Clone, Debug)]
pub struct NizkOfSecretKey {
    /// The scalar portion of the Schnorr signature encoding the context.
    s: Scalar,
    /// The scalar portion of the Schnorr signature which is the actual signature.
    r: Scalar,
}

impl NizkOfSecretKey {
    /// Prove knowledge of a secret key.
    pub fn prove(
        index: &u32,
        secret_key: &Scalar,
        public_key: &RistrettoPoint,
        mut csprng: impl Rng + CryptoRng,
    ) -> Self
    {
        let k: Scalar = Scalar::random(&mut csprng);
        let M: RistrettoPoint = &k * &RISTRETTO_BASEPOINT_TABLE;

        let mut hram = Sha512::new();

        hram.update(index.to_be_bytes());
        hram.update("Φ");
        hram.update(public_key.compress().as_bytes());
        hram.update(M.compress().as_bytes());

        let s = Scalar::from_hash(hram);
        let r = k + (secret_key * s);

        NizkOfSecretKey { s, r }
    }

    /// Verify that the prover does indeed know the secret key.
    pub fn verify(&self, index: &u32, public_key: &RistrettoPoint) -> Result<(), ()> {
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

        Err(())
    }
}
