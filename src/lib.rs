// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2017-2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! A Rust implementation of [FROST](FROST): Flexible Round-Optimised Schnorr Threshold Signatures.
//!
//! [FROST]: https://eprint.iacr.org/2020/852

#![warn(future_incompatible)]
#![deny(missing_docs)]
#![allow(non_snake_case)]

pub mod errors;
pub mod keygen;
pub mod parameters;
pub mod nizk;

pub use errors::ProofError; // XXX fixme real error handling;
pub use keygen::Participant;
pub use parameters::Parameters;
