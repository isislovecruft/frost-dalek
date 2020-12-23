// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2017-2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! A Rust implementation of [FROST]: Flexible Round-Optimised Schnorr Threshold Signatures.
//!
//! [FROST]: https://eprint.iacr.org/2020/852

#![no_std]
#![warn(future_incompatible)]
#![deny(missing_docs)]
#![allow(non_snake_case)]

#[cfg(not(any(feature = "std", feature = "alloc")))]
compile_error!("Either feature \"std\" or \"alloc\" must be enabled for this crate.");

// We use the vec! macro in unittests.
#[cfg(any(test, feature = "std"))]
#[macro_use]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod keygen;
pub mod parameters;
pub mod precomputation;
pub mod nizk;

// The signing protocol uses Hashmap (currently for the signature aggregator,
// only), which requires std.
#[cfg(any(test, feature = "std"))]
pub mod signature;

pub use keygen::DistributedKeyGeneration;
pub use keygen::Participant;
pub use parameters::Parameters;
pub use precomputation::generate_commitment_share_lists;
pub use signature::compute_message_hash;
pub use signature::SignatureAggregator;
