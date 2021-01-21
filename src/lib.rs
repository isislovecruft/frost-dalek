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
//!
//! # Usage
//!
//! ```rust
//! # #[cfg(feature = "std")]
//! use frost_dalek::compute_message_hash;
//! # #[cfg(feature = "std")]
//! use frost_dalek::generate_commitment_share_lists;
//! use frost_dalek::DistributedKeyGeneration;
//! use frost_dalek::Parameters;
//! use frost_dalek::Participant;
//! # #[cfg(feature = "std")]
//! use frost_dalek::SignatureAggregator;
//!
//! use rand::rngs::OsRng;
//!
//! # #[cfg(feature = "std")]
//! # fn do_test() -> Result<(), ()> {
//! // Set up key shares for a threshold signature scheme which needs at least
//! // 2-out-of-3 signers.
//! let params = Parameters { t: 2, n: 3 };
//!
//! // Alice, Bob, and Carol each generate their secret polynomial coefficients
//! // and commitments to them, as well as a zero-knowledge proof of a secret key.
//! let (alice, alice_coeffs) = Participant::new(&params, 1);
//! let (bob, bob_coeffs) = Participant::new(&params, 2);
//! let (carol, carol_coeffs) = Participant::new(&params, 3);
//!
//! // They send these values to each of the other participants (out of scope
//! // for this library), or otherwise publish them somewhere.
//! //
//! // alice.send_to(bob);
//! // alice.send_to(carol);
//! // bob.send_to(alice);
//! // bob.send_to(carol);
//! // carol.send_to(alice);
//! // carol.send_to(bob);
//! //
//! // NOTE: They should only send the `alice`, `bob`, and `carol` structs, *not*
//! //       the `alice_coefficients`, etc.
//! //
//! // Bob and Carol verify Alice's zero-knowledge proof by doing:
//!
//! alice.proof_of_secret_key.verify(&alice.index, &alice.public_key().unwrap())?;
//!
//! // Similarly, Alice and Carol verify Bob's proof:
//! bob.proof_of_secret_key.verify(&bob.index, &bob.public_key().unwrap())?;
//!
//! // And, again, Alice and Bob verify Carol's proof:
//! carol.proof_of_secret_key.verify(&carol.index, &carol.public_key().unwrap())?;
//!
//! // Alice enters round one of the distributed key generation protocol.
//! let mut alice_other_participants: Vec<Participant> = vec!(bob.clone(), carol.clone());
//! let alice_state = DistributedKeyGeneration::<_>::new(&params, &alice.index, &alice_coeffs,
//!                                                      &mut alice_other_participants).or(Err(()))?;
//!
//! // Alice then collects the secret shares which they send to the other participants:
//! let alice_their_secret_shares = alice_state.their_secret_shares()?;
//! // send_to_bob(alice_their_secret_shares[0]);
//! // send_to_carol(alice_their_secret_shares[1]);
//!
//! // Bob enters round one of the distributed key generation protocol.
//! let mut bob_other_participants: Vec<Participant> = vec!(alice.clone(), carol.clone());
//! let bob_state = DistributedKeyGeneration::<_>::new(&params, &bob.index, &bob_coeffs,
//!                                                    &mut bob_other_participants).or(Err(()))?;
//!
//! // Bob then collects the secret shares which they send to the other participants:
//! let bob_their_secret_shares = bob_state.their_secret_shares()?;
//! // send_to_alice(bob_their_secret_shares[0]);
//! // send_to_carol(bob_their_secret_shares[1]);
//!
//! // Carol enters round one of the distributed key generation protocol.
//! let mut carol_other_participants: Vec<Participant> = vec!(alice.clone(), bob.clone());
//! let carol_state = DistributedKeyGeneration::<_>::new(&params, &carol.index, &carol_coeffs,
//!                                                      &mut carol_other_participants).or(Err(()))?;
//!
//! // Carol then collects the secret shares which they send to the other participants:
//! let carol_their_secret_shares = carol_state.their_secret_shares()?;
//! // send_to_alice(carol_their_secret_shares[0]);
//! // send_to_bob(carol_their_secret_shares[1]);
//!
//! // Each participant now has a vector of secret shares given to them by the other participants:
//! let alice_my_secret_shares = vec!(bob_their_secret_shares[0].clone(),
//!                                   carol_their_secret_shares[0].clone());
//! let bob_my_secret_shares = vec!(alice_their_secret_shares[0].clone(),
//!                                 carol_their_secret_shares[1].clone());
//! let carol_my_secret_shares = vec!(alice_their_secret_shares[1].clone(),
//!                                   bob_their_secret_shares[1].clone());
//!
//! // The participants then use these secret shares from the other participants to advance to
//! // round two of the distributed key generation protocol.
//! let alice_state = alice_state.to_round_two(alice_my_secret_shares)?;
//! let bob_state = bob_state.to_round_two(bob_my_secret_shares)?;
//! let carol_state = carol_state.to_round_two(carol_my_secret_shares)?;
//!
//! // Each participant can now derive their long-lived secret keys and the group's
//! // public key.
//! let (alice_group_key, alice_secret_key) = alice_state.finish(alice.public_key().unwrap())?;
//! let (bob_group_key, bob_secret_key) = bob_state.finish(bob.public_key().unwrap())?;
//! let (carol_group_key, carol_secret_key) = carol_state.finish(carol.public_key().unwrap())?;
//!
//! // They should all derive the same group public key.
//! assert!(alice_group_key == bob_group_key);
//! assert!(carol_group_key == bob_group_key);
//!
//! // Alice, Bob, and Carol can now create partial threshold signatures over an agreed upon
//! // message with their respective secret keys, which they can then give to a
//! // [`SignatureAggregator`] to create a 2-out-of-3 threshold signature.
//! let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
//! let message = b"This is a test of the tsunami alert system. This is only a test.";
//!
//! // To do this, they each pre-compute and publish a list of commitment shares.
//! let (alice_public_comshares, mut alice_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
//! let (carol_public_comshares, mut carol_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 3, 1);
//!
//! let mut aggregator = SignatureAggregator::new(params, bob_group_key.clone(), &context[..], &message[..]);
//!
//! // The aggregator takes note of each expected signer for this run of the protocol.
//! aggregator.include_signer(1, alice_public_comshares.commitments[0], (&alice_secret_key).into());
//! aggregator.include_signer(3, carol_public_comshares.commitments[0], (&carol_secret_key).into());
//!
//! // The aggregator should then publicly announce which participants are expected to be signers.
//! let signers = aggregator.get_signers();
//!
//! // Every signer should compute a hash of the message to be signed, along with, optionally,
//! // some additional context, such as public information about the run of the protocol.
//! let message_hash = compute_message_hash(&context[..], &message[..]);
//!
//! // They each then compute their partial signatures, and send these to the signature aggregator.
//! let alice_partial = alice_secret_key.sign(&message_hash, &alice_group_key,
//!                                           &mut alice_secret_comshares, 0, signers).or(Err(()))?;
//! let carol_partial = carol_secret_key.sign(&message_hash, &carol_group_key,
//!                                           &mut carol_secret_comshares, 0, signers).or(Err(()))?;
//!
//! aggregator.include_partial_signature(alice_partial);
//! aggregator.include_partial_signature(carol_partial);
//!
//! // Once all the expected signers have sent their partial signatures, the
//! // aggregator attempts to finalize its state, ensuring that there are no errors
//! // thus far in the partial signatures, before finally attempting to complete
//! // the aggregation of the partial signatures into a threshold signature.
//! let state = aggregator.finalize();
//!
//! // If the aggregator could not finalize the state, then the .finalize() method
//! // will return a `HashMap<u32, &str>` describing participant indices and the issues
//! // encountered for them.  These issues are guaranteed to be the fault of the aggregator,
//! // e.g. not collecting all the expected partial signatures, accepting two partial
//! // signatures from the same participant, etc.
//! assert!(state.is_ok());
//!
//! let aggregator = state.unwrap();
//!
//! // And the same for the actual aggregation, if there was an error then a
//! // `HashMap<u32, &str>` will be returned which maps participant indices to issues.
//! // Unlike before, however, these issues are guaranteed to be the fault of the
//! // corresponding participant, that is, if their partial signature was incorrect.
//! let result = aggregator.aggregate();
//!
//! assert!(result.is_ok());
//!
//! let threshold_signature = result.unwrap();
//!
//! // Anyone with the group public key can then verify the threshold signature
//! // in the same way they would for a standard Schnorr signature.
//! let verified = threshold_signature.verify(&alice_group_key, &message_hash)?;
//! # Ok(())}
//! # #[cfg(feature = "std")]
//! # fn main() { assert!(do_test().is_ok()); }
//! # #[cfg(not(feature = "std"))]
//! # fn main() {}
//! ```

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

// The signing protocol uses Hashmap (currently for both the signature aggregator
// and signers), which requires std.
#[cfg(feature = "std")]
pub mod signature;

pub use keygen::DistributedKeyGeneration;
pub use keygen::Participant;
pub use parameters::Parameters;
pub use precomputation::generate_commitment_share_lists;

#[cfg(feature = "std")]
pub use signature::compute_message_hash;
#[cfg(feature = "std")]
pub use signature::SignatureAggregator;
