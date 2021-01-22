// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2017-2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! A Rust implementation of **[FROST]**: **F**lexible **R**ound-**O**ptimised **S**chnorr **T**hreshold signatures.
//!
//! Threshold signatures are a cryptographic construction wherein a subset, \\( t \\),
//! of a group of \\( n \\) signers can produce a valid signature.  For example, if
//! Alice, Bob, and Carol set up key materials for a 2-out-of-3 threshold signature
//! scheme, then the same public group key can be used to verify a message signed
//! by Alice and Carol as a different message signed by Bob and Carol.
//!
//! FROST signatures are unique in that they manage to optimise threshold signing into
//! a single round, while still safeguarding against [various] [cryptographic] [attacks]
//! that effect other threshold signing schemes, by utilising [commitments] to
//! pre-computed secret shares.
//!
//! For a more in-depth explanation of the mathematics involved, please see
//! [here](keygen/index.html), [here](precomputation/index.html), and
//! [here](signature/index.html).
//!
//! [FROST]: https://eprint.iacr.org/2020/852
//! [various]: https://eprint.iacr.org/2018/417
//! [cryptographic]: https://eprint.iacr.org/2020/945
//! [attacks]: https://www.researchgate.net/profile/Claus_Schnorr/publication/2900710_Security_of_Blind_Discrete_Log_Signatures_against_Interactive_Attacks/links/54231e540cf26120b7a6bb47.pdf
//! [commitments]: https://en.wikipedia.org/wiki/Commitment_scheme
//!
//! # Usage
//!
//! Alice, Bob, and Carol would like to set up a threshold signing scheme where
//! at least two of them need to sign on a given message to produce a valid
//! signature.
//!
//! ```rust
//! use frost_dalek::Parameters;
//!
//! let params = Parameters { t: 2, n: 3 };
//! ```
//!
//! ## Distributed Key Generation
//!
//! Alice, Bob, and Carol each generate their secret polynomial coefficients
//! (which make up each individual's personal secret key) and commitments to
//! them, as well as a zero-knowledge proof of their personal secret key.  Out
//! of scope, they each need to agree upon their *participant index* which is
//! some non-zero integer unique to each of them (these are the `1`, `2`, and
//! `3` in the following examples).
//! 
//! ```rust
//! # use frost_dalek::Parameters;
//! use frost_dalek::Participant;
//! #
//! # let params = Parameters { t: 2, n: 3 };
//! 
//! let (alice, alice_coefficients) = Participant::new(&params, 1);
//! let (bob, bob_coefficients) = Participant::new(&params, 2);
//! let (carol, carol_coefficients) = Participant::new(&params, 3);
//! ```
//!
//! They send these values to each of the other participants (also out of scope
//! for this library), or otherwise publish them publicly somewhere.
//!
//! ```rust
//! # // This comment is here just to silence the "this code block is empty" warning.
//! // send_to_bob(alice);
//! // send_to_carol(alice);
//! // send_to_alice(bob);
//! // send_to_carol(bob);
//! // send_to_alice(carol);
//! // send_to_bob(carol);
//! ```
//!
//! Note that they should only send the `alice`, `bob`, and `carol` structs, *not*
//! the `alice_coefficients`, etc., as the latter are their personal secret keys.
//!
//! Bob and Carol verify Alice's zero-knowledge proof by doing:
//!
//! ```rust
//! # use frost_dalek::Parameters;
//! # use frost_dalek::Participant;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! alice.proof_of_secret_key.verify(&alice.index, &alice.public_key().unwrap())?;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Similarly, Alice and Carol verify Bob's proof:
//!
//! ```rust
//! # use frost_dalek::Parameters;
//! # use frost_dalek::Participant;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! bob.proof_of_secret_key.verify(&bob.index, &bob.public_key().unwrap())?;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! And, again, Alice and Bob verify Carol's proof:
//!
//! ```rust
//! # use frost_dalek::Parameters;
//! # use frost_dalek::Participant;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! carol.proof_of_secret_key.verify(&carol.index, &carol.public_key().unwrap())?;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Alice enters round one of the distributed key generation protocol:
//!
//! ```rust
//! use frost_dalek::DistributedKeyGeneration;
//! # use frost_dalek::Parameters;
//! # use frost_dalek::Participant;
//! #
//! # fn do_test() -> Result<(), Vec<u32>> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//!
//! let mut alice_other_participants: Vec<Participant> = vec!(bob.clone(), carol.clone());
//! let alice_state = DistributedKeyGeneration::<_>::new(&params, &alice.index, &alice_coefficients,
//!                                                      &mut alice_other_participants)?;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Alice then collects the secret shares which they send to the other participants:
//!
//! ```rust
//! # use frost_dalek::DistributedKeyGeneration;
//! # use frost_dalek::Parameters;
//! # use frost_dalek::Participant;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! # let mut alice_other_participants: Vec<Participant> = vec!(bob.clone(), carol.clone());
//! # let alice_state = DistributedKeyGeneration::<_>::new(&params, &alice.index, &alice_coefficients,
//! #                                                      &mut alice_other_participants).or(Err(()))?;
//! let alice_their_secret_shares = alice_state.their_secret_shares()?;
//!
//! // send_to_bob(alice_their_secret_shares[0]);
//! // send_to_carol(alice_their_secret_shares[1]);
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Bob and Carol each do the same:
//!
//! ```rust
//! # use frost_dalek::DistributedKeyGeneration;
//! # use frost_dalek::Parameters;
//! # use frost_dalek::Participant;
//! #
//! # fn do_test() -> Result<(), Vec<u32>> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! let mut bob_other_participants: Vec<Participant> = vec!(alice.clone(), carol.clone());
//! let bob_state = DistributedKeyGeneration::<_>::new(&params, &bob.index, &bob_coefficients,
//!                                                    &mut bob_other_participants)?;
//! # Ok(()) }
//! # fn do_test2() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! # let mut bob_other_participants: Vec<Participant> = vec!(alice.clone(), carol.clone());
//! # let bob_state = DistributedKeyGeneration::<_>::new(&params, &bob.index, &bob_coefficients,
//! #                                                    &mut bob_other_participants).or(Err(()))?;
//!
//! let bob_their_secret_shares = bob_state.their_secret_shares()?;
//!
//! // send_to_alice(bob_their_secret_shares[0]);
//! // send_to_carol(bob_their_secret_shares[1]);
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); assert!(do_test2().is_ok()); }
//! ```
//!
//! and
//!
//! ```rust
//! # use frost_dalek::DistributedKeyGeneration;
//! # use frost_dalek::Parameters;
//! # use frost_dalek::Participant;
//! #
//! # fn do_test() -> Result<(), Vec<u32>> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! let mut carol_other_participants: Vec<Participant> = vec!(alice.clone(), bob.clone());
//! let carol_state = DistributedKeyGeneration::<_>::new(&params, &carol.index, &carol_coefficients,
//!                                                      &mut carol_other_participants)?;
//! # Ok(()) }
//! # fn do_test2() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! # let mut carol_other_participants: Vec<Participant> = vec!(alice.clone(), bob.clone());
//! # let carol_state = DistributedKeyGeneration::<_>::new(&params, &carol.index, &carol_coefficients,
//! #                                                      &mut carol_other_participants).or(Err(()))?;
//!
//! let carol_their_secret_shares = carol_state.their_secret_shares()?;
//!
//! // send_to_alice(carol_their_secret_shares[0]);
//! // send_to_bob(carol_their_secret_shares[1]);
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); assert!(do_test2().is_ok()); }
//! ```
//!
//! Each participant now has a vector of secret shares given to them by the other participants:
//!
//! ```rust
//! # use frost_dalek::DistributedKeyGeneration;
//! # use frost_dalek::Parameters;
//! # use frost_dalek::Participant;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! # let mut alice_other_participants: Vec<Participant> = vec!(bob.clone(), carol.clone());
//! # let alice_state = DistributedKeyGeneration::<_>::new(&params, &alice.index, &alice_coefficients,
//! #                                                      &mut alice_other_participants).or(Err(()))?;
//! # let alice_their_secret_shares = alice_state.their_secret_shares()?;
//! #
//! # let mut bob_other_participants: Vec<Participant> = vec!(alice.clone(), carol.clone());
//! # let bob_state = DistributedKeyGeneration::<_>::new(&params, &bob.index, &bob_coefficients,
//! #                                                    &mut bob_other_participants).or(Err(()))?;
//! # let bob_their_secret_shares = bob_state.their_secret_shares()?;
//! #
//! # let mut carol_other_participants: Vec<Participant> = vec!(alice.clone(), bob.clone());
//! # let carol_state = DistributedKeyGeneration::<_>::new(&params, &carol.index, &carol_coefficients,
//! #                                                      &mut carol_other_participants).or(Err(()))?;
//! # let carol_their_secret_shares = carol_state.their_secret_shares()?;
//! let alice_my_secret_shares = vec!(bob_their_secret_shares[0].clone(),
//!                                   carol_their_secret_shares[0].clone());
//! let bob_my_secret_shares = vec!(alice_their_secret_shares[0].clone(),
//!                                 carol_their_secret_shares[1].clone());
//! let carol_my_secret_shares = vec!(alice_their_secret_shares[1].clone(),
//!                                   bob_their_secret_shares[1].clone());
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! The participants then use these secret shares from the other participants to advance to
//! round two of the distributed key generation protocol.
//!
//! ```rust
//! # use frost_dalek::DistributedKeyGeneration;
//! # use frost_dalek::Parameters;
//! # use frost_dalek::Participant;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! # let mut alice_other_participants: Vec<Participant> = vec!(bob.clone(), carol.clone());
//! # let alice_state = DistributedKeyGeneration::<_>::new(&params, &alice.index, &alice_coefficients,
//! #                                                      &mut alice_other_participants).or(Err(()))?;
//! # let alice_their_secret_shares = alice_state.their_secret_shares()?;
//! #
//! # let mut bob_other_participants: Vec<Participant> = vec!(alice.clone(), carol.clone());
//! # let bob_state = DistributedKeyGeneration::<_>::new(&params, &bob.index, &bob_coefficients,
//! #                                                    &mut bob_other_participants).or(Err(()))?;
//! # let bob_their_secret_shares = bob_state.their_secret_shares()?;
//! #
//! # let mut carol_other_participants: Vec<Participant> = vec!(alice.clone(), bob.clone());
//! # let carol_state = DistributedKeyGeneration::<_>::new(&params, &carol.index, &carol_coefficients,
//! #                                                      &mut carol_other_participants).or(Err(()))?;
//! # let carol_their_secret_shares = carol_state.their_secret_shares()?;
//! # let alice_my_secret_shares = vec!(bob_their_secret_shares[0].clone(),
//! #                                   carol_their_secret_shares[0].clone());
//! # let bob_my_secret_shares = vec!(alice_their_secret_shares[0].clone(),
//! #                                 carol_their_secret_shares[1].clone());
//! # let carol_my_secret_shares = vec!(alice_their_secret_shares[1].clone(),
//! #                                   bob_their_secret_shares[1].clone());
//! #
//! let alice_state = alice_state.to_round_two(alice_my_secret_shares)?;
//! let bob_state = bob_state.to_round_two(bob_my_secret_shares)?;
//! let carol_state = carol_state.to_round_two(carol_my_secret_shares)?;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Each participant can now derive their long-lived, personal secret keys and the group's
//! public key.  They should all derive the same group public key.  They
//! also derive their [`IndividualPublicKey`]s from their [`IndividualSecretKey`]s.
//!
//! ```rust
//! # use frost_dalek::DistributedKeyGeneration;
//! # use frost_dalek::Parameters;
//! # use frost_dalek::Participant;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! # let mut alice_other_participants: Vec<Participant> = vec!(bob.clone(), carol.clone());
//! # let alice_state = DistributedKeyGeneration::<_>::new(&params, &alice.index, &alice_coefficients,
//! #                                                      &mut alice_other_participants).or(Err(()))?;
//! # let alice_their_secret_shares = alice_state.their_secret_shares()?;
//! #
//! # let mut bob_other_participants: Vec<Participant> = vec!(alice.clone(), carol.clone());
//! # let bob_state = DistributedKeyGeneration::<_>::new(&params, &bob.index, &bob_coefficients,
//! #                                                    &mut bob_other_participants).or(Err(()))?;
//! # let bob_their_secret_shares = bob_state.their_secret_shares()?;
//! #
//! # let mut carol_other_participants: Vec<Participant> = vec!(alice.clone(), bob.clone());
//! # let carol_state = DistributedKeyGeneration::<_>::new(&params, &carol.index, &carol_coefficients,
//! #                                                      &mut carol_other_participants).or(Err(()))?;
//! # let carol_their_secret_shares = carol_state.their_secret_shares()?;
//! # let alice_my_secret_shares = vec!(bob_their_secret_shares[0].clone(),
//! #                                   carol_their_secret_shares[0].clone());
//! # let bob_my_secret_shares = vec!(alice_their_secret_shares[0].clone(),
//! #                                 carol_their_secret_shares[1].clone());
//! # let carol_my_secret_shares = vec!(alice_their_secret_shares[1].clone(),
//! #                                   bob_their_secret_shares[1].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_secret_shares)?;
//! # let bob_state = bob_state.to_round_two(bob_my_secret_shares)?;
//! # let carol_state = carol_state.to_round_two(carol_my_secret_shares)?;
//! #
//! let (alice_group_key, alice_secret_key) = alice_state.finish(alice.public_key().unwrap())?;
//! let (bob_group_key, bob_secret_key) = bob_state.finish(bob.public_key().unwrap())?;
//! let (carol_group_key, carol_secret_key) = carol_state.finish(carol.public_key().unwrap())?;
//!
//! assert!(alice_group_key == bob_group_key);
//! assert!(carol_group_key == bob_group_key);
//!
//! let alice_public_key = alice_secret_key.to_public();
//! let bob_public_key = bob_secret_key.to_public();
//! let carol_public_key = carol_secret_key.to_public();
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! ## Precomputation and Partial Signatures
//!
//! Alice, Bob, and Carol can now create partial threshold signatures over an agreed upon
//! message with their respective secret keys, which they can then give to an untrusted
//! [`SignatureAggregator`] (which can be one of the participants) to create a
//! 2-out-of-3 threshold signature.  To do this, they each pre-compute (using
//! [`generate_commitment_share_lists`]) and publish a list of commitment shares.
//!
//! ```rust
//! # #[cfg(feature = "std")]
//! use frost_dalek::compute_message_hash;
//! # #[cfg(feature = "std")]
//! use frost_dalek::generate_commitment_share_lists;
//! # use frost_dalek::DistributedKeyGeneration;
//! # use frost_dalek::Parameters;
//! # use frost_dalek::Participant;
//! # #[cfg(feature = "std")]
//! use frost_dalek::SignatureAggregator;
//!
//! use rand::rngs::OsRng;
//! # #[cfg(feature = "std")]
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! # let mut alice_other_participants: Vec<Participant> = vec!(bob.clone(), carol.clone());
//! # let alice_state = DistributedKeyGeneration::<_>::new(&params, &alice.index, &alice_coefficients,
//! #                                                      &mut alice_other_participants).or(Err(()))?;
//! # let alice_their_secret_shares = alice_state.their_secret_shares()?;
//! #
//! # let mut bob_other_participants: Vec<Participant> = vec!(alice.clone(), carol.clone());
//! # let bob_state = DistributedKeyGeneration::<_>::new(&params, &bob.index, &bob_coefficients,
//! #                                                    &mut bob_other_participants).or(Err(()))?;
//! # let bob_their_secret_shares = bob_state.their_secret_shares()?;
//! #
//! # let mut carol_other_participants: Vec<Participant> = vec!(alice.clone(), bob.clone());
//! # let carol_state = DistributedKeyGeneration::<_>::new(&params, &carol.index, &carol_coefficients,
//! #                                                      &mut carol_other_participants).or(Err(()))?;
//! # let carol_their_secret_shares = carol_state.their_secret_shares()?;
//! # let alice_my_secret_shares = vec!(bob_their_secret_shares[0].clone(),
//! #                                   carol_their_secret_shares[0].clone());
//! # let bob_my_secret_shares = vec!(alice_their_secret_shares[0].clone(),
//! #                                 carol_their_secret_shares[1].clone());
//! # let carol_my_secret_shares = vec!(alice_their_secret_shares[1].clone(),
//! #                                   bob_their_secret_shares[1].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_secret_shares)?;
//! # let bob_state = bob_state.to_round_two(bob_my_secret_shares)?;
//! # let carol_state = carol_state.to_round_two(carol_my_secret_shares)?;
//! #
//! # let (alice_group_key, alice_secret_key) = alice_state.finish(alice.public_key().unwrap())?;
//! # let (bob_group_key, bob_secret_key) = bob_state.finish(bob.public_key().unwrap())?;
//! # let (carol_group_key, carol_secret_key) = carol_state.finish(carol.public_key().unwrap())?;
//! #
//! # let alice_public_key = alice_secret_key.to_public();
//! # let bob_public_key = bob_secret_key.to_public();
//! # let carol_public_key = carol_secret_key.to_public();
//!
//! let (alice_public_comshares, mut alice_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
//! let (bob_public_comshares, mut bob_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 2, 1);
//! let (carol_public_comshares, mut carol_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 3, 1);
//!
//! // Each application developer should choose a context string as unique to their usage as possible,
//! // in order to provide domain separation from other applications which use FROST signatures.
//! let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
//! let message = b"This is a test of the tsunami alert system. This is only a test.";
//!
//! // Every signer should compute a hash of the message to be signed, along with, optionally,
//! // some additional context, such as public information about the run of the protocol.
//! let message_hash = compute_message_hash(&context[..], &message[..]);
//!
//! let mut aggregator = SignatureAggregator::new(params, bob_group_key.clone(), &context[..], &message[..]);
//! # Ok(()) }
//! # #[cfg(feature = "std")]
//! # fn main() { assert!(do_test().is_ok()); }
//! # #[cfg(not(feature = "std"))]
//! # fn main() { }
//! ```
//!
//! The aggregator takes note of each expected signer for this run of the protocol.  For this run,
//! we'll have Alice and Carol sign.
//!
//! ```rust
//! # #[cfg(feature = "std")]
//! # use frost_dalek::compute_message_hash;
//! # #[cfg(feature = "std")]
//! # use frost_dalek::generate_commitment_share_lists;
//! # use frost_dalek::DistributedKeyGeneration;
//! # use frost_dalek::IndividualPublicKey;
//! # use frost_dalek::Parameters;
//! # use frost_dalek::Participant;
//! # #[cfg(feature = "std")]
//! # use frost_dalek::SignatureAggregator;
//! #
//! # use rand::rngs::OsRng;
//! #
//! # #[cfg(feature = "std")]
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! # let mut alice_other_participants: Vec<Participant> = vec!(bob.clone(), carol.clone());
//! # let alice_state = DistributedKeyGeneration::<_>::new(&params, &alice.index, &alice_coefficients,
//! #                                                      &mut alice_other_participants).or(Err(()))?;
//! # let alice_their_secret_shares = alice_state.their_secret_shares()?;
//! #
//! # let mut bob_other_participants: Vec<Participant> = vec!(alice.clone(), carol.clone());
//! # let bob_state = DistributedKeyGeneration::<_>::new(&params, &bob.index, &bob_coefficients,
//! #                                                    &mut bob_other_participants).or(Err(()))?;
//! # let bob_their_secret_shares = bob_state.their_secret_shares()?;
//! #
//! # let mut carol_other_participants: Vec<Participant> = vec!(alice.clone(), bob.clone());
//! # let carol_state = DistributedKeyGeneration::<_>::new(&params, &carol.index, &carol_coefficients,
//! #                                                      &mut carol_other_participants).or(Err(()))?;
//! # let carol_their_secret_shares = carol_state.their_secret_shares()?;
//! # let alice_my_secret_shares = vec!(bob_their_secret_shares[0].clone(),
//! #                                   carol_their_secret_shares[0].clone());
//! # let bob_my_secret_shares = vec!(alice_their_secret_shares[0].clone(),
//! #                                 carol_their_secret_shares[1].clone());
//! # let carol_my_secret_shares = vec!(alice_their_secret_shares[1].clone(),
//! #                                   bob_their_secret_shares[1].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_secret_shares)?;
//! # let bob_state = bob_state.to_round_two(bob_my_secret_shares)?;
//! # let carol_state = carol_state.to_round_two(carol_my_secret_shares)?;
//! #
//! # let (alice_group_key, alice_secret_key) = alice_state.finish(alice.public_key().unwrap())?;
//! # let (bob_group_key, bob_secret_key) = bob_state.finish(bob.public_key().unwrap())?;
//! # let (carol_group_key, carol_secret_key) = carol_state.finish(carol.public_key().unwrap())?;
//! #
//! # let alice_public_key = alice_secret_key.to_public();
//! # let bob_public_key = bob_secret_key.to_public();
//! # let carol_public_key = carol_secret_key.to_public();
//! #
//! # let (alice_public_comshares, mut alice_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
//! # let (bob_public_comshares, mut bob_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 2, 1);
//! # let (carol_public_comshares, mut carol_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 3, 1);
//! #
//! # let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
//! # let message = b"This is a test of the tsunami alert system. This is only a test.";
//! #
//! # let message_hash = compute_message_hash(&context[..], &message[..]);
//! #
//! # let mut aggregator = SignatureAggregator::new(params, bob_group_key.clone(), &context[..], &message[..]);
//! #
//! aggregator.include_signer(1, alice_public_comshares.commitments[0], alice_public_key);
//! aggregator.include_signer(3, carol_public_comshares.commitments[0], carol_public_key);
//! # Ok(()) }
//! # #[cfg(feature = "std")]
//! # fn main() { assert!(do_test().is_ok()); }
//! # #[cfg(not(feature = "std"))]
//! # fn main() { }
//! ```
//!
//! The aggregator should then publicly announce which participants are expected to be signers.
//!
//! ```rust,ignore
//! let signers = aggregator.get_signers();
//! ```
//!
//! Alice and Carol each then compute their partial signatures, and send these to the signature aggregator.
//!
//! ```rust
//! # #[cfg(feature = "std")]
//! # use frost_dalek::compute_message_hash;
//! # #[cfg(feature = "std")]
//! # use frost_dalek::generate_commitment_share_lists;
//! # use frost_dalek::DistributedKeyGeneration;
//! # use frost_dalek::Parameters;
//! # use frost_dalek::Participant;
//! # #[cfg(feature = "std")]
//! # use frost_dalek::SignatureAggregator;
//! #
//! # use rand::rngs::OsRng;
//! #
//! # #[cfg(feature = "std")]
//! # fn do_test() -> Result<(), &'static str> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! # let mut alice_other_participants: Vec<Participant> = vec!(bob.clone(), carol.clone());
//! # let alice_state = DistributedKeyGeneration::<_>::new(&params, &alice.index, &alice_coefficients,
//! #                                                      &mut alice_other_participants).or(Err(""))?;
//! # let alice_their_secret_shares = alice_state.their_secret_shares().or(Err(""))?;
//! #
//! # let mut bob_other_participants: Vec<Participant> = vec!(alice.clone(), carol.clone());
//! # let bob_state = DistributedKeyGeneration::<_>::new(&params, &bob.index, &bob_coefficients,
//! #                                                    &mut bob_other_participants).or(Err(""))?;
//! # let bob_their_secret_shares = bob_state.their_secret_shares().or(Err(""))?;
//! #
//! # let mut carol_other_participants: Vec<Participant> = vec!(alice.clone(), bob.clone());
//! # let carol_state = DistributedKeyGeneration::<_>::new(&params, &carol.index, &carol_coefficients,
//! #                                                      &mut carol_other_participants).or(Err(""))?;
//! # let carol_their_secret_shares = carol_state.their_secret_shares().or(Err(""))?;
//! # let alice_my_secret_shares = vec!(bob_their_secret_shares[0].clone(),
//! #                                   carol_their_secret_shares[0].clone());
//! # let bob_my_secret_shares = vec!(alice_their_secret_shares[0].clone(),
//! #                                 carol_their_secret_shares[1].clone());
//! # let carol_my_secret_shares = vec!(alice_their_secret_shares[1].clone(),
//! #                                   bob_their_secret_shares[1].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_secret_shares).or(Err(""))?;
//! # let bob_state = bob_state.to_round_two(bob_my_secret_shares).or(Err(""))?;
//! # let carol_state = carol_state.to_round_two(carol_my_secret_shares).or(Err(""))?;
//! #
//! # let (alice_group_key, alice_secret_key) = alice_state.finish(alice.public_key().unwrap()).or(Err(""))?;
//! # let (bob_group_key, bob_secret_key) = bob_state.finish(bob.public_key().unwrap()).or(Err(""))?;
//! # let (carol_group_key, carol_secret_key) = carol_state.finish(carol.public_key().unwrap()).or(Err(""))?;
//! #
//! # let alice_public_key = alice_secret_key.to_public();
//! # let bob_public_key = bob_secret_key.to_public();
//! # let carol_public_key = carol_secret_key.to_public();
//! #
//! # let (alice_public_comshares, mut alice_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
//! # let (bob_public_comshares, mut bob_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 2, 1);
//! # let (carol_public_comshares, mut carol_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 3, 1);
//! #
//! # let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
//! # let message = b"This is a test of the tsunami alert system. This is only a test.";
//! #
//! # let message_hash = compute_message_hash(&context[..], &message[..]);
//! #
//! # let mut aggregator = SignatureAggregator::new(params, bob_group_key.clone(), &context[..], &message[..]);
//! #
//! # aggregator.include_signer(1, alice_public_comshares.commitments[0], (&alice_secret_key).into());
//! # aggregator.include_signer(3, carol_public_comshares.commitments[0], (&carol_secret_key).into());
//! #
//! # let signers = aggregator.get_signers();
//!
//! let alice_partial = alice_secret_key.sign(&message_hash, &alice_group_key,
//!                                           &mut alice_secret_comshares, 0, signers)?;
//! let carol_partial = carol_secret_key.sign(&message_hash, &carol_group_key,
//!                                           &mut carol_secret_comshares, 0, signers)?;
//!
//! aggregator.include_partial_signature(alice_partial);
//! aggregator.include_partial_signature(carol_partial);
//! # Ok(()) }
//! # #[cfg(feature = "std")]
//! # fn main() { assert!(do_test().is_ok()); }
//! # #[cfg(not(feature = "std"))]
//! # fn main() { }
//! ```
//!
//! ## Signature Aggregation
//!
//! Once all the expected signers have sent their partial signatures, the
//! aggregator attempts to finalize its state, ensuring that there are no errors
//! thus far in the partial signatures, before finally attempting to complete
//! the aggregation of the partial signatures into a threshold signature.
//!
//! ```rust,ignore
//! let aggregator = aggregator.finalize()?;
//! ```
//!
//! If the aggregator could not finalize the state, then the `.finalize()` method
//! will return a `HashMap<u32, &'static str>` describing participant indices and the issues
//! encountered for them.  These issues are **guaranteed to be the fault of the aggregator**,
//! e.g. not collecting all the expected partial signatures, accepting two partial
//! signatures from the same participant, etc.
//!
//! And the same for the actual aggregation, if there was an error then a
//! `HashMap<u32, &'static str>` will be returned which maps participant indices to issues.
//! Unlike before, however, these issues are guaranteed to be the fault of the
//! corresponding participant, specifically, that their partial signature was invalid.
//!
//! ```rust,ignore
//! let threshold_signature = aggregator.aggregate()?;
//! ```
//!
//! Anyone with the group public key can then verify the threshold signature
//! in the same way they would for a standard Schnorr signature.
//!
//! ```rust,ignore
//! let verified = threshold_signature.verify(&alice_group_key, &message_hash)?;
//! ```
//!
//! # Note on `no_std` usage
//!
//! Most of this crate is `no_std` compliant, however, the current
//! implementation uses `HashMap`s for the signature creation and aggregation
//! protocols, and thus requires the standard library.

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
pub use keygen::GroupKey;
pub use keygen::IndividualPublicKey;
pub use keygen::Participant;
pub use keygen::SecretKey as IndividualSecretKey;
pub use parameters::Parameters;
pub use precomputation::generate_commitment_share_lists;

#[cfg(feature = "std")]
pub use signature::compute_message_hash;
#[cfg(feature = "std")]
pub use signature::SignatureAggregator;
