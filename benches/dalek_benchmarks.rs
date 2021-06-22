// -*- mode: rust; -*-
//
// This file is part of dalek-frost.
// Copyright (c) 2020 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Benchmarks for FROST.

#[macro_use]
extern crate criterion;

use criterion::Criterion;
use criterion::black_box;

use rand::rngs::OsRng;

use frost_dalek::compute_message_hash;
use frost_dalek::generate_commitment_share_lists;
use frost_dalek::DistributedKeyGeneration;
use frost_dalek::Parameters;
use frost_dalek::Participant;
use frost_dalek::SignatureAggregator;

mod dkg_benches {
    use super::*;

    fn participant_new(c: &mut Criterion) {
        let params = Parameters { n: 5, t: 3 };
        c.bench_function("Participant creation", move |b| b.iter(|| Participant::new(&params, 1)));
    }

    fn round_one_3_out_of_5(c: &mut Criterion) {
        let params = Parameters { n: 5, t: 3 };

        let (p1, p1coeffs) = Participant::new(&params, 1);
        let (p2, _p2coeffs) = Participant::new(&params, 2);
        let (p3, _p3coeffs) = Participant::new(&params, 3);
        let (p4, _p4coeffs) = Participant::new(&params, 4);
        let (p5, _p5coeffs) = Participant::new(&params, 5);

        let mut p1_other_participants: Vec<Participant> = vec!(p2.clone(), p3.clone(), p4.clone(), p5.clone());
        c.bench_function("Round One", move |b| {
            b.iter(|| DistributedKeyGeneration::<_>::new(&params,
                                                         &p1.index,
                                                         &p1coeffs,
                                                         &mut p1_other_participants));
        });
    }

    fn round_two_3_out_of_5(c: &mut Criterion) {
        let params = Parameters { n: 5, t: 3 };

        let (p1, p1coeffs) = Participant::new(&params, 1);
        let (p2, p2coeffs) = Participant::new(&params, 2);
        let (p3, p3coeffs) = Participant::new(&params, 3);
        let (p4, p4coeffs) = Participant::new(&params, 4);
        let (p5, p5coeffs) = Participant::new(&params, 5);

        let mut p1_other_participants: Vec<Participant> = vec!(p2.clone(), p3.clone(), p4.clone(), p5.clone());
        let p1_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p1.index,
                                                          &p1coeffs,
                                                          &mut p1_other_participants).unwrap();

        let mut p2_other_participants: Vec<Participant> = vec!(p1.clone(), p3.clone(), p4.clone(), p5.clone());
        let p2_state = DistributedKeyGeneration::<>::new(&params,
                                                         &p2.index,
                                                         &p2coeffs,
                                                         &mut p2_other_participants).unwrap();
        let p2_their_secret_shares = p2_state.their_secret_shares().unwrap();

        let mut p3_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p4.clone(), p5.clone());
        let p3_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p3.index,
                                                          &p3coeffs,
                                                          &mut p3_other_participants).unwrap();
        let p3_their_secret_shares = p3_state.their_secret_shares().unwrap();

        let mut p4_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone(), p5.clone());
        let p4_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p4.index,
                                                          &p4coeffs,
                                                          &mut p4_other_participants).unwrap();
        let p4_their_secret_shares = p4_state.their_secret_shares().unwrap();

        let mut p5_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone(), p4.clone());
        let p5_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p5.index,
                                                          &p5coeffs,
                                                          &mut p5_other_participants).unwrap();
        let p5_their_secret_shares = p5_state.their_secret_shares().unwrap();

        let p1_my_secret_shares = vec!(p2_their_secret_shares[0].clone(), // XXX FIXME indexing
                                       p3_their_secret_shares[0].clone(),
                                       p4_their_secret_shares[0].clone(),
                                       p5_their_secret_shares[0].clone());

        c.bench_function("Round Two", move |b| {
            b.iter(|| p1_state.clone().to_round_two(p1_my_secret_shares.clone()));
        });
    }

    fn long_term_verification_shares_3_out_of_5(c: &mut Criterion) {
        let params = Parameters { n: 5, t: 3 };

        let (p1, p1coeffs) = Participant::new(&params, 1);
        let (p2, p2coeffs) = Participant::new(&params, 2);
        let (p3, p3coeffs) = Participant::new(&params, 3);
        let (p4, p4coeffs) = Participant::new(&params, 4);
        let (p5, p5coeffs) = Participant::new(&params, 5);

        let mut p1_other_participants: Vec<Participant> = vec!(p2.clone(), p3.clone(), p4.clone(), p5.clone());
        let p1_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p1.index,
                                                          &p1coeffs,
                                                          &mut p1_other_participants).unwrap();

        let mut p2_other_participants: Vec<Participant> = vec!(p1.clone(), p3.clone(), p4.clone(), p5.clone());
        let p2_state = DistributedKeyGeneration::<>::new(&params,
                                                         &p2.index,
                                                         &p2coeffs,
                                                         &mut p2_other_participants).unwrap();
        let p2_their_secret_shares = p2_state.their_secret_shares().unwrap();

        let mut p3_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p4.clone(), p5.clone());
        let p3_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p3.index,
                                                          &p3coeffs,
                                                          &mut p3_other_participants).unwrap();
        let p3_their_secret_shares = p3_state.their_secret_shares().unwrap();

        let mut p4_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone(), p5.clone());
        let p4_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p4.index,
                                                          &p4coeffs,
                                                          &mut p4_other_participants).unwrap();
        let p4_their_secret_shares = p4_state.their_secret_shares().unwrap();

        let mut p5_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone(), p4.clone());
        let p5_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p5.index,
                                                          &p5coeffs,
                                                          &mut p5_other_participants).unwrap();
        let p5_their_secret_shares = p5_state.their_secret_shares().unwrap();

        let p1_my_secret_shares = vec!(p2_their_secret_shares[0].clone(), // XXX FIXME indexing
                                       p3_their_secret_shares[0].clone(),
                                       p4_their_secret_shares[0].clone(),
                                       p5_their_secret_shares[0].clone());

        let p1_state = p1_state.to_round_two(p1_my_secret_shares).unwrap();
        c.bench_function("LT Verification Shares", move |b| {
            b.iter(|| {
              let pubshare_p2 = p1_state.calculate_other_verification_share(black_box(&2), &p1);
              let pubshare_p3 = p1_state.calculate_other_verification_share(black_box(&3), &p1);
              let pubshare_p4 = p1_state.calculate_other_verification_share(black_box(&4), &p1);
              let pubshare_p5 = p1_state.calculate_other_verification_share(black_box(&5), &p1);
              (pubshare_p2, pubshare_p3, pubshare_p4, pubshare_p5)
              });
        });
    }

    fn finish_3_out_of_5(c: &mut Criterion) {
        let params = Parameters { n: 5, t: 3 };

        let (p1, p1coeffs) = Participant::new(&params, 1);
        let (p2, p2coeffs) = Participant::new(&params, 2);
        let (p3, p3coeffs) = Participant::new(&params, 3);
        let (p4, p4coeffs) = Participant::new(&params, 4);
        let (p5, p5coeffs) = Participant::new(&params, 5);

        let mut p1_other_participants: Vec<Participant> = vec!(p2.clone(), p3.clone(), p4.clone(), p5.clone());
        let p1_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p1.index,
                                                          &p1coeffs,
                                                          &mut p1_other_participants).unwrap();
        
        let mut p2_other_participants: Vec<Participant> = vec!(p1.clone(), p3.clone(), p4.clone(), p5.clone());
        let p2_state = DistributedKeyGeneration::<>::new(&params,
                                                         &p2.index,
                                                         &p2coeffs,
                                                         &mut p2_other_participants).unwrap();
        let p2_their_secret_shares = p2_state.their_secret_shares().unwrap();

        let mut p3_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p4.clone(), p5.clone());
        let p3_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p3.index,
                                                          &p3coeffs,
                                                          &mut p3_other_participants).unwrap();
        let p3_their_secret_shares = p3_state.their_secret_shares().unwrap();

        let mut p4_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone(), p5.clone());
        let p4_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p4.index,
                                                          &p4coeffs,
                                                          &mut p4_other_participants).unwrap();
        let p4_their_secret_shares = p4_state.their_secret_shares().unwrap();

        let mut p5_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone(), p4.clone());
        let p5_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p5.index,
                                                          &p5coeffs,
                                                          &mut p5_other_participants).unwrap();
        let p5_their_secret_shares = p5_state.their_secret_shares().unwrap();

        let p1_my_secret_shares = vec!(p2_their_secret_shares[0].clone(), // XXX FIXME indexing
                                       p3_their_secret_shares[0].clone(),
                                       p4_their_secret_shares[0].clone(),
                                       p5_their_secret_shares[0].clone());

        let p1_state = p1_state.to_round_two(p1_my_secret_shares).unwrap();
        
        c.bench_function("Finish", move |b| {
            let pk = p1.public_key().unwrap();

            b.iter(|| p1_state.clone().finish(pk));
        });
    }

    criterion_group! {
        name = dkg_benches;
        config = Criterion::default();
        targets =
            participant_new,
            round_one_3_out_of_5,
            round_two_3_out_of_5,
            long_term_verification_shares_3_out_of_5,
            finish_3_out_of_5,
    }
}

mod sign_benches {
    use super::*;

    fn partial_sign_3_out_of_5(c: &mut Criterion) {
        let params = Parameters { n: 5, t: 3 };

        let (p1, p1coeffs) = Participant::new(&params, 1);
        let (p2, p2coeffs) = Participant::new(&params, 2);
        let (p3, p3coeffs) = Participant::new(&params, 3);
        let (p4, p4coeffs) = Participant::new(&params, 4);
        let (p5, p5coeffs) = Participant::new(&params, 5);

        let mut p1_other_participants: Vec<Participant> = vec!(p2.clone(), p3.clone(), p4.clone(), p5.clone());
        let p1_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p1.index,
                                                          &p1coeffs,
                                                          &mut p1_other_participants).unwrap();
        let p1_their_secret_shares = p1_state.their_secret_shares().unwrap();
        
        let mut p2_other_participants: Vec<Participant> = vec!(p1.clone(), p3.clone(), p4.clone(), p5.clone());
        let p2_state = DistributedKeyGeneration::<>::new(&params,
                                                         &p2.index,
                                                         &p2coeffs,
                                                         &mut p2_other_participants).unwrap();
        let p2_their_secret_shares = p2_state.their_secret_shares().unwrap();

        let mut p3_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p4.clone(), p5.clone());
        let p3_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p3.index,
                                                          &p3coeffs,
                                                          &mut p3_other_participants).unwrap();
        let p3_their_secret_shares = p3_state.their_secret_shares().unwrap();

        let mut p4_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone(), p5.clone());
        let p4_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p4.index,
                                                          &p4coeffs,
                                                          &mut p4_other_participants).unwrap();
        let p4_their_secret_shares = p4_state.their_secret_shares().unwrap();

        let mut p5_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone(), p4.clone());
        let p5_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p5.index,
                                                          &p5coeffs,
                                                          &mut p5_other_participants).unwrap();
        let p5_their_secret_shares = p5_state.their_secret_shares().unwrap();

        let p1_my_secret_shares = vec!(p2_their_secret_shares[0].clone(), // XXX FIXME indexing
                                       p3_their_secret_shares[0].clone(),
                                       p4_their_secret_shares[0].clone(),
                                       p5_their_secret_shares[0].clone());

        let p2_my_secret_shares = vec!(p1_their_secret_shares[0].clone(),
                                       p3_their_secret_shares[1].clone(),
                                       p4_their_secret_shares[1].clone(),
                                       p5_their_secret_shares[1].clone());
        
        let p3_my_secret_shares = vec!(p1_their_secret_shares[1].clone(),
                                       p2_their_secret_shares[1].clone(),
                                       p4_their_secret_shares[2].clone(),
                                       p5_their_secret_shares[2].clone());
        
        let p4_my_secret_shares = vec!(p1_their_secret_shares[2].clone(),
                                       p2_their_secret_shares[2].clone(),
                                       p3_their_secret_shares[2].clone(),
                                       p5_their_secret_shares[3].clone());
        
        let p5_my_secret_shares = vec!(p1_their_secret_shares[3].clone(),
                                       p2_their_secret_shares[3].clone(),
                                       p3_their_secret_shares[3].clone(),
                                       p4_their_secret_shares[3].clone());

        let p1_state = p1_state.to_round_two(p1_my_secret_shares).unwrap();
        let p2_state = p2_state.to_round_two(p2_my_secret_shares).unwrap();
        let p3_state = p3_state.to_round_two(p3_my_secret_shares).unwrap();
        let p4_state = p4_state.to_round_two(p4_my_secret_shares).unwrap();
        let p5_state = p5_state.to_round_two(p5_my_secret_shares).unwrap();

        let (group_key, p1_sk) = p1_state.finish(p1.public_key().unwrap()).unwrap();
        let (_, _) = p2_state.finish(p2.public_key().unwrap()).unwrap();
        let (_, p3_sk) = p3_state.finish(p3.public_key().unwrap()).unwrap();
        let (_, p4_sk) = p4_state.finish(p4.public_key().unwrap()).unwrap();
        let (_, _) = p5_state.finish(p5.public_key().unwrap()).unwrap();

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (p3_public_comshares, _p3_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 3, 1);
        let (p4_public_comshares, _p4_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 4, 1);

        let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());
        aggregator.include_signer(3, p3_public_comshares.commitments[0], (&p3_sk).into());
        aggregator.include_signer(4, p4_public_comshares.commitments[0], (&p4_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        c.bench_function("Partial signature creation", move |b| {
            b.iter(|| p1_sk.sign(&message_hash, &group_key, &mut p1_secret_comshares, 0, signers));
        });
    }

    fn signature_aggregation_3_out_of_5(c: &mut Criterion) {
        let params = Parameters { n: 5, t: 3 };

        let (p1, p1coeffs) = Participant::new(&params, 1);
        let (p2, p2coeffs) = Participant::new(&params, 2);
        let (p3, p3coeffs) = Participant::new(&params, 3);
        let (p4, p4coeffs) = Participant::new(&params, 4);
        let (p5, p5coeffs) = Participant::new(&params, 5);

        let mut p1_other_participants: Vec<Participant> = vec!(p2.clone(), p3.clone(), p4.clone(), p5.clone());
        let p1_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p1.index,
                                                          &p1coeffs,
                                                          &mut p1_other_participants).unwrap();
        let p1_their_secret_shares = p1_state.their_secret_shares().unwrap();
        
        let mut p2_other_participants: Vec<Participant> = vec!(p1.clone(), p3.clone(), p4.clone(), p5.clone());
        let p2_state = DistributedKeyGeneration::<>::new(&params,
                                                         &p2.index,
                                                         &p2coeffs,
                                                         &mut p2_other_participants).unwrap();
        let p2_their_secret_shares = p2_state.their_secret_shares().unwrap();

        let mut p3_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p4.clone(), p5.clone());
        let p3_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p3.index,
                                                          &p3coeffs,
                                                          &mut p3_other_participants).unwrap();
        let p3_their_secret_shares = p3_state.their_secret_shares().unwrap();

        let mut p4_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone(), p5.clone());
        let p4_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p4.index,
                                                          &p4coeffs,
                                                          &mut p4_other_participants).unwrap();
        let p4_their_secret_shares = p4_state.their_secret_shares().unwrap();

        let mut p5_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone(), p4.clone());
        let p5_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p5.index,
                                                          &p5coeffs,
                                                          &mut p5_other_participants).unwrap();
        let p5_their_secret_shares = p5_state.their_secret_shares().unwrap();

        let p1_my_secret_shares = vec!(p2_their_secret_shares[0].clone(), // XXX FIXME indexing
                                       p3_their_secret_shares[0].clone(),
                                       p4_their_secret_shares[0].clone(),
                                       p5_their_secret_shares[0].clone());

        let p2_my_secret_shares = vec!(p1_their_secret_shares[0].clone(),
                                       p3_their_secret_shares[1].clone(),
                                       p4_their_secret_shares[1].clone(),
                                       p5_their_secret_shares[1].clone());
        
        let p3_my_secret_shares = vec!(p1_their_secret_shares[1].clone(),
                                       p2_their_secret_shares[1].clone(),
                                       p4_their_secret_shares[2].clone(),
                                       p5_their_secret_shares[2].clone());
        
        let p4_my_secret_shares = vec!(p1_their_secret_shares[2].clone(),
                                       p2_their_secret_shares[2].clone(),
                                       p3_their_secret_shares[2].clone(),
                                       p5_their_secret_shares[3].clone());
        
        let p5_my_secret_shares = vec!(p1_their_secret_shares[3].clone(),
                                       p2_their_secret_shares[3].clone(),
                                       p3_their_secret_shares[3].clone(),
                                       p4_their_secret_shares[3].clone());

        let p1_state = p1_state.to_round_two(p1_my_secret_shares).unwrap();
        let p2_state = p2_state.to_round_two(p2_my_secret_shares).unwrap();
        let p3_state = p3_state.to_round_two(p3_my_secret_shares).unwrap();
        let p4_state = p4_state.to_round_two(p4_my_secret_shares).unwrap();
        let p5_state = p5_state.to_round_two(p5_my_secret_shares).unwrap();

        let (group_key, p1_sk) = p1_state.finish(p1.public_key().unwrap()).unwrap();
        let (_, _) = p2_state.finish(p2.public_key().unwrap()).unwrap();
        let (_, p3_sk) = p3_state.finish(p3.public_key().unwrap()).unwrap();
        let (_, p4_sk) = p4_state.finish(p4.public_key().unwrap()).unwrap();
        let (_, _) = p5_state.finish(p5.public_key().unwrap()).unwrap();

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (p3_public_comshares, mut p3_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 3, 1);
        let (p4_public_comshares, mut p4_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 4, 1);

        let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());
        aggregator.include_signer(3, p3_public_comshares.commitments[0], (&p3_sk).into());
        aggregator.include_signer(4, p4_public_comshares.commitments[0], (&p4_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        let p1_partial = p1_sk.sign(&message_hash, &group_key, &mut p1_secret_comshares, 0, signers).unwrap();
        let p3_partial = p3_sk.sign(&message_hash, &group_key, &mut p3_secret_comshares, 0, signers).unwrap();
        let p4_partial = p4_sk.sign(&message_hash, &group_key, &mut p4_secret_comshares, 0, signers).unwrap();

        aggregator.include_partial_signature(p1_partial);
        aggregator.include_partial_signature(p3_partial);
        aggregator.include_partial_signature(p4_partial);

        let aggregator = aggregator.finalize().unwrap();

        c.bench_function("Signature aggregation", move |b| {
            b.iter(|| aggregator.aggregate());
        });
    }

    fn verify_3_out_of_5(c: &mut Criterion) {
        let params = Parameters { n: 5, t: 3 };

        let (p1, p1coeffs) = Participant::new(&params, 1);
        let (p2, p2coeffs) = Participant::new(&params, 2);
        let (p3, p3coeffs) = Participant::new(&params, 3);
        let (p4, p4coeffs) = Participant::new(&params, 4);
        let (p5, p5coeffs) = Participant::new(&params, 5);

        let mut p1_other_participants: Vec<Participant> = vec!(p2.clone(), p3.clone(), p4.clone(), p5.clone());
        let p1_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p1.index,
                                                          &p1coeffs,
                                                          &mut p1_other_participants).unwrap();
        let p1_their_secret_shares = p1_state.their_secret_shares().unwrap();
        
        let mut p2_other_participants: Vec<Participant> = vec!(p1.clone(), p3.clone(), p4.clone(), p5.clone());
        let p2_state = DistributedKeyGeneration::<>::new(&params,
                                                         &p2.index,
                                                         &p2coeffs,
                                                         &mut p2_other_participants).unwrap();
        let p2_their_secret_shares = p2_state.their_secret_shares().unwrap();

        let mut p3_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p4.clone(), p5.clone());
        let p3_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p3.index,
                                                          &p3coeffs,
                                                          &mut p3_other_participants).unwrap();
        let p3_their_secret_shares = p3_state.their_secret_shares().unwrap();

        let mut p4_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone(), p5.clone());
        let p4_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p4.index,
                                                          &p4coeffs,
                                                          &mut p4_other_participants).unwrap();
        let p4_their_secret_shares = p4_state.their_secret_shares().unwrap();

        let mut p5_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone(), p4.clone());
        let p5_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p5.index,
                                                          &p5coeffs,
                                                          &mut p5_other_participants).unwrap();
        let p5_their_secret_shares = p5_state.their_secret_shares().unwrap();

        let p1_my_secret_shares = vec!(p2_their_secret_shares[0].clone(), // XXX FIXME indexing
                                       p3_their_secret_shares[0].clone(),
                                       p4_their_secret_shares[0].clone(),
                                       p5_their_secret_shares[0].clone());

        let p2_my_secret_shares = vec!(p1_their_secret_shares[0].clone(),
                                       p3_their_secret_shares[1].clone(),
                                       p4_their_secret_shares[1].clone(),
                                       p5_their_secret_shares[1].clone());
        
        let p3_my_secret_shares = vec!(p1_their_secret_shares[1].clone(),
                                       p2_their_secret_shares[1].clone(),
                                       p4_their_secret_shares[2].clone(),
                                       p5_their_secret_shares[2].clone());
        
        let p4_my_secret_shares = vec!(p1_their_secret_shares[2].clone(),
                                       p2_their_secret_shares[2].clone(),
                                       p3_their_secret_shares[2].clone(),
                                       p5_their_secret_shares[3].clone());
        
        let p5_my_secret_shares = vec!(p1_their_secret_shares[3].clone(),
                                       p2_their_secret_shares[3].clone(),
                                       p3_their_secret_shares[3].clone(),
                                       p4_their_secret_shares[3].clone());

        let p1_state = p1_state.to_round_two(p1_my_secret_shares).unwrap();
        let p2_state = p2_state.to_round_two(p2_my_secret_shares).unwrap();
        let p3_state = p3_state.to_round_two(p3_my_secret_shares).unwrap();
        let p4_state = p4_state.to_round_two(p4_my_secret_shares).unwrap();
        let p5_state = p5_state.to_round_two(p5_my_secret_shares).unwrap();

        let (group_key, p1_sk) = p1_state.finish(p1.public_key().unwrap()).unwrap();
        let (_, _) = p2_state.finish(p2.public_key().unwrap()).unwrap();
        let (_, p3_sk) = p3_state.finish(p3.public_key().unwrap()).unwrap();
        let (_, p4_sk) = p4_state.finish(p4.public_key().unwrap()).unwrap();
        let (_, _) = p5_state.finish(p5.public_key().unwrap()).unwrap();

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (p3_public_comshares, mut p3_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 3, 1);
        let (p4_public_comshares, mut p4_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 4, 1);

        let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());
        aggregator.include_signer(3, p3_public_comshares.commitments[0], (&p3_sk).into());
        aggregator.include_signer(4, p4_public_comshares.commitments[0], (&p4_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        let p1_partial = p1_sk.sign(&message_hash, &group_key, &mut p1_secret_comshares, 0, signers).unwrap();
        let p3_partial = p3_sk.sign(&message_hash, &group_key, &mut p3_secret_comshares, 0, signers).unwrap();
        let p4_partial = p4_sk.sign(&message_hash, &group_key, &mut p4_secret_comshares, 0, signers).unwrap();

        aggregator.include_partial_signature(p1_partial);
        aggregator.include_partial_signature(p3_partial);
        aggregator.include_partial_signature(p4_partial);

        let aggregator = aggregator.finalize().unwrap();
        let threshold_signature = aggregator.aggregate().unwrap();

        c.bench_function("Signature verification", move |b| {
            b.iter(|| threshold_signature.verify(&group_key, &message_hash));
        });
    }

    criterion_group! {
        name = sign_benches;
        config = Criterion::default();
        targets =
            partial_sign_3_out_of_5,
            signature_aggregation_3_out_of_5,
            verify_3_out_of_5,
    }
}

criterion_main!(
    dkg_benches::dkg_benches,
    sign_benches::sign_benches,
);
