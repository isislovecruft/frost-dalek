// -*- mode: rust; -*-
//
// This file is part of dalek-frost.
// Copyright (c) 2020 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Runtime errors which may occur during an instance of a threshold signing protocol.

/// A zero-knowledge proof could not be verified.
// XXX todo implement real error handling
pub struct ProofError;
