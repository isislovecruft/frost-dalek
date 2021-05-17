
# FROST [![](https://img.shields.io/crates/v/frost-dalek.svg)](https://crates.io/crates/frost-dalek) [![](https://docs.rs/frost-dalek/badge.svg)](https://docs.rs/frost-dalek) [![](https://travis-ci.com/github/isislovecruft/frost-dalek.svg?branch=master)](https://travis-ci.org/isislovecruft/frost-dalek)

A Rust implementation of
[FROST: Flexible Round-Optimised Schnorr Threshold signatures](https://eprint.iacr.org/2020/852)
by Chelsea Komlo and Ian Goldberg.

## Usage

Please see [the documentation](https://docs.rs/frost-dalek) for usage examples.

## Note on `no_std` usage

Most of this crate is `no_std` compliant, however, the current
implementation uses `HashMap`s for the signature creation and aggregation
protocols, and thus requires the standard library.

## WARNING

This code is likely not stable.  The author is working with the paper authors on
an RFC which, if/when adopted, will allow us to stabilise this codebase.  Until
then, the structure and construction of these signatures, as well as wireformats
for several types which must be sent between signing parties, may change in
incompatible ways.
