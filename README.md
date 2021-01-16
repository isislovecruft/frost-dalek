
# FROST [![](https://img.shields.io/crates/v/frost-dalek.svg)](https://crates.io/crates/frost-dalek) [![](https://img.shields.io/badge/dynamic/json.svg?label=docs&uri=https%3A%2F%2Fcrates.io%2Fapi%2Fv1%2Fcrates%2Ffrost-dalek%2Fversions&query=%24.versions%5B0%5D.num&colorB=4F74A6)](https://doc.dalek.rs) [![](https://travis-ci.com/github/isislovecruft/frost-dalek.svg?branch=master)](https://travis-ci.org/isislovecruft/frost-dalek)

A Rust implementation of
[FROST: Flexible Round-Optimised Schnorr Threshold signatures](https://eprint.iacr.org/2020/852)
by Chelsea Komlo and Ian Goldberg.

## Usage

Please see [the documentation](https://docs.rs/frost-dalek) for usage examples.

## WARNING

This code is likely not stable.  The author is working with the paper authors on
an RFC which, if/when adopted, will allow us to stabilise this codebase.  Until
then, the structure and construction of these signatures, as well as wireformats
for several types which must be sent between signing parties, may change in
incompatible ways.
