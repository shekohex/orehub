#![cfg_attr(not(feature = "std"), no_std)]
#![deny(warnings, unused, future_incompatible, nonstandard_style, rust_2018_idioms)]
#![forbid(unsafe_code)]

//! Non-interactive publicly verifiable distributed key generation and resharing algorithm over BLS12-381
//! Built using [Arkworks](https://arkworks.rs/)

/// Encryption and Decryption functions
pub mod cipher;
/// Hashing functions
pub mod hash;
/// Key Pair is a struct that contains the public and private keys
pub mod keys;
/// Sharing of secrets and verification
pub mod share;
/// Signing and Signatures
pub mod sig;
