#![cfg_attr(not(feature = "std"), no_std)]
#![deny(
    warnings,
    unused,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    unsafe_code,
    unused_crate_dependencies
)]

//! Non-interactive publicly verifiable distributed key generation and resharing algorithm over BLS12-381
//! Built using [Arkworks](https://arkworks.rs/)
//!
//! See: [NPVDKGRS](https://github.com/natrixofficial/npvdkgrs/blob/fb5280af42e97a97fef6e1e652c9bf57d7632d37/math/NPVDKGRS.pdf) for more information.

/// Addresses and Public Keys
pub mod addr;
/// Arkworks specific utilities
pub mod ark;
/// Encryption and Decryption functions
pub mod cipher;
/// Hashing functions
pub mod hash;
/// Key Pair is a struct that contains the public and private keys
pub mod keys;
/// Share Maps
pub mod maps;
/// DKG Protocol Parameters
pub mod params;
/// Participants in the protocol
pub mod party;
/// Working with Polynomials.
pub mod poly;
/// NPVDKG Protocol Rounds
pub mod rounds;
/// Sharing of secrets and verification
pub mod share;
/// Signing and Signatures
pub mod sig;
/// Progress tracing
pub mod trace;
