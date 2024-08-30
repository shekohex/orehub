//! A minimal runtime for OreHub.

#![cfg_attr(not(feature = "std"), no_std)]
#![recursion_limit = "256"]

// Make the WASM binary available.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

extern crate alloc;

mod bags;

/// Mainnent Runtime
#[cfg(all(feature = "mainnet", not(feature = "testnet")))]
mod mainnet;
/// Testnet Runtime
#[cfg(all(feature = "testnet", not(feature = "mainnet")))]
mod testnet;

#[cfg(all(feature = "mainnet", not(feature = "testnet")))]
pub use mainnet::*;

#[cfg(all(feature = "testnet", not(feature = "mainnet")))]
pub use testnet::*;

#[cfg(all(not(feature = "testnet"), not(feature = "mainnet")))]
compile_error!("Please enable one of the following features: 'mainnet', 'testnet'.");
#[cfg(all(feature = "testnet", feature = "mainnet"))]
compile_error!("Please enable only one of the following features: 'mainnet', 'testnet'.");
