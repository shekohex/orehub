#![deny(
    trivial_casts,
    trivial_numeric_casts,
    stable_features,
    non_shorthand_field_patterns,
    renamed_and_removed_lints,
    unsafe_code,
    clippy::exhaustive_enums
)]
#![allow(clippy::all, clippy::exhaustive_enums)]
/// Orehub Testnet runtime module.
pub mod testnet_runtime;
#[cfg(any(feature = "std", feature = "web"))]
pub use subxt;
pub use subxt_signer;
// `subxt` already re-exports `subxt-core`
#[cfg(not(any(feature = "std", feature = "web")))]
pub use subxt_core;
