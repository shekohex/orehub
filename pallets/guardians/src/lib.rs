//! Guardians pallet built with [`frame`] for OreHub runtime.
//!
//! By defintion, a guardian is a person who protects or defends something, in OreHub, guardians are
//! a group of _active_ validators that are responsible for the security of the network by working
//! together to create a Distributed Key Generation (DKG).
//!
#![cfg_attr(not(feature = "std"), no_std)]

use frame::prelude::*;

// Re-export all pallet parts, this is needed to properly import the pallet into the runtime.
pub use pallet::*;

#[frame::pallet(dev_mode)]
pub mod pallet {
    use frame::deps::frame_support::dispatch::PostDispatchInfo;

    use super::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {}

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        pub fn check_is_odd(origin: OriginFor<T>, number: u32) -> DispatchResultWithPostInfo {
            let _who = ensure_signed(origin)?;
            let valid = Self::is_odd(number);

            Ok(PostDispatchInfo { actual_weight: None, pays_fee: if valid { Pays::No } else { Pays::Yes } })
        }
    }

    impl<T: Config> Pallet<T> {
        fn is_odd(number: u32) -> bool {
            number % 2 != 0
        }
    }
}
