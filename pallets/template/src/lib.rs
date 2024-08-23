//! A shell pallet built with [`frame`].
//!
//! To get started with this pallet, try implementing the guide in
//! <https://paritytech.github.io/polkadot-sdk/master/polkadot_sdk_docs/guides/your_first_pallet/index.html>

#![cfg_attr(not(feature = "std"), no_std)]

use frame::prelude::*;

// Re-export all pallet parts, this is needed to properly import the pallet into the runtime.
pub use pallet::*;

#[frame::pallet]
pub mod pallet {
    use super::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {}

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(10_000)]
        #[pallet::feeless_if(|_: &OriginFor<T>, number: &u32| -> bool {
            Pallet::<T>::is_odd(*number)
        })]
        pub fn check_is_odd(origin: OriginFor<T>, number: u32) -> DispatchResult {
            let _who = ensure_signed(origin)?;
            ensure!(Self::is_odd(number), "Number is not odd.");
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        fn is_odd(number: u32) -> bool {
            number % 2 != 0
        }
    }
}
