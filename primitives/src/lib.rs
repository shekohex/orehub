#![cfg_attr(not(feature = "std"), no_std)]

// Useful for when no-standard is enabled
#[cfg(not(feature = "std"))]
extern crate alloc;

use frame::{
    deps::sp_runtime::{generic, MultiAddress},
    runtime::types_common::{AccountId, BlockNumber},
};
/// Account index type as expected by this runtime.
pub type AccountIndex = u32;
/// The address format for describing accounts.
pub type Address = MultiAddress<AccountId, AccountIndex>;
/// Block header type as expected by this runtime.
pub type Header = generic::Header<BlockNumber, frame::traits::BlakeTwo256>;
/// Index of a transaction in the chain.
pub type Nonce = u32;
/// A hash of some data used by the chain.
pub type Hash = frame::primitives::H256;

/// Orehub Runtime time-related
pub mod time {
    use frame::runtime::types_common::BlockNumber;
    /// A Moment in time.
    pub type Moment = u64;
    /// This determines the average expected block time that we are targeting. Blocks will be
    /// produced at a minimum duration defined by `SLOT_DURATION`. `SLOT_DURATION` is picked up by
    /// `pallet_timestamp` which is in turn picked up by `pallet_aura`, or `pallet_babe` to implement `fn
    /// slot_duration()`.
    ///
    /// Change this to adjust the block time.
    pub const SECONDS_PER_BLOCK: Moment = 3;

    pub const MILLISECS_PER_BLOCK: Moment = SECONDS_PER_BLOCK * 1000;
    pub const SLOT_DURATION: Moment = MILLISECS_PER_BLOCK;

    // Time is measured by number of blocks.
    pub const MINUTES: BlockNumber = 60_000 / (MILLISECS_PER_BLOCK as BlockNumber);
    pub const HOURS: BlockNumber = MINUTES * 60;
    pub const DAYS: BlockNumber = HOURS * 24;

    // 1 in 4 blocks (on average, not counting collisions) will be primary BABE blocks.
    pub const PRIMARY_PROBABILITY: (u64, u64) = (1, 4);

    #[cfg(feature = "fast-runtime")]
    pub const EPOCH_DURATION_IN_BLOCKS: BlockNumber = 40; // 40 blocks for fast tests

    // NOTE: Currently it is not possible to change the epoch duration after the chain has started.
    //       Attempting to do so will brick block production.
    #[cfg(not(feature = "fast-runtime"))]
    pub const EPOCH_DURATION_IN_BLOCKS: BlockNumber = 4 * HOURS;

    #[cfg(not(feature = "fast-runtime"))]
    pub const SESSION_PERIOD_IN_BLOCKS: BlockNumber = 1 * HOURS;

    #[cfg(feature = "fast-runtime")]
    pub const SESSION_PERIOD_IN_BLOCKS: BlockNumber = 10; // 10 blocks for fast tests

    pub const EPOCH_DURATION_IN_SLOTS: u64 = {
        const SLOT_FILL_RATE: f64 = MILLISECS_PER_BLOCK as f64 / SLOT_DURATION as f64;

        (EPOCH_DURATION_IN_BLOCKS as f64 * SLOT_FILL_RATE) as u64
    };
}

/// Money matters.
pub mod currency {
    /// The balance of an account.
    pub type Balance = u128;

    // Supply units
    // =============
    /// The base unit, since we use 11 decimal places (10^11)
    pub const ORE: Balance = 100_000_000_000;
    /// A MilliORE is a thousandth of a ORE = 0.001 ORE
    pub const MILLIORE: Balance = ORE / 1000;
    /// A MicroORE is a millionth of a ORE = 0.000001 ORE
    pub const MICRORE: Balance = MILLIORE / 1000;
    /// A NanoORE is a billionth of a ORE = 0.000000001 ORE
    pub const NANORE: Balance = MICRORE / 1000;
    /// A GRAIN is a smallest possible unit of ORE = 0.000000000001 ORE
    pub const GRAIN: Balance = 1;

    // Monetary value
    // =============
    /// Lets assume 1 ORE = 100USD
    /// This assumption forms the base of all fee calculations, revisit this
    /// if the assumption is no longer true.
    pub const DOLLAR: Balance = ORE / 100;
    pub const CENT: Balance = DOLLAR / 100;
    pub const MILLICENT: Balance = CENT / 1000;
    /// The existential deposit.
    pub const EXISTENTIAL_DEPOSIT: Balance = 5 * CENT;

    /// Return the cost to add an item to storage based on size
    pub const fn deposit(items: u32, bytes: u32) -> Balance {
        items as Balance * 5 * CENT + (bytes as Balance) * MILLICENT
    }
}

/// Fee config for Orehub
pub mod fee {
    use frame::{
        arithmetic::Perbill,
        deps::frame_support::weights::{
            constants::ExtrinsicBaseWeight, WeightToFeeCoefficient, WeightToFeeCoefficients,
            WeightToFeePolynomial,
        },
    };
    use smallvec::smallvec;

    use crate::currency::*;
    /// Handles converting a weight scalar to a fee value, based on the scale and granularity of the
    /// node's balance type.
    ///
    /// This should typically create a mapping between the following ranges:
    ///   - `[0, MAXIMUM_BLOCK_WEIGHT]`
    ///   - `[Balance::min, Balance::max]`
    ///
    /// Yet, it can be used for any other sort of change to weight-fee. Some examples being:
    ///   - Setting it to `0` will essentially disable the weight fee.
    ///   - Setting it to `1` will cause the literal `#[weight = x]` values to be charged.
    pub struct WeightToFee;
    impl WeightToFeePolynomial for WeightToFee {
        type Balance = Balance;
        fn polynomial() -> WeightToFeeCoefficients<Self::Balance> {
            let p = CENT;
            let q = 100 * Balance::from(ExtrinsicBaseWeight::get().ref_time());
            smallvec![WeightToFeeCoefficient {
                degree: 1,
                negative: false,
                coeff_frac: Perbill::from_rational(p % q, q),
                coeff_integer: p / q,
            }]
        }
    }
}

/// Orehub democracy pallet constants
pub mod democracy {
    use crate::{
        currency::{Balance, MILLIORE},
        time::{DAYS, HOURS},
    };
    use frame::runtime::types_common::BlockNumber;
    pub const LAUNCH_PERIOD: BlockNumber = 12 * HOURS; // 12 hours
    pub const VOTING_PERIOD: BlockNumber = 7 * DAYS; // 7 days
    pub const FASTTRACK_VOTING_PERIOD: BlockNumber = 2 * DAYS; // 2 days
    pub const MINIMUM_DEPOSIT: Balance = 10 * MILLIORE; // 10 MILLIORE
    pub const ENACTMENT_PERIOD: BlockNumber = 3 * DAYS; // 3 days
    pub const COOLOFF_PERIOD: BlockNumber = 3 * DAYS; // 3 days
    pub const MAX_PROPOSALS: u32 = 100;
}

pub mod elections {
    use crate::{
        currency::{Balance, ORE},
        time::DAYS,
    };
    use frame::runtime::types_common::BlockNumber;

    pub const CANDIDACY_BOND: Balance = 100 * ORE;
    pub const TERM_DURATION: BlockNumber = 7 * DAYS;
    pub const DESIRED_MEMBERS: u32 = 5;
    pub const DESIRED_RUNNERS_UP: u32 = 3;
    pub const MAX_CANDIDATES: u32 = 64;
    pub const MAX_VOTERS: u32 = 512;
    pub const MAX_VOTES_PER_VOTER: u32 = 32;
    pub const ELECTIONS_PHRAGMEN_PALLET_ID: frame::traits::LockIdentifier = *b"phrelect";
}

pub mod treasury {
    use frame::{
        arithmetic::{Percent, Permill},
        deps::frame_support::PalletId,
        runtime::types_common::BlockNumber,
    };

    use crate::{
        currency::{Balance, CENT, MILLIORE},
        time::DAYS,
    };

    pub const PROPOSAL_BOND: Permill = Permill::from_percent(1);
    pub const PROPOSAL_BOND_MINIMUM: Balance = 10 * MILLIORE;
    pub const SPEND_PERIOD: BlockNumber = DAYS;
    pub const BURN: Permill = Permill::from_percent(0);
    pub const TIP_COUNTDOWN: BlockNumber = DAYS;
    pub const TIP_FINDERS_FEE: Percent = Percent::from_percent(5);
    pub const DATA_DEPOSIT_PER_BYTE: Balance = CENT;
    pub const TREASURY_PALLET_ID: PalletId = PalletId(*b"py/trsry");
    pub const MAXIMUM_REASON_LENGTH: u32 = 300;
    pub const MAX_APPROVALS: u32 = 100;
}

#[cfg(not(feature = "fast-runtime"))]
pub mod staking {
    use frame::{arithmetic::Perbill, runtime::types_common::BlockNumber};

    // Six sessions in an era (24 hours).
    pub const SESSIONS_PER_ERA: sp_staking::SessionIndex = 6;
    // 7 eras for unbonding (14 days).
    pub const BONDING_DURATION: sp_staking::EraIndex = 7;
    // 27 eras for slash defer duration (10 days).
    pub const SLASH_DEFER_DURATION: sp_staking::EraIndex = 10;
    pub const MAX_NOMINATOR_REWARDED_PER_VALIDATOR: u32 = 256;
    pub const OFFENDING_VALIDATOR_THRESHOLD: Perbill = Perbill::from_percent(17);
    pub const OFFCHAIN_REPEAT: BlockNumber = 5;
    pub const HISTORY_DEPTH: u32 = 80;
}

#[cfg(feature = "fast-runtime")]
pub mod staking {
    use frame::{arithmetic::Perbill, runtime::types_common::BlockNumber};

    // 1 sessions in an era (10 blocks).
    pub const SESSIONS_PER_ERA: sp_staking::SessionIndex = 1;
    // 2 eras for unbonding (20 blocks).
    pub const BONDING_DURATION: sp_staking::EraIndex = 2;
    // 1 eras for slash defer (10 blocks).
    pub const SLASH_DEFER_DURATION: sp_staking::EraIndex = 1;
    pub const MAX_NOMINATOR_REWARDED_PER_VALIDATOR: u32 = 256;
    pub const OFFENDING_VALIDATOR_THRESHOLD: Perbill = Perbill::from_percent(17);
    pub const OFFCHAIN_REPEAT: BlockNumber = 5;
    pub const HISTORY_DEPTH: u32 = 80;
}

/// Block Size limit in bytes.
pub const MAX_BLOCK_SIZE: u32 = 3 * 1024 * 1024; // 3 MB

/// We assume that ~10% of the block weight is consumed by `on_initialize` handlers. This is
/// used to limit the maximal weight of a single extrinsic.
pub const AVERAGE_ON_INITIALIZE_RATIO: frame::arithmetic::Perbill =
    frame::arithmetic::Perbill::from_percent(10);

/// We allow `Normal` extrinsics to fill up the block up to 85%, the rest can be used by
/// `Operational` extrinsics.
pub const NORMAL_DISPATCH_RATIO: frame::arithmetic::Perbill =
    frame::arithmetic::Perbill::from_percent(85);

/// We allow for 2000ms of compute with a 6 second average block time.
pub const WEIGHT_MILLISECS_PER_BLOCK: u64 = 2000;
/// The maximum weight of a block (in `Weight` units) that we are willing to produce.
pub const MAXIMUM_BLOCK_WEIGHT: frame::prelude::Weight = frame::prelude::Weight::from_parts(
    WEIGHT_MILLISECS_PER_BLOCK
        * frame::deps::frame_support::weights::constants::WEIGHT_REF_TIME_PER_MILLIS,
    u64::MAX,
);

// `25257` this would give us addresses with `or` prefix for mainnet like
// orTenVQtiHJE6BP9HQGuqgEy3u8quqjmpBuA23dDgg37GBGP1
pub const MAINNET_SS58_PREFIX: u16 = 25257;

// `13737` this would give us addresses with `ot` prefix for testnet like
// otMcKQGBNapqu9Vq6cPdHrN28BMZVtDjhmmgWjcSQUHQXXXBG
pub const TESTNET_SS58_PREFIX: u16 = 13737;

// `25255` this would give us addresses with `od` prefix for local testnet and development like
// odgtMQRb764H4BsMuU8JoLtvfB2YGpHBC3WFDJ8u9Qazr9mev
pub const TESTNET_LOCAL_SS58_PREFIX: u16 = 25255;
