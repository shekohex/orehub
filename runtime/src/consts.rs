/// The prefix for the SS58 address encoding for Substrate-based chains.
pub const SS58_PREFIX: u16 = 7849;
/// Block Size limit in bytes.
pub const MAX_BLOCK_SIZE: u32 = 3 * 1024 * 1024; // 3 MB

/// Money matters.
pub mod currency {
    pub type Balance = u128;

    // Supply units
    // =============
    /// The base unit, since we use 11 decimal places (10^11)
    pub const ORE: Balance = 100_000_000_000;
    pub const MILLIORE: Balance = ORE / 1000;
    pub const MICRORE: Balance = MILLIORE / 1000;
    pub const NANORE: Balance = MICRORE / 1000;

    // Monetary value
    // =============
    /// Lets assume 1 ORE = 100USD
    /// This assumption forms the base of all fee calculations, revisit this
    /// if the assumption is no longer true.
    pub const DOLLAR: Balance = ORE / 100;
    pub const CENT: Balance = DOLLAR / 100;
    pub const MILLICENT: Balance = CENT / 1000;
    /// The existential deposit.
    pub const EXISTENTIAL_DEPOSIT: Balance = MILLIORE / 100;

    /// Return the cost to add an item to storage based on size
    pub const fn deposit(items: u32, bytes: u32) -> Balance {
        items as Balance * 5 * CENT + (bytes as Balance) * 100 * MILLICENT
    }
}

pub mod time {
    use crate::BlockNumber;
    /// This determines the average expected block time that we are targeting.
    /// Blocks will be produced at a minimum duration defined by `SLOT_DURATION`.
    /// `SLOT_DURATION` is picked up by `pallet_timestamp` which is in turn picked
    /// up by `pallet_aura` to implement `fn slot_duration()`.
    ///
    /// Change this to adjust the block time.
    pub const MILLISECS_PER_BLOCK: u64 = 5000;

    // NOTE: Currently it is not possible to change the slot duration after the chain has started.
    //       Attempting to do so will brick block production.
    pub const SLOT_DURATION: u64 = MILLISECS_PER_BLOCK / 2;

    // Time is measured by number of blocks.
    pub const MINUTES: BlockNumber = 60_000 / (MILLISECS_PER_BLOCK as BlockNumber);
    pub const HOURS: BlockNumber = MINUTES * 60;
    pub const DAYS: BlockNumber = HOURS * 24;
}
