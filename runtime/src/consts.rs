/// The prefix for the SS58 address encoding for Substrate-based chains.
pub const SS58_PREFIX: u16 = 7849;

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
    pub const EXISTENTIAL_DEPOSIT: Balance = MILLIORE;

    /// Return the cost to add an item to storage based on size
    pub const fn deposit(items: u32, bytes: u32) -> Balance {
        items as Balance * 5 * CENT + (bytes as Balance) * 100 * MILLICENT
    }
}
