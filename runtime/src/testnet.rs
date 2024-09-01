use alloc::{vec, vec::Vec};
use frame::traits::tokens::UnityAssetBalanceConversion;
use frame::traits::{EqualPrivilegeOnly, KeyOwnerProofSystem, OpaqueKeys};
use frame::{
    arithmetic::*,
    deps::frame_support::{
        self,
        genesis_builder_helper::{build_state, get_preset},
        runtime,
        weights::{constants::BlockExecutionWeight, constants::RocksDbWeight, ConstantMultiplier},
        PalletId,
    },
    deps::sp_io,
    prelude::*,
    primitives::*,
    runtime::{
        apis::{
            self, ed25519::AuthorityId as AuraId, impl_runtime_apis, ApplyExtrinsicResult,
            AuthorityId as GrandpaId, CheckInherentsResult, ExtrinsicInclusionMode, OpaqueMetadata,
        },
        prelude::*,
        types_common::*,
    },
    traits::{
        tokens::PayFromAccount, Block as BlockT, Currency, EitherOfDiverse, IdentityLookup,
        Imbalance, LockIdentifier, NumberFor, OnUnbalanced, StaticLookup,
    },
};
use frame_election_provider_support::bounds::ElectionBounds;
use frame_election_provider_support::bounds::ElectionBoundsBuilder;
use frame_election_provider_support::onchain;
use frame_election_provider_support::BalancingConfig;
use frame_election_provider_support::ElectionDataProvider;
use frame_election_provider_support::SequentialPhragmen;
use frame_election_provider_support::VoteWeight;
use frame_system::EnsureWithSuccess;
use orehub_primitives::currency::{MICRORE, MILLIORE, ORE};
use orehub_primitives::fee;
use orehub_primitives::{
    currency::{self, Balance},
    democracy, elections, staking, time, treasury, AccountIndex, Address, Hash, Header, Nonce,
    MAXIMUM_BLOCK_WEIGHT, MAX_BLOCK_SIZE, NORMAL_DISPATCH_RATIO, TESTNET_SS58_PREFIX,
};
use pallet_election_provider_multi_phase::GeometricDepositBase;
use pallet_election_provider_multi_phase::SolutionAccuracyOf;
use pallet_im_online::ed25519::AuthorityId as ImOnlineId;
use pallet_transaction_payment::{
    FeeDetails, Multiplier, RuntimeDispatchInfo, TargetedFeeAdjustment,
};
use sp_runtime::Deserialize;
use sp_runtime::Serialize;
use sp_runtime::{generic, KeyTypeId};
use sp_staking::currency_to_vote::U128CurrencyToVote;

/// Opaque types. These are used by the CLI to instantiate machinery that don't need to know
/// the specifics of the runtime. They can then be made to be agnostic over specific formats
/// of data like extrinsics, allowing for them to continue syncing the network through upgrades
/// to even the core data structures.
pub mod opaque {
    use super::*;

    use sp_runtime::generic;
    use sp_runtime::impl_opaque_keys;
    pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;

    /// Opaque block header type.
    pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
    /// Opaque block type.
    pub type Block = generic::Block<Header, UncheckedExtrinsic>;
    /// Opaque block identifier type.
    pub type BlockId = generic::BlockId<Block>;

    impl_opaque_keys! {
        pub struct SessionKeys {
            pub aura: Aura,
            pub grandpa: Grandpa,
            pub im_online: ImOnline,
        }
    }
}

/// The runtime version.
#[runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: create_runtime_str!("orehub"),
    impl_name: create_runtime_str!("orehub-rust"),
    authoring_version: 1,
    // The version of the runtime specification. A full node will not attempt to use its native
    //   runtime in substitute for the on-chain Wasm runtime unless all of `spec_name`,
    //   `spec_version`, and `authoring_version` are the same between Wasm and native.
    // This value is set to 100 to notify Polkadot-JS App (https://polkadot.js.org/apps) to use
    //   the compatible custom types.
    spec_version: 1000, // v1.0.0+0
    impl_version: 1,
    apis: RUNTIME_API_VERSIONS,
    transaction_version: 1,
    state_version: 1,
};

/// The version information used to identify this runtime when compiled natively.
#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
    NativeVersion {
        runtime_version: VERSION,
        can_author_with: Default::default(),
    }
}

/// The signed extensions that are added to the runtime.
pub type SignedExtra = (
    frame_system::CheckNonZeroSender<Runtime>,
    // Checks that the runtime version is correct.
    frame_system::CheckSpecVersion<Runtime>,
    // Checks that the transaction version is correct.
    frame_system::CheckTxVersion<Runtime>,
    // Checks that the genesis hash is correct.
    frame_system::CheckGenesis<Runtime>,
    // Checks that the era is valid.
    frame_system::CheckEra<Runtime>,
    // Checks that the nonce is valid.
    frame_system::CheckNonce<Runtime>,
    // Checks that the weight is valid.
    frame_system::CheckWeight<Runtime>,
    // Ensures that the sender has enough funds to pay for the transaction
    // and deducts the fee from the sender's account.
    pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
    // Add the `CheckMetadataHash` extension.
    frame_metadata_hash_extension::CheckMetadataHash<Runtime>,
);

// Composes the runtime by adding all the used pallets and deriving necessary types.
#[runtime]
pub mod runtime {
    /// The main runtime type.
    #[runtime::runtime]
    #[runtime::derive(
        RuntimeCall,
        RuntimeEvent,
        RuntimeError,
        RuntimeOrigin,
        RuntimeFreezeReason,
        RuntimeHoldReason,
        RuntimeSlashReason,
        RuntimeLockId,
        RuntimeTask
    )]
    pub struct Runtime;

    #[runtime::pallet_index(0)]
    pub type System = frame_system;
    #[runtime::pallet_index(1)]
    pub type Timestamp = pallet_timestamp;

    #[runtime::pallet_index(2)]
    pub type Sudo = pallet_sudo;
    #[runtime::pallet_index(3)]
    pub type Balances = pallet_balances;
    #[runtime::pallet_index(4)]
    pub type TransactionPayment = pallet_transaction_payment;

    #[runtime::pallet_index(5)]
    pub type Authorship = pallet_authorship;
    #[runtime::pallet_index(6)]
    pub type Aura = pallet_aura;
    #[runtime::pallet_index(7)]
    pub type Grandpa = pallet_grandpa;

    #[runtime::pallet_index(8)]
    pub type Indices = pallet_indices;
    #[runtime::pallet_index(9)]
    pub type Democracy = pallet_democracy;
    #[runtime::pallet_index(10)]
    pub type Council = pallet_collective<Instance1>;

    #[runtime::pallet_index(11)]
    pub type Elections = pallet_elections_phragmen;
    #[runtime::pallet_index(12)]
    pub type ElectionProviderMultiPhase = pallet_election_provider_multi_phase;
    #[runtime::pallet_index(13)]
    pub type Staking = pallet_staking;
    #[runtime::pallet_index(14)]
    pub type Session = pallet_session;
    #[runtime::pallet_index(15)]
    pub type Historical = pallet_session::historical;
    #[runtime::pallet_index(16)]
    pub type Treasury = pallet_treasury;
    #[runtime::pallet_index(17)]
    pub type Bounties = pallet_bounties;
    #[runtime::pallet_index(18)]
    pub type ChildBounties = pallet_child_bounties;
    #[runtime::pallet_index(19)]
    pub type BagsList = pallet_bags_list;

    #[runtime::pallet_index(20)]
    pub type Scheduler = pallet_scheduler;
    #[runtime::pallet_index(21)]
    pub type Preimage = pallet_preimage;
    #[runtime::pallet_index(22)]
    pub type Offences = pallet_offences;

    #[runtime::pallet_index(23)]
    pub type TxPause = pallet_tx_pause;
    #[runtime::pallet_index(24)]
    pub type ImOnline = pallet_im_online;
    #[runtime::pallet_index(25)]
    pub type Identity = pallet_identity;
    #[runtime::pallet_index(26)]
    pub type Multisig = pallet_multisig;
    #[runtime::pallet_index(27)]
    pub type Utility = pallet_utility;

    // 27 to 59 are reserved for more pallets.

    /// A Playground pallet for testing.
    #[runtime::pallet_index(60)]
    pub type OreHub = pallet_orehub;
}

parameter_types! {
    pub const BlockHashCount: BlockNumber = 2400;
    pub const Version: RuntimeVersion = VERSION;
    /// We allow for 2 seconds of compute with a 6 second average block time.
    pub BlockWeights: frame_system::limits::BlockWeights =
        frame_system::limits::BlockWeights::with_sensible_defaults(
            MAXIMUM_BLOCK_WEIGHT,
            NORMAL_DISPATCH_RATIO,
        );
    pub BlockLength: frame_system::limits::BlockLength = frame_system::limits::BlockLength
        ::max_with_normal_ratio(MAX_BLOCK_SIZE, NORMAL_DISPATCH_RATIO);
    /// Our custom SS58 prefix.
    pub const SS58Prefix: u16 = TESTNET_SS58_PREFIX;
}

/// Implements the types required for the system pallet.
#[derive_impl(frame_system::config_preludes::SolochainDefaultConfig)]
impl frame_system::Config for Runtime {
    /// The block type for the runtime.
    type Block = Block;
    /// Block & extrinsics weights: base values and limits.
    type BlockWeights = BlockWeights;
    /// The maximum length of a block (in bytes).
    type BlockLength = BlockLength;
    /// The identifier used to distinguish between accounts.
    type AccountId = AccountId;
    /// The type for storing how many extrinsics an account has signed.
    type Nonce = Nonce;
    /// The type for hashing blocks and tries.
    type Hash = Hash;
    /// Maximum number of block number to block hash mappings to keep (oldest pruned first).
    type BlockHashCount = BlockHashCount;
    /// The weight of database operations that the runtime can invoke.
    type DbWeight = RocksDbWeight;
    /// Version of the runtime.
    type Version = Version;
    type Lookup = Indices;
    /// The data to be stored in an account.
    type AccountData = pallet_balances::AccountData<Balance>;
    type SS58Prefix = SS58Prefix;
    type MaxConsumers = frame::traits::ConstU32<16>;
    type SystemWeightInfo = ();
}

parameter_types! {
    /// The amount needed to reserve for creating an index.
    pub const IndexDeposit: Balance = MILLIORE;
}

impl pallet_indices::Config for Runtime {
    type AccountIndex = AccountIndex;
    type Currency = Balances;
    type Deposit = IndexDeposit;
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = pallet_indices::weights::SubstrateWeight<Runtime>;
}

// Implements the types required for the balances pallet.
impl pallet_balances::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    /// The type for recording an account's balance.
    type Balance = Balance;
    type ExistentialDeposit = frame::traits::ConstU128<{ currency::EXISTENTIAL_DEPOSIT }>;
    type MaxLocks = frame::traits::ConstU32<50>;
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 8];
    /// The ubiquitous event type.
    type DustRemoval = ();
    type AccountStore = System;
    type WeightInfo = pallet_balances::weights::SubstrateWeight<Runtime>;
    type FreezeIdentifier = RuntimeFreezeReason;
    type MaxFreezes = frame::traits::VariantCountOf<RuntimeFreezeReason>;
    type RuntimeHoldReason = RuntimeHoldReason;
    type RuntimeFreezeReason = RuntimeHoldReason;
}

parameter_types! {
    // 80% of block weight.
    pub MaximumSchedulerWeight: Weight = Perbill::from_percent(80) *
        BlockWeights::get().max_block;
}

impl pallet_scheduler::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeOrigin = RuntimeOrigin;
    type PalletsOrigin = OriginCaller;
    type RuntimeCall = RuntimeCall;
    type MaximumWeight = MaximumSchedulerWeight;
    type ScheduleOrigin = EnsureRoot<AccountId>;
    type MaxScheduledPerBlock = ConstU32<512>;
    type WeightInfo = pallet_scheduler::weights::SubstrateWeight<Runtime>;
    type OriginPrivilegeCmp = EqualPrivilegeOnly;
    type Preimages = Preimage;
}

parameter_types! {
    /// 0.1 ORE
    pub const PreimageBaseDeposit: Balance = 100 * MILLIORE;
    /// 0.00001 ORE per byte
    pub const PreimageByteDeposit: Balance = 10 * MICRORE;
}

impl pallet_preimage::Config for Runtime {
    type Consideration = ();
    type Currency = Balances;
    type RuntimeEvent = RuntimeEvent;
    type ManagerOrigin = EnsureRoot<AccountId>;
    type WeightInfo = pallet_preimage::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
    pub const MaxAuthorities: u32 = 512;
    pub const AllowMultipleBlocksPerSlot: bool = false;
    pub const MaxNominators: u32 = 256;
    pub const MaxSetIdSessionEntries: u32 = 0;
    // NOTE: Currently it is not possible to change the epoch duration after the chain has started.
    //       Attempting to do so will brick block production.
    pub const EpochDuration: u64 = time::EPOCH_DURATION_IN_SLOTS;
    pub const ReportLongevity: u64 =
        BondingDuration::get() as u64 * SessionsPerEra::get() as u64 * EpochDuration::get();
}

impl pallet_aura::Config for Runtime {
    type AuthorityId = AuraId;
    type DisabledValidators = ();
    type MaxAuthorities = MaxAuthorities;
    type AllowMultipleBlocksPerSlot = AllowMultipleBlocksPerSlot;
    type SlotDuration = pallet_aura::MinimumPeriodTimesTwo<Runtime>;
}

impl pallet_grandpa::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;

    type MaxAuthorities = MaxAuthorities;
    type MaxNominators = MaxNominators;
    type MaxSetIdSessionEntries = MaxSetIdSessionEntries;
    type EquivocationReportSystem =
        pallet_grandpa::EquivocationReportSystem<Self, Offences, Historical, ReportLongevity>;
    type KeyOwnerProof = <Historical as KeyOwnerProofSystem<(KeyTypeId, GrandpaId)>>::Proof;

    type WeightInfo = ();
}

// Implements the types required for the sudo pallet.
impl pallet_sudo::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type WeightInfo = pallet_sudo::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
    pub const MinimumPeriod: u64 = time::SLOT_DURATION / 2;
}

impl pallet_timestamp::Config for Runtime {
    /// A timestamp: milliseconds since the unix epoch.
    type Moment = time::Moment;
    type OnTimestampSet = Aura;
    type MinimumPeriod = MinimumPeriod;
    type WeightInfo = pallet_timestamp::weights::SubstrateWeight<Runtime>;
}

// Implements the types required for the authorship pallet.
impl pallet_authorship::Config for Runtime {
    type EventHandler = Staking;
    type FindAuthor = pallet_session::FindAccountFromAuthorIndex<Self, Aura>;
}

pub type NegativeImbalance<T> = <pallet_balances::Pallet<T> as Currency<
    <T as frame_system::Config>::AccountId,
>>::NegativeImbalance;

pub struct DealWithFees<R>(core::marker::PhantomData<R>);
impl<R> OnUnbalanced<NegativeImbalance<R>> for DealWithFees<R>
where
    R: pallet_balances::Config + pallet_treasury::Config + pallet_authorship::Config,
    pallet_treasury::Pallet<R>: OnUnbalanced<NegativeImbalance<R>>,
    <R as frame_system::Config>::RuntimeEvent: From<pallet_balances::Event<R>>,
{
    fn on_unbalanceds<B>(mut fees_then_tips: impl Iterator<Item = NegativeImbalance<R>>) {
        if let Some(fees) = fees_then_tips.next() {
            // for fees, 90% to treasury, 10% to author
            let mut split = fees.ration(90, 10);
            if let Some(tips) = fees_then_tips.next() {
                // for tips, if any, 100% to author
                tips.merge_into(&mut split.1);
            }

            <pallet_treasury::Pallet<R> as OnUnbalanced<_>>::on_unbalanced(split.0);
            <ToAuthor<R> as OnUnbalanced<_>>::on_unbalanced(split.1);
        }
    }
}

/// Logic for the author to get a portion of fees.
pub struct ToAuthor<R>(core::marker::PhantomData<R>);

impl<R> OnUnbalanced<NegativeImbalance<R>> for ToAuthor<R>
where
    R: pallet_balances::Config + pallet_authorship::Config,
    <R as frame_system::Config>::RuntimeEvent: From<pallet_balances::Event<R>>,
{
    fn on_nonzero_unbalanced(amount: NegativeImbalance<R>) {
        if let Some(author) = <pallet_authorship::Pallet<R>>::author() {
            let _numeric_amount = amount.peek();
            <pallet_balances::Pallet<R>>::resolve_creating(&author, amount);
        }
    }
}

parameter_types! {
    pub const TransactionByteFee: Balance = currency::GRAIN;
    pub const OperationalFeeMultiplier: u8 = 3;
    pub const TargetBlockFullness: Perquintill = Perquintill::from_percent(85);
    pub AdjustmentVariable: Multiplier = Multiplier::saturating_from_rational(1, 100_000);
    pub MinimumMultiplier: Multiplier = Multiplier::saturating_from_rational(1, 1_000_000_000u128);
    pub MaximumMultiplier: Multiplier = Bounded::max_value();
}

// Implements the types required for the transaction payment pallet.
impl pallet_transaction_payment::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    #[allow(deprecated)]
    type OnChargeTransaction =
        pallet_transaction_payment::CurrencyAdapter<Balances, DealWithFees<Runtime>>;
    type OperationalFeeMultiplier = OperationalFeeMultiplier;
    type WeightToFee = fee::WeightToFee;
    type LengthToFee = ConstantMultiplier<Balance, TransactionByteFee>;
    type FeeMultiplierUpdate = TargetedFeeAdjustment<
        Self,
        TargetBlockFullness,
        AdjustmentVariable,
        MinimumMultiplier,
        MaximumMultiplier,
    >;
}

parameter_types! {
    pub const SpendPeriod: BlockNumber = treasury::SPEND_PERIOD;
    pub const Burn: Permill = treasury:: BURN;
    pub const TipCountdown: BlockNumber = treasury::TIP_COUNTDOWN;
    pub const TipFindersFee: Percent = treasury::TIP_FINDERS_FEE;
    pub const DataDepositPerByte: Balance = treasury::DATA_DEPOSIT_PER_BYTE;
    pub const TreasuryPalletId: PalletId = treasury::TREASURY_PALLET_ID;
    pub const MaximumReasonLength: u32 = treasury::MAXIMUM_REASON_LENGTH;
    pub const MaxApprovals: u32 = treasury::MAX_APPROVALS;
    pub const PayoutPeriod: BlockNumber = 30 * time::DAYS;
    pub TreasuryAccount: AccountId = Treasury::account_id();
    pub const MaxBalance: Balance = Balance::MAX;
}

impl pallet_treasury::Config for Runtime {
    type PalletId = TreasuryPalletId;
    type Currency = Balances;
    // TODO: revist this once we have democracy pallet and others.
    type RejectOrigin = EnsureRoot<AccountId>;
    type RuntimeEvent = RuntimeEvent;
    type AssetKind = ();
    type Beneficiary = AccountId;
    type BeneficiaryLookup = IdentityLookup<AccountId>;
    type Paymaster = PayFromAccount<Balances, TreasuryAccount>;
    type BalanceConverter = UnityAssetBalanceConversion;
    type PayoutPeriod = PayoutPeriod;
    type SpendPeriod = SpendPeriod;
    type Burn = Burn;
    type BurnDestination = ();
    type SpendOrigin = EnsureWithSuccess<EnsureRoot<AccountId>, AccountId, MaxBalance>;
    // This should be bounties
    type SpendFunds = Bounties;
    type WeightInfo = pallet_treasury::weights::SubstrateWeight<Runtime>;
    type MaxApprovals = MaxApprovals;
}

use crate::opaque::SessionKeys;

pub struct ValidatorToAccountIdConverter;

impl frame::traits::Convert<interface::AccountId, Option<interface::AccountId>>
    for ValidatorToAccountIdConverter
{
    fn convert(account: interface::AccountId) -> Option<interface::AccountId> {
        Some(account)
    }
}

parameter_types! {
    pub const SessionPeriod: BlockNumber = time::SESSION_PERIOD_IN_BLOCKS;
    pub const SessionOffset: BlockNumber = 0;
}

impl pallet_session::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type ValidatorId = interface::AccountId;
    type ValidatorIdOf = ValidatorToAccountIdConverter;
    type ShouldEndSession = pallet_session::PeriodicSessions<SessionPeriod, SessionOffset>;
    type NextSessionRotation = pallet_session::PeriodicSessions<SessionPeriod, SessionOffset>;
    type SessionManager = pallet_session::historical::NoteHistoricalRoot<Self, Staking>;
    type SessionHandler = <SessionKeys as OpaqueKeys>::KeyTypeIdProviders;
    type Keys = SessionKeys;
    type WeightInfo = pallet_session::weights::SubstrateWeight<Runtime>;
}

impl pallet_session::historical::Config for Runtime {
    type FullIdentification = pallet_staking::Exposure<AccountId, Balance>;
    type FullIdentificationOf = pallet_staking::ExposureOf<Runtime>;
}

parameter_types! {
    pub const SessionsPerEra: sp_staking::SessionIndex = staking::SESSIONS_PER_ERA;
    pub const BondingDuration: sp_staking::EraIndex = staking::BONDING_DURATION;
    pub const SlashDeferDuration: sp_staking::EraIndex = staking::SLASH_DEFER_DURATION;
    pub OffchainRepeat: BlockNumber = staking::OFFCHAIN_REPEAT;
    pub const HistoryDepth: u32 = staking::HISTORY_DEPTH;
    pub const MaxControllersInDeprecationBatch: u32 = 500;
    pub const MaxExposurePageSize: u32 = 64;
}

pub struct StakingBenchmarkingConfig;
impl pallet_staking::BenchmarkingConfig for StakingBenchmarkingConfig {
    type MaxNominators = ConstU32<1000>;
    type MaxValidators = ConstU32<1000>;
}

/// Upper limit on the number of NPOS nominations.
const MAX_QUOTA_NOMINATIONS: u32 = 16;

impl pallet_staking::Config for Runtime {
    type Currency = Balances;
    type CurrencyBalance = Balance;
    type AdminOrigin = EnsureRoot<AccountId>;
    type UnixTime = Timestamp;
    type CurrencyToVote = sp_staking::currency_to_vote::U128CurrencyToVote;
    type RewardRemainder = Treasury;
    type RuntimeEvent = RuntimeEvent;
    type Slash = Treasury; // send the slashed funds to the treasury.
    type Reward = (); // rewards are minted from the void
    type SessionsPerEra = SessionsPerEra;
    type BondingDuration = BondingDuration;
    type SlashDeferDuration = SlashDeferDuration;
    type SessionInterface = Self;
    type TargetList = pallet_staking::UseValidatorsMap<Runtime>;
    type EraPayout = ();
    type NextNewSession = Session;
    type MaxExposurePageSize = MaxExposurePageSize;
    type MaxControllersInDeprecationBatch = MaxControllersInDeprecationBatch;
    type ElectionProvider = ElectionProviderMultiPhase;
    type GenesisElectionProvider = onchain::OnChainExecution<OnChainSeqPhragmen>;
    type VoterList = BagsList;
    type MaxUnlockingChunks = ConstU32<32>;
    type HistoryDepth = HistoryDepth;
    type EventListeners = ();
    type WeightInfo = pallet_staking::weights::SubstrateWeight<Runtime>;
    type NominationsQuota = pallet_staking::FixedNominationsQuota<MAX_QUOTA_NOMINATIONS>;
    type DisablingStrategy = pallet_staking::UpToLimitDisablingStrategy;
    type BenchmarkingConfig = StakingBenchmarkingConfig;
}

parameter_types! {
    pub const LaunchPeriod: BlockNumber = democracy::LAUNCH_PERIOD;
    pub const VotingPeriod: BlockNumber = democracy::VOTING_PERIOD;
    pub const FastTrackVotingPeriod: BlockNumber = democracy::FASTTRACK_VOTING_PERIOD;
    pub const MinimumDeposit: Balance = democracy::MINIMUM_DEPOSIT;
    pub const EnactmentPeriod: BlockNumber = democracy::ENACTMENT_PERIOD;
    pub const CooloffPeriod: BlockNumber = democracy::COOLOFF_PERIOD;
    pub const MaxProposals: u32 = democracy::MAX_PROPOSALS;
}

type EnsureRootOrHalfCouncil = EitherOfDiverse<
    EnsureRoot<AccountId>,
    pallet_collective::EnsureProportionMoreThan<AccountId, CouncilCollective, 1, 2>,
>;

impl pallet_democracy::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type SubmitOrigin = frame_system::EnsureSigned<AccountId>;
    type EnactmentPeriod = EnactmentPeriod;
    type LaunchPeriod = LaunchPeriod;
    type VotingPeriod = VotingPeriod;
    type VoteLockingPeriod = EnactmentPeriod; // Same as EnactmentPeriod
    type MinimumDeposit = MinimumDeposit;
    /// A straight majority of the council can decide what their next motion is.
    type ExternalOrigin =
        pallet_collective::EnsureProportionAtLeast<AccountId, CouncilCollective, 1, 2>;
    /// A super-majority can have the next scheduled referendum be a straight majority-carries vote.
    type ExternalMajorityOrigin =
        pallet_collective::EnsureProportionAtLeast<AccountId, CouncilCollective, 3, 4>;
    /// A unanimous council can have the next scheduled referendum be a straight default-carries
    /// (NTB) vote.
    type ExternalDefaultOrigin =
        pallet_collective::EnsureProportionAtLeast<AccountId, CouncilCollective, 1, 1>;
    /// Two thirds of the council can have an ExternalMajority/ExternalDefault vote
    /// be tabled immediately and with a shorter voting/enactment period.
    type FastTrackOrigin =
        pallet_collective::EnsureProportionAtLeast<AccountId, CouncilCollective, 2, 3>;
    type InstantOrigin =
        pallet_collective::EnsureProportionAtLeast<AccountId, CouncilCollective, 1, 1>;
    type InstantAllowed = frame::traits::ConstBool<true>;
    type FastTrackVotingPeriod = FastTrackVotingPeriod;
    // To cancel a proposal which has been passed, 2/3 of the council must agree to it.
    type CancellationOrigin =
        pallet_collective::EnsureProportionAtLeast<AccountId, CouncilCollective, 2, 3>;
    // To cancel a proposal before it has been passed, the council must be unanimous or
    // Root must agree.
    type CancelProposalOrigin = EitherOfDiverse<
        EnsureRoot<AccountId>,
        pallet_collective::EnsureProportionAtLeast<AccountId, CouncilCollective, 1, 1>,
    >;
    type BlacklistOrigin = EnsureRoot<AccountId>;
    // Any single council member may veto a coming council proposal, however they can
    // only do it once and it lasts only for the cool-off period.
    type VetoOrigin = pallet_collective::EnsureMember<AccountId, CouncilCollective>;
    type CooloffPeriod = CooloffPeriod;
    type Slash = Treasury;
    type Scheduler = Scheduler;
    type PalletsOrigin = OriginCaller;
    type MaxVotes = ConstU32<100>;
    type WeightInfo = pallet_democracy::weights::SubstrateWeight<Runtime>;
    type MaxProposals = MaxProposals;
    type Preimages = Preimage;
    type MaxDeposits = ConstU32<100>;
    type MaxBlacklisted = ConstU32<100>;
}

parameter_types! {
    pub const CouncilMotionDuration: BlockNumber = 7 * time::DAYS;
    pub const CouncilMaxProposals: u32 = 100;
    pub const CouncilMaxMembers: u32 = 100;
    pub MaxProposalWeight: Weight = Perbill::from_percent(50) * BlockWeights::get().max_block;
}

type CouncilCollective = pallet_collective::Instance1;
impl pallet_collective::Config<CouncilCollective> for Runtime {
    type RuntimeOrigin = RuntimeOrigin;
    type Proposal = RuntimeCall;
    type RuntimeEvent = RuntimeEvent;
    type MotionDuration = CouncilMotionDuration;
    type MaxProposals = CouncilMaxProposals;
    type SetMembersOrigin = EnsureRoot<AccountId>;
    type MaxMembers = CouncilMaxMembers;
    type DefaultVote = pallet_collective::PrimeDefaultVote;
    type WeightInfo = pallet_collective::weights::SubstrateWeight<Runtime>;
    type MaxProposalWeight = MaxProposalWeight;
}

parameter_types! {
    // phase durations. 1/4 of the last session for each.
    pub const SignedPhase: u32 = time::EPOCH_DURATION_IN_BLOCKS / 4;
    pub const UnsignedPhase: u32 = time::EPOCH_DURATION_IN_BLOCKS / 4;

    // signed config
    pub const SignedRewardBase: Balance = 0;
    pub const SignedDepositBase: Balance = 5 * currency::CENT;
    pub const SignedDepositByte: Balance = currency::CENT;

    pub BetterUnsignedThreshold: Perbill = Perbill::from_rational(1u32, 10_000);

    // miner configs
    pub const MultiPhaseUnsignedPriority: TransactionPriority = StakingUnsignedPriority::get() - 1u64;
    pub MinerMaxWeight: Weight = BlockWeights::get()
        .get(DispatchClass::Normal)
        .max_extrinsic.expect("Normal extrinsics have a weight limit configured; qed")
        .saturating_sub(BlockExecutionWeight::get());
    // Solution can occupy 50% of normal block size
    pub MinerMaxLength: u32 = Perbill::from_rational(5u32, 10) *
        *BlockLength::get()
        .max
        .get(DispatchClass::Normal);
}

frame_election_provider_support::generate_solution_type!(
    #[compact]
    pub struct NposSolution16::<
        VoterIndex = u32,
        TargetIndex = u16,
        Accuracy = sp_runtime::PerU16,
        MaxVoters = MaxElectingVoters,
    >(16)
);

parameter_types! {
    pub MaxNominations: u32 = <NposSolution16 as frame_election_provider_support::NposSolution>::LIMIT as u32;
    pub MaxElectingVoters: u32 = 40_000;
    pub MaxElectableTargets: u16 = 10_000;
    // OnChain values are lower.
    pub MaxOnChainElectingVoters: u32 = 5000;
    pub MaxOnChainElectableTargets: u16 = 1250;
    // The maximum winners that can be elected by the Election pallet which is equivalent to the
    // maximum active validators the staking pallet can have.
    pub MaxActiveValidators: u32 = 1000;
    pub ElectionBoundsOnChain: ElectionBounds = ElectionBoundsBuilder::default()
        .voters_count(5_000.into()).targets_count(1_250.into()).build();
    pub ElectionBoundsMultiPhase: ElectionBounds = ElectionBoundsBuilder::default()
        .voters_count(10_000.into()).targets_count(1_500.into()).build();
}

/// The numbers configured here could always be more than the the maximum limits of staking pallet
/// to ensure election snapshot will not run out of memory. For now, we set them to smaller values
/// since the staking is bounded and the weight pipeline takes hours for this single pallet.
pub struct ElectionProviderBenchmarkConfig;
impl pallet_election_provider_multi_phase::BenchmarkingConfig for ElectionProviderBenchmarkConfig {
    const VOTERS: [u32; 2] = [1000, 2000];
    const TARGETS: [u32; 2] = [500, 1000];
    const ACTIVE_VOTERS: [u32; 2] = [500, 800];
    const DESIRED_TARGETS: [u32; 2] = [200, 400];
    const SNAPSHOT_MAXIMUM_VOTERS: u32 = 1000;
    const MINER_MAXIMUM_VOTERS: u32 = 1000;
    const MAXIMUM_TARGETS: u32 = 300;
}

/// Maximum number of iterations for balancing that will be executed in the embedded OCW
/// miner of election provider multi phase.
pub const MINER_MAX_ITERATIONS: u32 = 10;

/// A source of random balance for NposSolver, which is meant to be run by the OCW election miner.
pub struct OffchainRandomBalancing;
impl Get<Option<BalancingConfig>> for OffchainRandomBalancing {
    fn get() -> Option<BalancingConfig> {
        use sp_runtime::traits::TrailingZeroInput;
        let iterations = match MINER_MAX_ITERATIONS {
            0 => 0,
            max => {
                let seed = sp_io::offchain::random_seed();
                let random = <u32>::decode(&mut TrailingZeroInput::new(&seed))
                    .expect("input is padded with zeroes; qed")
                    % max.saturating_add(1);
                random as usize
            }
        };

        let config = BalancingConfig {
            iterations,
            tolerance: 0,
        };
        Some(config)
    }
}

pub struct OnChainSeqPhragmen;
impl onchain::Config for OnChainSeqPhragmen {
    type System = Runtime;
    type Solver = SequentialPhragmen<
        AccountId,
        pallet_election_provider_multi_phase::SolutionAccuracyOf<Runtime>,
    >;
    type DataProvider = <Runtime as pallet_election_provider_multi_phase::Config>::DataProvider;
    type WeightInfo = frame_election_provider_support::weights::SubstrateWeight<Runtime>;
    type MaxWinners = <Runtime as pallet_election_provider_multi_phase::Config>::MaxWinners;
    type Bounds = ElectionBoundsOnChain;
}

impl pallet_election_provider_multi_phase::MinerConfig for Runtime {
    type AccountId = AccountId;
    type MaxLength = MinerMaxLength;
    type MaxWeight = MinerMaxWeight;
    type Solution = NposSolution16;
    type MaxWinners = MaxActiveValidators;
    type MaxVotesPerVoter =
	<<Self as pallet_election_provider_multi_phase::Config>::DataProvider as ElectionDataProvider>::MaxVotesPerVoter;

    // The unsigned submissions have to respect the weight of the submit_unsigned call, thus their
    // weight estimate function is wired to this call's weight.
    fn solution_weight(v: u32, t: u32, a: u32, d: u32) -> Weight {
        <
			<Self as pallet_election_provider_multi_phase::Config>::WeightInfo
			as
			pallet_election_provider_multi_phase::WeightInfo
		>::submit_unsigned(v, t, a, d)
    }
}

parameter_types! {
    pub const SignedFixedDeposit: Balance = 1; // Need to be updated with correct value.
    pub const SignedDepositIncreaseFactor: Percent = Percent::from_percent(10);
}

impl pallet_election_provider_multi_phase::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type EstimateCallFee = TransactionPayment;
    type SignedPhase = SignedPhase;
    type UnsignedPhase = UnsignedPhase;
    type BetterSignedThreshold = ();
    type OffchainRepeat = OffchainRepeat;
    type MinerTxPriority = MultiPhaseUnsignedPriority;
    type MinerConfig = Self;
    type SignedMaxSubmissions = ConstU32<10>;
    type SignedRewardBase = SignedRewardBase;
    type SignedDepositBase =
        GeometricDepositBase<Balance, SignedFixedDeposit, SignedDepositIncreaseFactor>;
    type SignedDepositByte = SignedDepositByte;
    type SignedMaxRefunds = ConstU32<3>;
    type SignedDepositWeight = ();
    type SignedMaxWeight = MinerMaxWeight;
    type SlashHandler = (); // burn slashes
    type RewardHandler = (); // nothing to do upon rewards
    type DataProvider = Staking;
    type Fallback = onchain::OnChainExecution<OnChainSeqPhragmen>;
    type GovernanceFallback = onchain::OnChainExecution<OnChainSeqPhragmen>;
    type Solver = SequentialPhragmen<AccountId, SolutionAccuracyOf<Self>, OffchainRandomBalancing>;
    type ForceOrigin = EnsureRootOrHalfCouncil;
    type MaxWinners = MaxActiveValidators;
    type BenchmarkingConfig = ElectionProviderBenchmarkConfig;
    type ElectionBounds = ElectionBoundsMultiPhase;
    type WeightInfo = pallet_election_provider_multi_phase::weights::SubstrateWeight<Self>;
}

parameter_types! {
    pub const BagThresholds: &'static [u64] = &crate::bags::THRESHOLDS;
}

impl pallet_bags_list::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type ScoreProvider = Staking;
    type WeightInfo = pallet_bags_list::weights::SubstrateWeight<Runtime>;
    type BagThresholds = BagThresholds;
    type Score = VoteWeight;
}

parameter_types! {
    pub const ImOnlineUnsignedPriority: TransactionPriority = TransactionPriority::MAX;
    /// We prioritize im-online heartbeats over election solution submission.
    pub const StakingUnsignedPriority: TransactionPriority = TransactionPriority::MAX / 2;
}

impl<LocalCall> frame_system::offchain::CreateSignedTransaction<LocalCall> for Runtime
where
    RuntimeCall: From<LocalCall>,
{
    fn create_transaction<C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>>(
        call: RuntimeCall,
        public: <Signature as frame::traits::Verify>::Signer,
        account: AccountId,
        nonce: Nonce,
    ) -> Option<(
        RuntimeCall,
        <UncheckedExtrinsic as frame::traits::Extrinsic>::SignaturePayload,
    )> {
        let tip = 0;
        // take the biggest period possible.
        let period = BlockHashCount::get()
            .checked_next_power_of_two()
            .map(|c| c / 2)
            .unwrap_or(2);
        let current_block = System::block_number()
            .saturated_into::<u32>()
            // The `System::block_number` is initialized with `n+1`,
            // so the actual block number is `n`.
            .saturating_sub(1);
        let era = generic::Era::mortal(period.into(), current_block.into());
        let extra = (
            frame_system::CheckNonZeroSender::<Runtime>::new(),
            frame_system::CheckSpecVersion::<Runtime>::new(),
            frame_system::CheckTxVersion::<Runtime>::new(),
            frame_system::CheckGenesis::<Runtime>::new(),
            frame_system::CheckEra::<Runtime>::from(era),
            frame_system::CheckNonce::<Runtime>::from(nonce),
            frame_system::CheckWeight::<Runtime>::new(),
            pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(tip),
            frame_metadata_hash_extension::CheckMetadataHash::<Runtime>::new(true),
        );
        let raw_payload = SignedPayload::new(call, extra)
            .map_err(|e| {
                frame::log::warn!("Unable to create signed payload: {:?}", e);
            })
            .ok()?;
        let signature = raw_payload.using_encoded(|payload| C::sign(payload, public))?;
        let address = Indices::unlookup(account);
        let (call, extra, _) = raw_payload.deconstruct();
        Some((call, (address, signature, extra)))
    }
}

impl frame_system::offchain::SigningTypes for Runtime {
    type Public = <Signature as frame::traits::Verify>::Signer;
    type Signature = Signature;
}

impl<C> frame_system::offchain::SendTransactionTypes<C> for Runtime
where
    RuntimeCall: From<C>,
{
    type Extrinsic = UncheckedExtrinsic;
    type OverarchingCall = RuntimeCall;
}

impl pallet_offences::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type IdentificationTuple = pallet_session::historical::IdentificationTuple<Self>;
    type OnOffenceHandler = Staking;
}

parameter_types! {
    pub const CandidacyBond: Balance = elections::CANDIDACY_BOND;
    // 1 storage item created, key size is 32 bytes, value size is 16+16.
    pub const VotingBondBase: Balance = currency::deposit(1, 64);
    // additional data per vote is 32 bytes (account id).
    pub const VotingBondFactor: Balance = currency::deposit(0, 32);
    pub const TermDuration: BlockNumber = elections::TERM_DURATION;
    pub const DesiredMembers: u32 = elections::DESIRED_MEMBERS;
    pub const DesiredRunnersUp: u32 = elections::DESIRED_RUNNERS_UP;
    pub const MaxCandidates: u32 = elections::MAX_CANDIDATES;
    pub const MaxVoters: u32 = elections::MAX_VOTERS;
    pub const MaxVotesPerVoter: u32 = elections::MAX_VOTES_PER_VOTER;
    pub const ElectionsPhragmenPalletId: LockIdentifier = elections::ELECTIONS_PHRAGMEN_PALLET_ID;
}

// Make sure that there are no more than `MaxMembers` members elected via
// elections-phragmen.
static_assertions::const_assert!(DesiredMembers::get() <= CouncilMaxMembers::get());

impl pallet_elections_phragmen::Config for Runtime {
    type CandidacyBond = CandidacyBond;
    type ChangeMembers = Council;
    type Currency = Balances;
    type CurrencyToVote = U128CurrencyToVote;
    type DesiredMembers = DesiredMembers;
    type DesiredRunnersUp = DesiredRunnersUp;
    type RuntimeEvent = RuntimeEvent;
    type MaxVotesPerVoter = MaxVotesPerVoter;
    // NOTE: this implies that council's genesis members cannot be set directly and
    // must come from this module.
    type InitializeMembers = Council;
    type KickedMember = ();
    type LoserCandidate = ();
    type PalletId = ElectionsPhragmenPalletId;
    type TermDuration = TermDuration;
    type MaxCandidates = MaxCandidates;
    type MaxVoters = MaxVoters;
    type VotingBondBase = VotingBondBase;
    type VotingBondFactor = VotingBondFactor;
    type WeightInfo = pallet_elections_phragmen::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
    pub const BountyValueMinimum: Balance = 1 * ORE;
    pub const BountyDepositBase: Balance = 100 * MILLIORE;
    pub const CuratorDepositMultiplier: Permill = Permill::from_percent(50);
    pub const CuratorDepositMin: Balance = 10 * MILLIORE;
    pub const CuratorDepositMax: Balance = 1_000 * ORE;
    pub const BountyDepositPayoutDelay: BlockNumber = 1 * time::DAYS;
    pub const BountyUpdatePeriod: BlockNumber = 14 * time::DAYS;
}

impl pallet_bounties::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type BountyDepositBase = BountyDepositBase;
    type BountyDepositPayoutDelay = BountyDepositPayoutDelay;
    type BountyUpdatePeriod = BountyUpdatePeriod;
    type CuratorDepositMultiplier = CuratorDepositMultiplier;
    type CuratorDepositMin = CuratorDepositMin;
    type CuratorDepositMax = CuratorDepositMax;
    type BountyValueMinimum = BountyValueMinimum;
    type DataDepositPerByte = DataDepositPerByte;
    type MaximumReasonLength = MaximumReasonLength;
    type WeightInfo = pallet_bounties::weights::SubstrateWeight<Runtime>;
    type OnSlash = Treasury;
    type ChildBountyManager = ChildBounties;
}

parameter_types! {
    pub const ChildBountyValueMinimum: Balance = 10 * MILLIORE;
}

impl pallet_child_bounties::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type MaxActiveChildBountyCount = ConstU32<5>;
    type ChildBountyValueMinimum = ChildBountyValueMinimum;
    type WeightInfo = pallet_child_bounties::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
    pub const MaxKeys: u32 = 10_000;
    pub const MaxPeerInHeartbeats: u32 = 10_000;
}

impl pallet_im_online::Config for Runtime {
    type AuthorityId = ImOnlineId;
    type RuntimeEvent = RuntimeEvent;
    type NextSessionRotation = pallet_session::PeriodicSessions<SessionPeriod, SessionOffset>;
    type ValidatorSet = Historical;
    type ReportUnresponsiveness = ();
    type UnsignedPriority = ImOnlineUnsignedPriority;
    type WeightInfo = pallet_im_online::weights::SubstrateWeight<Runtime>;
    type MaxKeys = MaxKeys;
    type MaxPeerInHeartbeats = MaxPeerInHeartbeats;
}

/// Calls that cannot be paused by the tx-pause pallet.
pub struct TxPauseWhitelistedCalls;
/// Whitelist `Balances::transfer_keep_alive`, all others are pauseable.
impl frame::traits::Contains<pallet_tx_pause::RuntimeCallNameOf<Runtime>>
    for TxPauseWhitelistedCalls
{
    fn contains(full_name: &pallet_tx_pause::RuntimeCallNameOf<Runtime>) -> bool {
        matches!(
            (full_name.0.as_slice(), full_name.1.as_slice()),
            (b"Balances", b"transfer_keep_alive")
        )
    }
}

impl pallet_tx_pause::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type PauseOrigin = EnsureRoot<AccountId>;
    type UnpauseOrigin = EnsureRoot<AccountId>;
    type WhitelistedCalls = TxPauseWhitelistedCalls;
    type MaxNameLen = ConstU32<256>;
    type WeightInfo = pallet_tx_pause::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
    pub const BasicDeposit: Balance = currency::deposit(0, 100);
    pub const ByteDeposit: Balance = currency::deposit(0, 100);
    pub const SubAccountDeposit: Balance = currency::deposit(1, 1);
    pub const MaxSubAccounts: u32 = 100;
    #[derive(Serialize, Deserialize)]
    pub const MaxAdditionalFields: u32 = 100;
    pub const MaxRegistrars: u32 = 25;
    pub const PendingUsernameExpiration: u32 = 7 * time::DAYS;
}

impl pallet_identity::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    /// The amount held on deposit for a registered subaccount.
    type SubAccountDeposit = SubAccountDeposit;
    /// The maximum number of sub-accounts allowed per identified account.
    type MaxSubAccounts = MaxSubAccounts;
    /// Maximum number of registrars allowed in the system.
    type MaxRegistrars = MaxRegistrars;
    type Slashed = Treasury;
    /// The origin which may forcibly set or remove a name. Root can always do this.
    type ForceOrigin = EnsureRoot<Self::AccountId>;
    /// The origin which may add or remove registrars. Root can always do this.
    type RegistrarOrigin = EnsureRoot<Self::AccountId>;
    /// The amount held on deposit for a registered identity.
    type BasicDeposit = BasicDeposit;
    /// The amount held on deposit per additional bytes in additional fields for a registered
    /// identity
    type ByteDeposit = ByteDeposit;
    type IdentityInformation = pallet_identity::legacy::IdentityInfo<MaxAdditionalFields>;
    type OffchainSignature = Signature;
    type SigningPublicKey = <Signature as frame::traits::Verify>::Signer;
    type UsernameAuthorityOrigin = EnsureRoot<AccountId>;
    type PendingUsernameExpiration = PendingUsernameExpiration;
    type MaxSuffixLength = ConstU32<7>;
    type MaxUsernameLength = ConstU32<64>;
    type WeightInfo = ();
}

impl pallet_utility::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type PalletsOrigin = OriginCaller;
    type WeightInfo = ();
}

parameter_types! {
    // One storage item; key size is 32; value is size 4+4+16+32 bytes = 56 bytes.
    pub const DepositBase: Balance = currency::deposit(1, 88);
    // Additional storage item size of 32 bytes.
    pub const DepositFactor: Balance = currency::deposit(0, 32);
}

impl pallet_multisig::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type Currency = Balances;
    type DepositBase = DepositBase;
    type DepositFactor = DepositFactor;
    type MaxSignatories = ConstU32<100>;
    type WeightInfo = pallet_multisig::weights::SubstrateWeight<Runtime>;
}

impl pallet_orehub::Config for Runtime {}

/// All migrations of the runtime, aside from the ones declared in the pallets.
///
/// This can be a tuple of types, each implementing `OnRuntimeUpgrade`.
#[allow(unused_parens)]
type Migrations = ();

/// Unchecked extrinsic type as expected by this runtime.
pub type UncheckedExtrinsic =
    generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;

/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;

/// The payload being signed in transactions.
pub type SignedPayload = generic::SignedPayload<RuntimeCall, SignedExtra>;
/// Executive: handles dispatch to the various modules.
pub type RuntimeExecutive = Executive<
    Runtime,
    Block,
    frame_system::ChainContext<Runtime>,
    Runtime,
    AllPalletsWithSystem,
    Migrations,
>;

impl_runtime_apis! {
    impl apis::Core<Block> for Runtime {
        fn version() -> RuntimeVersion {
            VERSION
        }

        fn execute_block(block: Block) {
            RuntimeExecutive::execute_block(block)
        }

        fn initialize_block(header: &Header) -> ExtrinsicInclusionMode {
            RuntimeExecutive::initialize_block(header)
        }
    }
    impl apis::Metadata<Block> for Runtime {
        fn metadata() -> OpaqueMetadata {
            OpaqueMetadata::new(Runtime::metadata().into())
        }

        fn metadata_at_version(version: u32) -> Option<OpaqueMetadata> {
            Runtime::metadata_at_version(version)
        }

        fn metadata_versions() -> Vec<u32> {
            Runtime::metadata_versions()
        }
    }

    impl apis::BlockBuilder<Block> for Runtime {
        fn apply_extrinsic(extrinsic: ExtrinsicFor<Runtime>) -> ApplyExtrinsicResult {
            RuntimeExecutive::apply_extrinsic(extrinsic)
        }

        fn finalize_block() -> HeaderFor<Runtime> {
            RuntimeExecutive::finalize_block()
        }

        fn inherent_extrinsics(data: InherentData) -> Vec<ExtrinsicFor<Runtime>> {
            data.create_extrinsics()
        }

        fn check_inherents(
            block: Block,
            data: InherentData,
        ) -> CheckInherentsResult {
            data.check_extrinsics(&block)
        }
    }

    impl apis::TaggedTransactionQueue<Block> for Runtime {
        fn validate_transaction(
            source: TransactionSource,
            tx: ExtrinsicFor<Runtime>,
            block_hash: <Runtime as frame_system::Config>::Hash,
        ) -> TransactionValidity {
            RuntimeExecutive::validate_transaction(source, tx, block_hash)
        }
    }

    impl apis::OffchainWorkerApi<Block> for Runtime {
        fn offchain_worker(header: &HeaderFor<Runtime>) {
            RuntimeExecutive::offchain_worker(header)
        }
    }


    impl apis::SessionKeys<Block> for Runtime {
        fn generate_session_keys(seed: Option<Vec<u8>>) -> Vec<u8> {
            opaque::SessionKeys::generate(seed)
        }

        fn decode_session_keys(
            encoded: Vec<u8>,
        ) -> Option<Vec<(Vec<u8>, apis::KeyTypeId)>> {
            opaque::SessionKeys::decode_into_raw_public_keys(&encoded)
        }
    }

    impl apis::AuraApi<Block, AuraId> for Runtime {
            fn slot_duration() -> apis::SlotDuration {
                apis::SlotDuration::from_millis(Aura::slot_duration())
            }

            fn authorities() -> Vec<AuraId> {
                pallet_aura::Authorities::<Runtime>::get().into_inner()
            }
        }

    impl apis::GrandpaApi<Block> for Runtime {
        fn grandpa_authorities() -> apis::AuthorityList {
            Grandpa::grandpa_authorities()
        }

        fn current_set_id() -> apis::SetId {
            Grandpa::current_set_id()
        }

        fn submit_report_equivocation_unsigned_extrinsic(
            _equivocation_proof: apis::EquivocationProof<
                <Block as BlockT>::Hash,
                NumberFor<Block>,
            >,
            _key_owner_proof: apis::OpaqueKeyOwnershipProof,
        ) -> Option<()> {
            None
        }

        fn generate_key_ownership_proof(
            _set_id: apis::SetId,
            _authority_id: apis::AuthorityId,
        ) -> Option<apis::OpaqueKeyOwnershipProof> {
            // NOTE: this is the only implementation possible since we've
            // defined our key owner proof type as a bottom type (i.e. a type
            // with no values).
            None
        }
    }

    impl apis::AccountNonceApi<Block, interface::AccountId, interface::Nonce> for Runtime {
        fn account_nonce(account: interface::AccountId) -> interface::Nonce {
            System::account_nonce(account)
        }
    }

    impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<
        Block,
        interface::Balance,
    > for Runtime {
        fn query_info(uxt: ExtrinsicFor<Runtime>, len: u32) -> RuntimeDispatchInfo<interface::Balance> {
            TransactionPayment::query_info(uxt, len)
        }
        fn query_fee_details(uxt: ExtrinsicFor<Runtime>, len: u32) -> FeeDetails<interface::Balance> {
            TransactionPayment::query_fee_details(uxt, len)
        }
        fn query_weight_to_fee(weight: Weight) -> interface::Balance {
            TransactionPayment::weight_to_fee(weight)
        }
        fn query_length_to_fee(length: u32) -> interface::Balance {
            TransactionPayment::length_to_fee(length)
        }
    }

    impl sp_genesis_builder::GenesisBuilder<Block> for Runtime {
        fn build_state(config: Vec<u8>) -> sp_genesis_builder::Result {
            build_state::<RuntimeGenesisConfig>(config)
        }

        fn get_preset(id: &Option<sp_genesis_builder::PresetId>) -> Option<Vec<u8>> {
            get_preset::<RuntimeGenesisConfig>(id, |_| None)
        }

        fn preset_names() -> Vec<sp_genesis_builder::PresetId> {
            vec![]
        }
    }


    #[cfg(feature = "runtime-benchmarks")]
    impl frame_benchmarking::Benchmark<Block> for Runtime {
        fn benchmark_metadata(extra: bool) -> (
            Vec<frame_benchmarking::BenchmarkList>,
            Vec<frame_support::traits::StorageInfo>,
        ) {
            use frame::deps::frame_benchmarking::{baseline, Benchmarking, BenchmarkList};
            use frame::deps::frame_support::traits::StorageInfoTrait;
            use frame::deps::frame_system_benchmarking::Pallet as SystemBench;
            use baseline::Pallet as BaselineBench;

            let mut list = Vec::<BenchmarkList>::new();
            list_benchmarks!(list, extra);

            let storage_info = AllPalletsWithSystem::storage_info();

            (list, storage_info)
        }

        fn dispatch_benchmark(
            config: frame_benchmarking::BenchmarkConfig
        ) -> Result<Vec<frame_benchmarking::BenchmarkBatch>, sp_runtime::RuntimeString> {
            use frame::deps::frame_benchmarking::{baseline, Benchmarking, BenchmarkBatch};
            use frame::deps::sp_storage::TrackedStorageKey;
            use frame::deps::frame_system_benchmarking::Pallet as SystemBench;
            use baseline::Pallet as BaselineBench;

            impl frame::deps::frame_system_benchmarking::Config for Runtime {}
            impl baseline::Config for Runtime {}

            use frame::deps::frame_support::traits::WhitelistedStorageKeys;
            let whitelist: Vec<TrackedStorageKey> = AllPalletsWithSystem::whitelisted_storage_keys();

            let mut batches = Vec::<BenchmarkBatch>::new();
            let params = (&config, &whitelist);
            add_benchmarks!(params, batches);

            Ok(batches)
        }
    }

    #[cfg(feature = "try-runtime")]
    impl frame_try_runtime::TryRuntime<Block> for Runtime {
        fn on_runtime_upgrade(checks: frame_try_runtime::UpgradeCheckSelect) -> (Weight, Weight) {
            // NOTE: intentional unwrap: we don't want to propagate the error backwards, and want to
            // have a backtrace here. If any of the pre/post migration checks fail, we shall stop
            // right here and right now.
            let weight = RuntimeExecutive::try_runtime_upgrade(checks).unwrap();
            (weight, BlockWeights::get().max_block)
        }

        fn execute_block(
            block: Block,
            state_root_check: bool,
            signature_check: bool,
            select: frame_try_runtime::TryStateSelect
        ) -> Weight {
            // NOTE: intentional unwrap: we don't want to propagate the error backwards, and want to
            // have a backtrace here.
            RuntimeExecutive::try_execute_block(block, state_root_check, signature_check, select).expect("execute-block failed")
        }
    }
}

#[cfg(feature = "runtime-benchmarks")]
mod benches {
    frame::deps::frame_benchmarking::define_benchmarks!(
        [frame_benchmarking, BaselineBench::<Runtime>]
        [frame_system, SystemBench::<Runtime>]
        [pallet_balances, Balances]
        [pallet_timestamp, Timestamp]
        [pallet_sudo, Sudo]
    );
}

/// Some re-exports that the node side code needs to know. Some are useful in this context as well.
///
/// Other types should preferably be private.
// TODO: this should be standardized in some way, see:
// https://github.com/paritytech/substrate/issues/10579#issuecomment-1600537558
pub mod interface {
    use super::Runtime;
    use frame::deps::frame_system;

    pub type Block = <Runtime as frame_system::Config>::Block;
    pub use frame::runtime::types_common::OpaqueBlock;
    pub type AccountId = <Runtime as frame_system::Config>::AccountId;
    pub type Signature = super::Signature;
    pub type Nonce = <Runtime as frame_system::Config>::Nonce;
    pub type Hash = <Runtime as frame_system::Config>::Hash;
    pub type Balance = <Runtime as pallet_balances::Config>::Balance;
    pub type MinimumBalance = <Runtime as pallet_balances::Config>::ExistentialDeposit;
    pub type SS58Prefix = <Runtime as frame_system::Config>::SS58Prefix;

    pub use frame_system::Call as SystemCall;
    pub use pallet_balances::Call as BalancesCall;
    pub use pallet_timestamp::Call as TimestampCall;
}
