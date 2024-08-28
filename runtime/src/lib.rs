//! A minimal runtime for OreHub.

#![cfg_attr(not(feature = "std"), no_std)]

// Make the WASM binary available.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

extern crate alloc;

use alloc::{vec, vec::Vec};
use consts::currency::Balance;
use frame::{
    arithmetic::*,
    deps::{
        frame_support::{
            genesis_builder_helper::{build_state, get_preset},
            runtime,
            weights::{
                constants::{RocksDbWeight, WEIGHT_REF_TIME_PER_SECOND},
                ConstantMultiplier, IdentityFee,
            },
        },
        sp_core,
    },
    prelude::*,
    primitives::*,
    runtime::{
        apis::{
            self, ed25519::AuthorityId as AuraId, impl_runtime_apis, ApplyExtrinsicResult,
            CheckInherentsResult, ExtrinsicInclusionMode, OpaqueMetadata,
        },
        prelude::*,
        types_common::*,
    },
    traits::{Block as BlockT, NumberFor},
};

/// Predefined constants for the runtime.
pub mod consts;

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
    spec_version: 1000,
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
mod runtime {
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

    /// Mandatory system pallet that should always be included in a FRAME runtime.
    #[runtime::pallet_index(0)]
    pub type System = frame_system::Pallet<Runtime>;

    /// Provides a way for consensus systems to set and check the onchain time.
    #[runtime::pallet_index(1)]
    pub type Timestamp = pallet_timestamp::Pallet<Runtime>;

    #[runtime::pallet_index(2)]
    pub type Aura = pallet_aura::Pallet<Runtime>;

    #[runtime::pallet_index(3)]
    pub type Grandpa = pallet_grandpa::Pallet<Runtime>;

    /// Provides the ability to keep track of balances.
    #[runtime::pallet_index(4)]
    pub type Balances = pallet_balances::Pallet<Runtime>;

    /// Provides a way to execute privileged functions.
    #[runtime::pallet_index(5)]
    pub type Sudo = pallet_sudo::Pallet<Runtime>;

    /// Provides the ability to charge for extrinsic execution.
    #[runtime::pallet_index(6)]
    pub type TransactionPayment = pallet_transaction_payment::Pallet<Runtime>;

    /// Provides the ability to track the current block author.
    #[runtime::pallet_index(7)]
    pub type Author = pallet_authorship::Pallet<Runtime>;

    /// A Playground pallet for testing.
    #[runtime::pallet_index(8)]
    pub type OreHub = pallet_orehub::Pallet<Runtime>;
}

const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);

parameter_types! {
    pub const BlockHashCount: BlockNumber = 2400;
    pub const Version: RuntimeVersion = VERSION;
    /// We allow for 2 seconds of compute with a 5 second average block time.
    pub BlockWeights: frame_system::limits::BlockWeights =
        frame_system::limits::BlockWeights::with_sensible_defaults(
            Weight::from_parts(2u64 * WEIGHT_REF_TIME_PER_SECOND, u64::MAX),
            NORMAL_DISPATCH_RATIO,
        );
    pub BlockLength: frame_system::limits::BlockLength = frame_system::limits::BlockLength
        ::max_with_normal_ratio(consts::MAX_BLOCK_SIZE, NORMAL_DISPATCH_RATIO);
    /// Our custom SS58 prefix.
    pub const SS58Prefix: u16 = consts::SS58_PREFIX;
}

/// Implements the types required for the system pallet.
///
/// The default types are being injected by [`derive_impl`](`frame_support::derive_impl`) from
/// [`SoloChainDefaultConfig`](`struct@frame_system::config_preludes::SolochainDefaultConfig`),
/// but overridden as needed.
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
    /// The data to be stored in an account.
    type AccountData = pallet_balances::AccountData<consts::currency::Balance>;
    type SS58Prefix = SS58Prefix;
    type MaxConsumers = frame::traits::ConstU32<16>;
    type SystemWeightInfo = frame::deps::frame_system::weights::SubstrateWeight<Self>;
}

// Implements the types required for the balances pallet.
impl pallet_balances::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    /// The type for recording an account's balance.
    type Balance = consts::currency::Balance;
    type ExistentialDeposit = frame::traits::ConstU128<{ consts::currency::EXISTENTIAL_DEPOSIT }>;
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
    pub const MaxAuthorities: u32 = 32;
    pub const AllowMultipleBlocksPerSlot: bool = false;
    pub const MaxNominators: u32 = 0;
    pub const MaxSetIdSessionEntries: u32 = 0;
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

    type KeyOwnerProof = sp_core::Void;
    type EquivocationReportSystem = ();

    type WeightInfo = ();
}

// Implements the types required for the sudo pallet.
impl pallet_sudo::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type WeightInfo = pallet_sudo::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
    pub const BlockTime: u64 = consts::time::SLOT_DURATION;
}

impl pallet_timestamp::Config for Runtime {
    type Moment = u64;
    type OnTimestampSet = Aura;
    type MinimumPeriod = BlockTime;
    type WeightInfo = pallet_timestamp::weights::SubstrateWeight<Self>;
}

// Implements the types required for the authorship pallet.
impl pallet_authorship::Config for Runtime {
    type FindAuthor = pallet_aura::AuraAuthorId<Self>;
    type EventHandler = ();
}

parameter_types! {
    pub const TransactionByteFee: Balance = consts::currency::NANORE;
    pub const OperationalFeeMultiplier: u8 = 5;
    pub FeeMultiplier: Multiplier = Multiplier::one();
}

// Implements the types required for the transaction payment pallet.
impl pallet_transaction_payment::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    // TODO: deal with unbalanced fees
    type OnChargeTransaction = pallet_transaction_payment::FungibleAdapter<Balances, ()>;
    type OperationalFeeMultiplier = OperationalFeeMultiplier;
    type WeightToFee = IdentityFee<Balance>;
    type LengthToFee = ConstantMultiplier<Balance, TransactionByteFee>;
    type FeeMultiplierUpdate = ConstFeeMultiplier<FeeMultiplier>;
}

impl pallet_orehub::Config for Runtime {}

/// The address format for describing accounts.
pub type Address = sp_runtime::MultiAddress<AccountId, ()>;
/// Block header type as expected by this runtime.
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
/// Index of a transaction in the chain.
pub type Nonce = u32;
/// A hash of some data used by the chain.
pub type Hash = H256;

/// All migrations of the runtime, aside from the ones declared in the pallets.
///
/// This can be a tuple of types, each implementing `OnRuntimeUpgrade`.
#[allow(unused_parens)]
type Migrations = ();

/// Unchecked extrinsic type as expected by this runtime.
pub type UncheckedExtrinsic =
    generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;

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

use pallet_transaction_payment::{ConstFeeMultiplier, FeeDetails, Multiplier, RuntimeDispatchInfo};
use sp_runtime::generic;

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

    impl apis::AuraApi<Block, AuraId> for Runtime {
        fn slot_duration() -> apis::SlotDuration {
            apis::SlotDuration::from_millis(Aura::slot_duration())
        }

        fn authorities() -> Vec<AuraId> {
            pallet_aura::Authorities::<Runtime>::get().into_inner()
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

    pub use frame_system::Call as SystemCall;
    pub use pallet_balances::Call as BalancesCall;
    pub use pallet_timestamp::Call as TimestampCall;
}
