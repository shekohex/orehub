#![warn(missing_docs)]
//! RPC interface for the runtime.

use frame::runtime::types_common::BlockNumber;
use jsonrpsee::RpcModule;
use orehub_runtime::interface::{AccountId, Balance, Hash, Nonce, OpaqueBlock as Block};
use sc_client_api::Backend;
use sc_rpc::SubscriptionTaskExecutor;
use sc_transaction_pool_api::TransactionPool;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};
use std::sync::Arc;

pub use sc_rpc_api::DenyUnsafe;

/// Extra dependencies for GRANDPA
pub struct GrandpaDeps<BE> {
    /// Voting round info.
    pub shared_voter_state: sc_consensus_grandpa::SharedVoterState,
    /// Authority set info.
    pub shared_authority_set: sc_consensus_grandpa::SharedAuthoritySet<Hash, BlockNumber>,
    /// Receives notifications about justification events from Grandpa.
    pub justification_stream: sc_consensus_grandpa::GrandpaJustificationStream<Block>,
    /// Executor to drive the subscription manager in the Grandpa RPC handler.
    pub subscription_executor: SubscriptionTaskExecutor,
    /// Finality proof provider.
    pub finality_provider: Arc<sc_consensus_grandpa::FinalityProofProvider<BE, Block>>,
}

/// Full client dependencies.
pub struct FullDeps<C, P, BE> {
    /// The client instance to use.
    pub client: Arc<C>,
    /// Transaction pool instance.
    pub pool: Arc<P>,
    /// Whether to deny unsafe calls
    pub deny_unsafe: DenyUnsafe,
    /// GRANDPA specific dependencies.
    pub grandpa: GrandpaDeps<BE>,
}

#[docify::export]
/// Instantiate all full RPC extensions.
pub fn create_full<C, P, BE>(
    deps: FullDeps<C, P, BE>,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
where
    C: Send
        + Sync
        + 'static
        + sp_api::ProvideRuntimeApi<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = BlockChainError>
        + 'static,
    C::Api: sp_block_builder::BlockBuilder<Block>,
    C::Api: substrate_frame_rpc_system::AccountNonceApi<Block, AccountId, Nonce>,
    C::Api: pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>,
    BE: Backend<Block> + 'static,
    P: TransactionPool + 'static,
{
    use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};
    use sc_consensus_grandpa_rpc::{Grandpa, GrandpaApiServer};
    use substrate_frame_rpc_system::{System, SystemApiServer};

    let mut module = RpcModule::new(());
    let FullDeps { client, pool, deny_unsafe, grandpa } = deps;

    let GrandpaDeps {
        shared_voter_state,
        shared_authority_set,
        justification_stream,
        subscription_executor,
        finality_provider,
    } = grandpa;

    module.merge(System::new(client.clone(), pool.clone(), deny_unsafe).into_rpc())?;
    module.merge(TransactionPayment::new(client.clone()).into_rpc())?;
    module.merge(
        Grandpa::new(
            subscription_executor,
            shared_authority_set.clone(),
            shared_voter_state,
            justification_stream,
            finality_provider,
        )
        .into_rpc(),
    )?;

    // You probably want to enable the `rpc v2 chainSpec` API as well
    //
    // let chain_name = chain_spec.name().to_string();
    // let genesis_hash = client.block_hash(0).ok().flatten().expect("Genesis block exists; qed");
    // let properties = chain_spec.properties();
    // module.merge(ChainSpec::new(chain_name, genesis_hash, properties).into_rpc())?;

    Ok(module)
}
