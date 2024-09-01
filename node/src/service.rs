// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use futures::FutureExt;
use orehub_runtime::{interface::OpaqueBlock as Block, RuntimeApi};
use sc_client_api::{Backend, BlockBackend};
use sc_executor::WasmExecutor;
use sc_service::{error::Error as ServiceError, Configuration, TaskManager};
use sc_telemetry::{Telemetry, TelemetryWorker};
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;

#[cfg(feature = "manual-seal")]
use crate::cli::Consensus;

#[cfg(feature = "runtime-benchmarks")]
type HostFunctions = (
    sp_io::SubstrateHostFunctions,
    frame_benchmarking::benchmarking::HostFunctions,
);

#[cfg(not(feature = "runtime-benchmarks"))]
type HostFunctions = sp_io::SubstrateHostFunctions;

#[docify::export]
pub(crate) type FullClient =
    sc_service::TFullClient<Block, RuntimeApi, WasmExecutor<HostFunctions>>;

type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;

#[cfg(not(feature = "manual-seal"))]
type AuraPair = sp_consensus_aura::ed25519::AuthorityPair;

/// The minimum period of blocks on which justifications will be
/// imported and generated.
const GRANDPA_JUSTIFICATION_PERIOD: u32 = 512;

/// Assembly of PartialComponents (enough to run chain ops subcommands)
#[cfg(not(feature = "manual-seal"))]
pub type Service = sc_service::PartialComponents<
    FullClient,
    FullBackend,
    FullSelectChain,
    sc_consensus::DefaultImportQueue<Block>,
    sc_transaction_pool::FullPool<Block, FullClient>,
    (
        sc_consensus_grandpa::GrandpaBlockImport<FullBackend, Block, FullClient, FullSelectChain>,
        sc_consensus_grandpa::LinkHalf<Block, FullClient, FullSelectChain>,
        Option<Telemetry>,
    ),
>;

#[cfg(feature = "manual-seal")]
pub type Service = sc_service::PartialComponents<
    FullClient,
    FullBackend,
    FullSelectChain,
    sc_consensus::DefaultImportQueue<Block>,
    sc_transaction_pool::FullPool<Block, FullClient>,
    (Option<Telemetry>,),
>;

pub fn new_partial(config: &Configuration) -> Result<Service, ServiceError> {
    let telemetry = config
        .telemetry_endpoints
        .clone()
        .filter(|x| !x.is_empty())
        .map(|endpoints| -> Result<_, sc_telemetry::Error> {
            let worker = TelemetryWorker::new(16)?;
            let telemetry = worker.handle().new_telemetry(endpoints);
            Ok((worker, telemetry))
        })
        .transpose()?;

    let executor = sc_service::new_wasm_executor(config);

    let (client, backend, keystore_container, task_manager) =
        sc_service::new_full_parts::<Block, RuntimeApi, _>(
            config,
            telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
            executor,
        )?;
    let client = Arc::new(client);

    let telemetry = telemetry.map(|(worker, telemetry)| {
        task_manager
            .spawn_handle()
            .spawn("telemetry", None, worker.run());
        telemetry
    });

    let select_chain = sc_consensus::LongestChain::new(backend.clone());

    let transaction_pool = sc_transaction_pool::BasicPool::new_full(
        config.transaction_pool.clone(),
        config.role.is_authority().into(),
        config.prometheus_registry(),
        task_manager.spawn_essential_handle(),
        client.clone(),
    );

    #[cfg(not(feature = "manual-seal"))]
    let (grandpa_block_import, grandpa_link) = sc_consensus_grandpa::block_import(
        client.clone(),
        GRANDPA_JUSTIFICATION_PERIOD,
        &client,
        select_chain.clone(),
        telemetry.as_ref().map(|x| x.handle()),
    )?;
    #[cfg(feature = "manual-seal")]
    let import_queue = sc_consensus_manual_seal::import_queue(
        Box::new(client.clone()),
        &task_manager.spawn_essential_handle(),
        config.prometheus_registry(),
    );

    #[cfg(not(feature = "manual-seal"))]
    let cidp_client = client.clone();
    #[cfg(not(feature = "manual-seal"))]
    let import_queue = sc_consensus_aura::import_queue::<AuraPair, _, _, _, _, _>(
        sc_consensus_aura::ImportQueueParams {
            block_import: grandpa_block_import.clone(),
            justification_import: Some(Box::new(grandpa_block_import.clone())),
            client: client.clone(),
            create_inherent_data_providers: move |parent_hash, _| {
                let cidp_client = cidp_client.clone();
                async move {
                    let slot_duration = sc_consensus_aura::standalone::slot_duration_at(
                        &*cidp_client,
                        parent_hash,
                    )?;
                    let timestamp = sp_timestamp::InherentDataProvider::from_system_time();
                    let slot = sp_consensus_aura::inherents::InherentDataProvider::from_timestamp_and_slot_duration(*timestamp, slot_duration);
                    Ok((slot, timestamp))
                }
            },
            spawner: &task_manager.spawn_essential_handle(),
            registry: config.prometheus_registry(),
            check_for_equivocation: Default::default(),
            telemetry: telemetry.as_ref().map(|x| x.handle()),
            compatibility_mode: Default::default(),
        },
    )?;

    Ok(sc_service::PartialComponents {
        client,
        backend,
        task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other: (
            #[cfg(not(feature = "manual-seal"))]
            grandpa_block_import,
            #[cfg(not(feature = "manual-seal"))]
            grandpa_link,
            telemetry,
        ),
    })
}

pub struct FullNodeArgs {
    pub config: Configuration,
    #[cfg(feature = "manual-seal")]
    pub consensus: Consensus,
    pub hwbench: Option<sc_sysinfo::HwBench>,
}

/// Builds a new service for a full client.
pub fn new_full<Network: sc_network::NetworkBackend<Block, <Block as BlockT>::Hash>>(
    FullNodeArgs {
        config,
        #[cfg(feature = "manual-seal")]
        consensus,
        hwbench,
    }: FullNodeArgs,
) -> Result<TaskManager, ServiceError> {
    let sc_service::PartialComponents {
        client,
        backend,
        mut task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other: other_stuff,
    } = new_partial(&config)?;

    #[cfg(not(feature = "manual-seal"))]
    let (block_import, grandpa_link, mut telemetry) = other_stuff;
    #[cfg(feature = "manual-seal")]
    let (mut telemetry,) = other_stuff;

    #[cfg(feature = "manual-seal")]
    let net_config = sc_network::config::FullNetworkConfiguration::<
        Block,
        <Block as BlockT>::Hash,
        Network,
    >::new(&config.network);

    #[cfg(not(feature = "manual-seal"))]
    let mut net_config = sc_network::config::FullNetworkConfiguration::<
        Block,
        <Block as BlockT>::Hash,
        Network,
    >::new(&config.network);
    let metrics = Network::register_notification_metrics(
        config.prometheus_config.as_ref().map(|cfg| &cfg.registry),
    );

    #[cfg(not(feature = "manual-seal"))]
    let peer_store_handle = net_config.peer_store_handle();
    #[cfg(not(feature = "manual-seal"))]
    let grandpa_protocol_name = sc_consensus_grandpa::protocol_standard_name(
        &client
            .block_hash(0)
            .ok()
            .flatten()
            .expect("Genesis block exists; qed"),
        &config.chain_spec,
    );

    #[cfg(not(feature = "manual-seal"))]
    let (grandpa_protocol_config, grandpa_notification_service) =
        sc_consensus_grandpa::grandpa_peers_set_config::<_, Network>(
            grandpa_protocol_name.clone(),
            metrics.clone(),
            peer_store_handle,
        );

    #[cfg(not(feature = "manual-seal"))]
    net_config.add_notification_protocol(grandpa_protocol_config);

    #[cfg(not(feature = "manual-seal"))]
    let warp_sync = Arc::new(sc_consensus_grandpa::warp_proof::NetworkProvider::new(
        backend.clone(),
        grandpa_link.shared_authority_set().clone(),
        Vec::default(),
    ));

    let (network, system_rpc_tx, tx_handler_controller, network_starter, sync_service) =
        sc_service::build_network(sc_service::BuildNetworkParams {
            config: &config,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            spawn_handle: task_manager.spawn_handle(),
            import_queue,
            net_config,
            block_announce_validator_builder: None,
            #[cfg(not(feature = "manual-seal"))]
            warp_sync_params: Some(sc_service::WarpSyncParams::WithProvider(warp_sync)),
            #[cfg(feature = "manual-seal")]
            warp_sync_params: None,
            block_relay: None,
            metrics,
        })?;

    if config.offchain_worker.enabled {
        task_manager.spawn_handle().spawn(
            "offchain-workers-runner",
            "offchain-worker",
            sc_offchain::OffchainWorkers::new(sc_offchain::OffchainWorkerOptions {
                runtime_api_provider: client.clone(),
                is_validator: config.role.is_authority(),
                keystore: Some(keystore_container.keystore()),
                offchain_db: backend.offchain_storage(),
                transaction_pool: Some(OffchainTransactionPoolFactory::new(
                    transaction_pool.clone(),
                )),
                network_provider: Arc::new(network.clone()),
                enable_http_requests: true,
                custom_extensions: |_| vec![],
            })
            .run(client.clone(), task_manager.spawn_handle())
            .boxed(),
        );
    }
    let role = config.role.clone();
    let force_authoring = config.force_authoring;
    let name = config.network.node_name.clone();
    let enable_grandpa = !config.disable_grandpa;
    let prometheus_registry = config.prometheus_registry().cloned();

    let rpc_extensions_builder = {
        let client = client.clone();
        let pool = transaction_pool.clone();
        let justification_stream = grandpa_link.justification_stream();
        let shared_authority_set = grandpa_link.shared_authority_set().clone();
        let shared_voter_state = sc_consensus_grandpa::SharedVoterState::empty();

        let finality_proof_provider = sc_consensus_grandpa::FinalityProofProvider::new_for_service(
            backend.clone(),
            Some(shared_authority_set.clone()),
        );

        Box::new(
            move |deny_unsafe, subscription_task_executor: sc_rpc::SubscriptionTaskExecutor| {
                let deps = crate::rpc::FullDeps {
                    client: client.clone(),
                    pool: pool.clone(),
                    deny_unsafe,
                    grandpa: crate::rpc::GrandpaDeps {
                        shared_voter_state: shared_voter_state.clone(),
                        shared_authority_set: shared_authority_set.clone(),
                        justification_stream: justification_stream.clone(),
                        subscription_executor: subscription_task_executor.clone(),
                        finality_provider: finality_proof_provider.clone(),
                    },
                };
                crate::rpc::create_full(deps).map_err(Into::into)
            },
        )
    };

    let _rpc_handlers = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
        network: network.clone(),
        client: client.clone(),
        keystore: keystore_container.keystore(),
        task_manager: &mut task_manager,
        transaction_pool: transaction_pool.clone(),
        rpc_builder: rpc_extensions_builder,
        backend,
        system_rpc_tx,
        tx_handler_controller,
        sync_service: sync_service.clone(),
        config,
        telemetry: telemetry.as_mut(),
    })?;

    if let Some(hwbench) = hwbench {
        sc_sysinfo::print_hwbench(&hwbench);
        match crate::reference_hardware::REFERENCE_HARDWARE.check_hardware(&hwbench) {
            Err(err) if role.is_authority() => {
                frame::log::warn!(
				"⚠️  The hardware does not meet the minimal requirements {} for role 'Authority' find out more at:\n\
				https://wiki.polkadot.network/docs/maintain-guides-how-to-validate-polkadot#reference-hardware",
				err
			);
            }
            _ => {}
        }

        if let Some(ref mut telemetry) = telemetry {
            let telemetry_handle = telemetry.handle();
            task_manager.spawn_handle().spawn(
                "telemetry_hwbench",
                None,
                sc_sysinfo::initialize_hwbench_telemetry(telemetry_handle, hwbench),
            );
        }
    }

    // Manual Seal stuff
    #[cfg(feature = "manual-seal")]
    let proposer = sc_basic_authorship::ProposerFactory::new(
        task_manager.spawn_handle(),
        client.clone(),
        transaction_pool.clone(),
        prometheus_registry.as_ref(),
        telemetry.as_ref().map(|x| x.handle()),
    );

    #[cfg(feature = "manual-seal")]
    match consensus {
        Consensus::InstantSeal => {
            let params = sc_consensus_manual_seal::InstantSealParams {
                block_import: client.clone(),
                env: proposer,
                client,
                pool: transaction_pool,
                select_chain,
                consensus_data_provider: None,
                create_inherent_data_providers: move |_, ()| async move {
                    Ok(sp_timestamp::InherentDataProvider::from_system_time())
                },
            };

            let authorship_future = sc_consensus_manual_seal::run_instant_seal(params);

            task_manager.spawn_essential_handle().spawn_blocking(
                "instant-seal",
                None,
                authorship_future,
            );
        }
        Consensus::ManualSeal(block_time) => {
            let (mut sink, commands_stream) = futures::channel::mpsc::channel(1024);
            task_manager
                .spawn_handle()
                .spawn("block_authoring", None, async move {
                    loop {
                        futures_timer::Delay::new(std::time::Duration::from_millis(block_time))
                            .await;
                        sink.try_send(sc_consensus_manual_seal::EngineCommand::SealNewBlock {
                            create_empty: true,
                            finalize: true,
                            parent_hash: None,
                            sender: None,
                        })
                        .unwrap();
                    }
                });

            let params = sc_consensus_manual_seal::ManualSealParams {
                block_import: client.clone(),
                env: proposer,
                client,
                pool: transaction_pool,
                select_chain,
                commands_stream: Box::pin(commands_stream),
                consensus_data_provider: None,
                create_inherent_data_providers: move |_, ()| async move {
                    Ok(sp_timestamp::InherentDataProvider::from_system_time())
                },
            };
            let authorship_future = sc_consensus_manual_seal::run_manual_seal(params);

            task_manager.spawn_essential_handle().spawn_blocking(
                "manual-seal",
                None,
                authorship_future,
            );
        }
    }

    // Aura and Grandpa stuff
    #[cfg(not(feature = "manual-seal"))]
    if role.is_authority() {
        let proposer_factory = sc_basic_authorship::ProposerFactory::new(
            task_manager.spawn_handle(),
            client.clone(),
            transaction_pool.clone(),
            prometheus_registry.as_ref(),
            telemetry.as_ref().map(|x| x.handle()),
        );

        let backoff_authoring_blocks =
            Some(sc_consensus_slots::BackoffAuthoringOnFinalizedHeadLagging::default());

        let slot_duration = sc_consensus_aura::slot_duration(&*client)?;

        let aura = sc_consensus_aura::start_aura::<AuraPair, _, _, _, _, _, _, _, _, _, _>(
            sc_consensus_aura::StartAuraParams {
                slot_duration,
                client,
                select_chain,
                block_import,
                proposer_factory,
                create_inherent_data_providers: move |_, ()| async move {
                    let timestamp = sp_timestamp::InherentDataProvider::from_system_time();
                    let slot = sp_consensus_aura::inherents::InherentDataProvider::from_timestamp_and_slot_duration(*timestamp, slot_duration);
                    Ok((slot, timestamp))
                },
                force_authoring,
                backoff_authoring_blocks,
                keystore: keystore_container.keystore(),
                sync_oracle: sync_service.clone(),
                justification_sync_link: sync_service.clone(),
                block_proposal_slot_portion: sc_consensus_aura::SlotProportion::new(2f32 / 3f32),
                max_block_proposal_slot_portion: None,
                telemetry: telemetry.as_ref().map(|x| x.handle()),
                compatibility_mode: Default::default(),
            },
        )?;

        // the AURA authoring task is considered essential, i.e. if it
        // fails we take down the service with it.
        task_manager
            .spawn_essential_handle()
            .spawn_blocking("aura", Some("block-authoring"), aura);
    }

    #[cfg(not(feature = "manual-seal"))]
    if enable_grandpa {
        // if the node isn't actively participating in consensus then it doesn't
        // need a keystore, regardless of which protocol we use below.
        let keystore = if role.is_authority() {
            Some(keystore_container.keystore())
        } else {
            None
        };

        let grandpa_config = sc_consensus_grandpa::Config {
            // FIXME #1578 make this available through chainspec
            gossip_duration: core::time::Duration::from_millis(333),
            justification_generation_period: GRANDPA_JUSTIFICATION_PERIOD,
            name: Some(name),
            observer_enabled: false,
            keystore,
            local_role: role,
            telemetry: telemetry.as_ref().map(|x| x.handle()),
            protocol_name: grandpa_protocol_name,
        };

        // start the full GRANDPA voter
        // NOTE: non-authorities could run the GRANDPA observer protocol, but at
        // this point the full voter should provide better guarantees of block
        // and vote data availability than the observer. The observer has not
        // been tested extensively yet and having most nodes in a network run it
        // could lead to finality stalls.
        let grandpa_config = sc_consensus_grandpa::GrandpaParams {
            config: grandpa_config,
            link: grandpa_link,
            network,
            sync: Arc::new(sync_service),
            notification_service: grandpa_notification_service,
            voting_rule: sc_consensus_grandpa::VotingRulesBuilder::default().build(),
            prometheus_registry,
            shared_voter_state: sc_consensus_grandpa::SharedVoterState::empty(),
            telemetry: telemetry.as_ref().map(|x| x.handle()),
            offchain_tx_pool_factory: OffchainTransactionPoolFactory::new(transaction_pool),
        };

        // the GRANDPA voter task is considered infallible, i.e.
        // if it fails we take down the service with it.
        task_manager.spawn_essential_handle().spawn_blocking(
            "grandpa-voter",
            None,
            sc_consensus_grandpa::run_grandpa_voter(grandpa_config)?,
        );
    }

    network_starter.start_network();
    Ok(task_manager)
}
