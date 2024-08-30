use frame::deps::sp_core::{Pair, Public};
use orehub_primitives::currency::ORE;
use orehub_runtime::interface::AccountId;
use orehub_runtime::interface::SS58Prefix;
use orehub_runtime::WASM_BINARY;
use pallet_im_online::ed25519::AuthorityId as ImOnlineId;
use sc_service::{ChainType, Properties};
use sp_consensus_babe::AuthorityId as BabeId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
use sp_keyring::ed25519::ed25519::Public as Ed25519Public;
use sp_keyring::ed25519::Keyring as AccountKeyring;

/// This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec;

/// Generate a crypto pair from seed.
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{}", seed), None)
        .expect("static values are valid; qed")
        .public()
}

pub struct SessionKeys {
    pub account: AccountId,
    pub babe: BabeId,
    pub grandpa: GrandpaId,
    pub im_online: ImOnlineId,
}

/// Generate an Aura authority key.
pub fn authority_keys_from_seed(s: &str) -> SessionKeys {
    SessionKeys {
        account: get_from_seed::<Ed25519Public>(s).into(),
        babe: get_from_seed::<BabeId>(s),
        grandpa: get_from_seed::<GrandpaId>(s),
        im_online: get_from_seed::<ImOnlineId>(s),
    }
}

fn props() -> Properties {
    let mut properties = Properties::new();
    properties.insert("tokenDecimals".to_string(), 11.into());
    properties.insert("tokenSymbol".to_string(), "ORE".into());
    properties.insert("ss58Format".to_string(), SS58Prefix::get().into());
    properties.insert("isEthereum".to_string(), false.into());
    properties
}

pub fn development_config() -> Result<ChainSpec, String> {
    Ok(ChainSpec::builder(
        WASM_BINARY.expect("Development wasm not available"),
        Default::default(),
    )
    .with_name("OreHub Development")
    .with_id("dev")
    .with_chain_type(ChainType::Development)
    .with_genesis_config_patch(testnet_genesis(
        // Initial PoA authorities
        vec![
            authority_keys_from_seed("Alice"),
            // authority_keys_from_seed("Bob"),
            // authority_keys_from_seed("Charlie"),
            // authority_keys_from_seed("Dave"),
            // authority_keys_from_seed("Eve"),
        ],
        // Sudo account
        AccountKeyring::Alice.to_account_id(),
        // Pre-funded accounts
        vec![
            AccountKeyring::Alice.to_account_id(),
            AccountKeyring::Bob.to_account_id(),
            AccountKeyring::Charlie.to_account_id(),
            AccountKeyring::Dave.to_account_id(),
            AccountKeyring::Eve.to_account_id(),
        ],
    ))
    .with_properties(props())
    .build())
}

pub fn local_testnet_config() -> Result<ChainSpec, String> {
    Ok(ChainSpec::builder(
        WASM_BINARY.expect("Development wasm not available"),
        Default::default(),
    )
    .with_name("OreHub Local Testnet")
    .with_id("local_testnet")
    .with_chain_type(ChainType::Local)
    .with_genesis_config_patch(testnet_genesis(
        // Initial PoA authorities
        vec![
            authority_keys_from_seed("Alice"),
            authority_keys_from_seed("Bob"),
            authority_keys_from_seed("Charlie"),
        ],
        // Sudo account
        AccountKeyring::Alice.to_account_id(),
        // Pre-funded accounts
        vec![
            AccountKeyring::Alice.to_account_id(),
            AccountKeyring::Bob.to_account_id(),
            AccountKeyring::Charlie.to_account_id(),
            AccountKeyring::Dave.to_account_id(),
            AccountKeyring::Eve.to_account_id(),
        ],
    ))
    .with_properties(props())
    .build())
}

/// Configure initial storage state for FRAME modules.
fn testnet_genesis(
    initial_authorities: Vec<SessionKeys>,
    root_key: AccountId,
    endowed_accounts: Vec<AccountId>,
) -> serde_json::Value {
    let endowment = 100 * ORE;
    serde_json::json!({
        "balances": {
            "balances": endowed_accounts.iter().cloned().map(|k| (k, endowment)).collect::<Vec<_>>(),
        },
        "session": {
            "keys": initial_authorities.iter().map(|x| (
                x.account.clone(),
                x.account.clone(),
                (x.babe.clone(), x.grandpa.clone(), x.im_online.clone()),
            )).collect::<Vec<_>>(),
        },
        "staking": {
            "validatorCount": initial_authorities.len(),
            "minimumValidatorCount": 1,
            "invulnerables": initial_authorities.iter().map(|x| x.account.clone()).collect::<Vec<_>>(),
            "slashRewardFraction": 0,
        },
        "babe": {
            "epochConfig": orehub_runtime::BABE_GENESIS_EPOCH_CONFIG,
        },
        "sudo": {
            // Assign network admin rights.
            "key": Some(root_key),
        },
    })
}
