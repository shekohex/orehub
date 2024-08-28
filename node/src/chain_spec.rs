use frame::deps::sp_core::{Pair, Public};
use orehub_runtime::{consts::currency::ORE, interface::AccountId, WASM_BINARY};
use sc_service::{ChainType, Properties};
use sp_consensus_aura::ed25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
use sp_keyring::ed25519::Keyring as AccountKeyring;

/// This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec;

/// Generate a crypto pair from seed.
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{}", seed), None)
        .expect("static values are valid; qed")
        .public()
}

/// Generate an Aura authority key.
pub fn authority_keys_from_seed(s: &str) -> (AuraId, GrandpaId) {
    (get_from_seed::<AuraId>(s), get_from_seed::<GrandpaId>(s))
}

fn props() -> Properties {
    let mut properties = Properties::new();
    properties.insert("tokenDecimals".to_string(), 11.into());
    properties.insert("tokenSymbol".to_string(), "ORE".into());
    properties.insert(
        "ss58Format".to_string(),
        orehub_runtime::consts::SS58_PREFIX.into(),
    );
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
    initial_authorities: Vec<(AuraId, GrandpaId)>,
    root_key: AccountId,
    endowed_accounts: Vec<AccountId>,
) -> serde_json::Value {
    let endowment = 1000 * ORE;
    serde_json::json!({
        "balances": {
            "balances": endowed_accounts.iter().cloned().map(|k| (k, endowment)).collect::<Vec<_>>(),
        },
        "aura": {
            "authorities": initial_authorities.iter().map(|x| (x.0.clone())).collect::<Vec<_>>(),
        },
        "grandpa": {
            "authorities": initial_authorities.iter().map(|x| (x.1.clone(), 1)).collect::<Vec<_>>(),
        },
        "sudo": {
            // Assign network admin rights.
            "key": Some(root_key),
        },
    })
}
