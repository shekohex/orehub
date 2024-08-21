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

use orehub_runtime::{consts::currency::ORE, BalancesConfig, SudoConfig, WASM_BINARY};
use sc_service::{ChainType, Properties};
use serde_json::{json, Value};
use sp_keyring::AccountKeyring;

/// This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec;

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
    .with_genesis_config_patch(testnet_genesis())
    .with_properties(props())
    .build())
}

/// Configure initial storage state for FRAME pallets.
fn testnet_genesis() -> Value {
    let endowment = 1000 * ORE;
    let balances = AccountKeyring::iter()
        .map(|a| (a.to_account_id(), endowment))
        .collect::<Vec<_>>();
    json!({
        "balances": BalancesConfig { balances },
        "sudo": SudoConfig { key: Some(AccountKeyring::Alice.to_account_id()) },
    })
}
