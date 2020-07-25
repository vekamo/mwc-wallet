// Copyright 2019 The vault713 Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// Swap API trait
pub mod api;

/// Library that support bitcoin operations
pub mod bitcoin;

/// Swap crate errors
pub mod error;

/// Messages that Buyer and Seller are exchanging during the swap process
pub mod message;

/// schnorr signature routine
pub mod multisig;

/// Finite State Machine that handle swap workflow
pub mod fsm;

/// Swap buyer API (selling MWC for BTC)
pub mod buyer;
/// Swap Seller API (selling BTC for MWC)
pub mod seller;
/// Swap state object that is used by both byer abd seller
pub mod swap;
/// Swap trade sessions catalog
pub mod trades;

/// Serialization adapters
pub mod ser;

/// Types used by swap library
pub mod types;

pub use self::error::ErrorKind;
pub use self::swap::Swap;
pub use self::types::Context;
//pub use self::types::BtcSellerContext;

pub(crate) use self::api::SwapApi;
pub(crate) use self::buyer::BuyApi;
pub(crate) use self::seller::SellApi;

pub use grin_keychain::Keychain;

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(test)]
use serial_test::serial;

const CURRENT_VERSION: u8 = 1;

#[cfg(test)]
lazy_static! {
	/// Flag to set test mode
	static ref TEST_MODE: AtomicBool = AtomicBool::new(false);
}

#[cfg(test)]
/// Set the test mode
pub fn set_test_mode(mode: bool) {
	TEST_MODE.store(mode, Ordering::Relaxed);
}

#[cfg(test)]
/// Check if we are in test mode
pub fn is_test_mode() -> bool {
	TEST_MODE.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
	use crate::grin_util::{Mutex, RwLock};
	use crate::NodeClient;
	use bitcoin_lib::network::constants::Network as BtcNetwork;
	use bitcoin_lib::util::key::PublicKey as BtcPublicKey;
	use bitcoin_lib::{Address, Transaction as BtcTransaction, TxOut};
	use grin_core::core::transaction::Weighting;
	use grin_core::core::verifier_cache::LruVerifierCache;
	use grin_core::core::{Transaction, TxKernel};
	use grin_keychain::{ExtKeychain, Identifier, Keychain, SwitchCommitmentType};
	use grin_util::secp::key::{PublicKey, SecretKey};
	use grin_util::secp::pedersen::{Commitment, RangeProof};
	use grin_util::to_hex;
	use std::collections::HashMap;
	use std::fs::{read_to_string, write};
	use std::mem;
	use std::str::FromStr;
	use std::sync::Arc;

	use super::bitcoin::*;
	use super::message::Message;
	use super::types::*;
	use super::*;
	use crate::swap::fsm::machine::StateMachine;
	use crate::swap::fsm::state::{Input, StateId, StateProcessRespond};
	use crate::swap::message::{SecondaryUpdate, Update};
	use grin_core::global;
	use grin_core::global::ChainTypes;

	const GRIN_UNIT: u64 = 1_000_000_000;

	fn keychain(idx: u8) -> ExtKeychain {
		let seed_sell: String = format!("fixed0rng0for0testing0purposes0{}", idx % 10);
		let seed_sell = crate::blake2::blake2b::blake2b(32, &[], seed_sell.as_bytes());
		ExtKeychain::from_seed(seed_sell.as_bytes(), false).unwrap()
	}

	fn context_sell(kc: &ExtKeychain) -> Context {
		Context {
			multisig_key: key_id(0, 0),
			multisig_nonce: key(kc, 1, 0),
			lock_nonce: key(kc, 1, 1),
			refund_nonce: key(kc, 1, 2),
			redeem_nonce: key(kc, 1, 3),
			role_context: RoleContext::Seller(SellerContext {
				inputs: vec![
					(key_id(0, 1), None, 60 * GRIN_UNIT),
					(key_id(0, 2), None, 60 * GRIN_UNIT),
				],
				change_output: key_id(0, 3),
				change_amount: 20 * GRIN_UNIT, // selling 100 coins, so 20 will be left
				refund_output: key_id(0, 4),
				secondary_context: SecondarySellerContext::Btc(BtcSellerContext {
					cosign: key_id(0, 5),
				}),
			}),
		}
	}

	fn context_buy(kc: &ExtKeychain) -> Context {
		Context {
			multisig_key: key_id(0, 0),
			multisig_nonce: key(kc, 1, 0),
			lock_nonce: key(kc, 1, 1),
			refund_nonce: key(kc, 1, 2),
			redeem_nonce: key(kc, 1, 3),
			role_context: RoleContext::Buyer(BuyerContext {
				output: key_id(0, 1),
				redeem: key_id(0, 2),
				secondary_context: SecondaryBuyerContext::Btc(BtcBuyerContext {
					refund: key_id(0, 3),
				}),
			}),
		}
	}

	fn key_id(d1: u32, d2: u32) -> Identifier {
		ExtKeychain::derive_key_id(2, d1, d2, 0, 0)
	}

	fn key(kc: &ExtKeychain, d1: u32, d2: u32) -> SecretKey {
		kc.derive_key(0, &key_id(d1, d2), SwitchCommitmentType::None)
			.unwrap()
	}

	fn btc_address(kc: &ExtKeychain) -> String {
		let key = PublicKey::from_secret_key(kc.secp(), &key(kc, 2, 0)).unwrap();
		let address = Address::p2pkh(
			&BtcPublicKey {
				compressed: true,
				key,
			},
			BtcNetwork::Testnet,
		);
		format!("{}", address)
	}

	#[derive(Debug, Clone)]
	struct TestNodeClientState {
		pub height: u64,
		pub pending: Vec<Transaction>,
		pub outputs: HashMap<Commitment, u64>,
		pub kernels: HashMap<Commitment, (TxKernel, u64)>,
	}

	#[derive(Debug, Clone)]
	struct TestNodeClient {
		pub state: Arc<Mutex<TestNodeClientState>>,
	}

	impl TestNodeClient {
		pub fn new(height: u64) -> Self {
			let state = TestNodeClientState {
				height,
				pending: Vec::new(),
				outputs: HashMap::new(),
				kernels: HashMap::new(),
			};
			Self {
				state: Arc::new(Mutex::new(state)),
			}
		}

		pub fn push_output(&self, commit: Commitment) {
			let mut state = self.state.lock();
			let height = state.height;
			state.outputs.insert(commit, height);
		}

		pub fn mine_block(&self) {
			let mut state = self.state.lock();
			state.height += 1;
			let height = state.height;

			let pending = mem::replace(&mut state.pending, Vec::new());
			for tx in pending {
				for input in tx.body.inputs {
					state.outputs.remove(&input.commit);
				}
				for output in tx.body.outputs {
					state.outputs.insert(output.commit, height);
				}
				for kernel in tx.body.kernels {
					state
						.kernels
						.insert(kernel.excess.clone(), (kernel, height));
				}
			}
		}

		pub fn mine_blocks(&self, count: u64) {
			if count > 0 {
				self.mine_block();
				if count > 1 {
					let mut state = self.state.lock();
					state.height += count - 1;
				}
			}
		}
	}

	impl NodeClient for TestNodeClient {
		fn node_url(&self) -> &str {
			"test_node_url"
		}
		fn set_node_url(&mut self, _node_url: &str) {
			unimplemented!()
		}
		fn node_api_secret(&self) -> Option<String> {
			unimplemented!()
		}
		fn set_node_api_secret(&mut self, _node_api_secret: Option<String>) {
			unimplemented!()
		}
		fn get_chain_tip(&self) -> Result<(u64, String, u64), crate::Error> {
			let res = (self.state.lock().height, "testnodehash".to_string(), 123455);
			Ok(res)
		}
		fn get_header_info(&self, _height: u64) -> Result<crate::HeaderInfo, crate::Error> {
			unimplemented!()
		}
		fn get_connected_peer_info(
			&self,
		) -> Result<Vec<grin_p2p::types::PeerInfoDisplay>, crate::Error> {
			unimplemented!()
		}
		fn height_range_to_pmmr_indices(
			&self,
			_start_height: u64,
			_end_height: Option<u64>,
		) -> Result<(u64, u64), crate::Error> {
			unimplemented!()
		}
		fn get_blocks_by_height(
			&self,
			_start_height: u64,
			_end_height: u64,
			_threads_number: usize,
		) -> Result<Vec<grin_api::BlockPrintable>, crate::Error> {
			unimplemented!()
		}
		fn reset_cache(&self) {
			unimplemented!()
		}
		fn post_tx(&self, tx: &Transaction, _fluff: bool) -> Result<(), crate::Error> {
			tx.validate(
				Weighting::AsTransaction,
				Arc::new(RwLock::new(LruVerifierCache::new())),
			)
			.map_err(|e| crate::ErrorKind::Node(format!("Node failure, {}", e)))?;

			let mut state = self.state.lock();
			for input in tx.inputs() {
				// Output not unspent
				if !state.outputs.contains_key(&input.commit) {
					return Err(crate::ErrorKind::Node("Node failure".to_string()).into());
				}

				// Double spend attempt
				for tx_pending in state.pending.iter() {
					for in_pending in tx_pending.inputs() {
						if in_pending.commit == input.commit {
							return Err(crate::ErrorKind::Node("Node failure".to_string()).into());
						}
					}
				}
			}
			// Check for duplicate output
			for output in tx.outputs() {
				if state.outputs.contains_key(&output.commit) {
					return Err(crate::ErrorKind::Node("Node failure".to_string()).into());
				}

				for tx_pending in state.pending.iter() {
					for out_pending in tx_pending.outputs() {
						if out_pending.commit == output.commit {
							return Err(crate::ErrorKind::Node("Node failure".to_string()).into());
						}
					}
				}
			}
			// Check for duplicate kernel
			for kernel in tx.kernels() {
				// Duplicate kernel
				if state.kernels.contains_key(&kernel.excess) {
					return Err(crate::ErrorKind::Node("Node failure".to_string()).into());
				}

				for tx_pending in state.pending.iter() {
					for kernel_pending in tx_pending.kernels() {
						if kernel_pending.excess == kernel.excess {
							return Err(crate::ErrorKind::Node("Node failure".to_string()).into());
						}
					}
				}
			}
			state.pending.push(tx.clone());

			Ok(())
		}
		fn get_version_info(&mut self) -> Option<crate::NodeVersionInfo> {
			unimplemented!()
		}
		fn get_outputs_from_node(
			&self,
			wallet_outputs: &Vec<Commitment>,
		) -> Result<HashMap<Commitment, (String, u64, u64)>, crate::Error> {
			let mut map = HashMap::new();
			let state = self.state.lock();
			for output in wallet_outputs {
				if let Some(height) = state.outputs.get(&output) {
					map.insert(output.clone(), (to_hex(output.0.to_vec()), *height, 0));
				}
			}
			Ok(map)
		}
		fn get_outputs_by_pmmr_index(
			&self,
			_start_height: u64,
			_end_height: Option<u64>,
			_max_outputs: u64,
		) -> Result<(u64, u64, Vec<(Commitment, RangeProof, bool, u64, u64)>), crate::Error> {
			unimplemented!()
		}
		fn get_kernel(
			&self,
			excess: &Commitment,
			_min_height: Option<u64>,
			_max_height: Option<u64>,
		) -> Result<Option<(TxKernel, u64, u64)>, crate::Error> {
			let state = self.state.lock();
			let res = state
				.kernels
				.get(excess)
				.map(|(kernel, height)| (kernel.clone(), *height, 0));
			Ok(res)
		}
	}

	#[test]
	#[serial]
	fn test_refund_tx_lock() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);

		let kc_sell = keychain(1);
		let ctx_sell = context_sell(&kc_sell);
		let secondary_redeem_address = btc_address(&kc_sell);
		let height = 100_000;

		let mut api_sell = BtcSwapApi::new(
			Arc::new(TestNodeClient::new(height)),
			Arc::new(Mutex::new(TestBtcNodeClient::new(1))),
		);
		let mut swap = api_sell
			.create_swap_offer(
				&kc_sell,
				&ctx_sell,
				100 * GRIN_UNIT,
				3_000_000,
				Currency::Btc,
				secondary_redeem_address,
				true, // mwc should be publisher first
				30,
				3,
				3600,
				3600,
			)
			.unwrap();
		let mut fsm_sell = api_sell.get_fsm(&kc_sell, &swap);
		let tx_state = api_sell
			.request_tx_confirmations(&kc_sell, &mut swap)
			.unwrap();

		let message = match fsm_sell
			.process(Input::Check, &mut swap, &ctx_sell, &tx_state)
			.unwrap()
			.action
			.unwrap()
		{
			Action::SellerSendOfferMessage(message) => message,
			_ => panic!("Unexpected action"),
		};

		// Simulate short refund lock time by passing height+4h
		let kc_buy = keychain(2);
		let ctx_buy = context_buy(&kc_buy);
		let nc = TestNodeClient::new(height + 12 * 60);

		let (id, offer, secondary_update) = message.unwrap_offer().unwrap();
		let res = BuyApi::accept_swap_offer(&kc_buy, &ctx_buy, id, offer, secondary_update, &nc);

		assert_eq!(
			res.err().unwrap(),
			ErrorKind::InvalidMessageData(
				"Lock Slate inputs are not found at the chain".to_string()
			)
		); // Swap cannot be accepted
	}

	#[test]
	#[serial]
	fn test_btc_swap() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_mining_mode(ChainTypes::Floonet);
		let write_json = false;

		let kc_sell = keychain(1);
		let ctx_sell = context_sell(&kc_sell);
		let secondary_redeem_address = btc_address(&kc_sell);

		let nc = TestNodeClient::new(300_000);
		let btc_nc = TestBtcNodeClient::new(500_000);

		let amount = 100 * GRIN_UNIT;
		let btc_amount_1 = 2_000_000;
		let btc_amount_2 = 1_000_000;
		let btc_amount = btc_amount_1 + btc_amount_2;

		// When test was stored:  Utc.ymd(2019, 9, 4).and_hms_micro(21, 22, 32, 581245)

		// Seller: create swap offer
		let mut api_sell =
			BtcSwapApi::new(Arc::new(nc.clone()), Arc::new(Mutex::new(btc_nc.clone())));
		let mut swap_sell = api_sell
			.create_swap_offer(
				&kc_sell,
				&ctx_sell,
				amount,
				btc_amount,
				Currency::Btc,
				secondary_redeem_address,
				true, // lock MWC first
				30,
				6,
				3600,
				3600,
			)
			.unwrap();

		let mut fsm_sell = api_sell.get_fsm(&kc_sell, &swap_sell);
		let tx_conf = &api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Check, &mut swap_sell, &ctx_sell, tx_conf)
			.unwrap();

		assert_eq!(swap_sell.state, StateId::SellerSendingOffer);
		let message_1: Message = match sell_resp.action.unwrap() {
			Action::SellerSendOfferMessage(message) => message,
			_ => panic!("Unexpected action"),
		};
		let tx_conf = api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::execute(), &mut swap_sell, &ctx_sell, &tx_conf)
			.unwrap();
		assert_eq!(
			sell_resp.action.unwrap().get_id_str(),
			"SellerWaitForOfferMessage"
		);
		assert_eq!(swap_sell.state, StateId::SellerWaitingForAcceptanceMessage);

		if write_json {
			write(
				"swap_test/swap_sell_1.json",
				serde_json::to_string_pretty(&swap_sell).unwrap(),
			)
			.unwrap();

			write(
				"swap_test/message_1.json",
				serde_json::to_string_pretty(&message_1).unwrap(),
			)
			.unwrap();
			write(
				"swap_test/context_sell.json",
				serde_json::to_string_pretty(&ctx_sell).unwrap(),
			)
			.unwrap();
		} else {
			assert_eq!(
				read_to_string("swap_test/swap_sell_1.json").unwrap(),
				serde_json::to_string_pretty(&swap_sell).unwrap()
			);
			assert_eq!(
				read_to_string("swap_test/message_1.json").unwrap(),
				serde_json::to_string_pretty(&message_1).unwrap()
			);
			assert_eq!(
				read_to_string("swap_test/context_sell.json").unwrap(),
				serde_json::to_string_pretty(&ctx_sell).unwrap()
			);
		}

		// Add inputs to utxo set
		nc.mine_blocks(2);
		for input in swap_sell.lock_slate.tx.inputs() {
			nc.push_output(input.commit.clone());
		}

		let kc_buy = keychain(2);
		let ctx_buy = context_buy(&kc_buy);

		// Buyer: accept swap offer
		let api_buy = BtcSwapApi::new(Arc::new(nc.clone()), Arc::new(Mutex::new(btc_nc.clone())));

		let (id, offer, secondary_update) = message_1.unwrap_offer().unwrap();
		let mut swap_buy =
			BuyApi::accept_swap_offer(&kc_buy, &ctx_buy, id, offer, secondary_update, &nc).unwrap();

		let mut fsm_buy = api_buy.get_fsm(&kc_buy, &swap_buy);
		let tx_conf = api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
			.unwrap();

		assert_eq!(swap_buy.state, StateId::BuyerSendingAcceptOfferMessage);
		let message_2 = match buy_resp.action.unwrap() {
			Action::BuyerSendAcceptOfferMessage(message) => message,
			_ => panic!("Unexpected action"),
		};
		let tx_conf = api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::execute(), &mut swap_buy, &ctx_buy, &tx_conf)
			.unwrap();
		assert_eq!(swap_buy.state, StateId::BuyerWaitingForSellerToLock);

		// Expected to wait for the Seller to deposit MWC and wait for 1 block
		match buy_resp.action.unwrap() {
			Action::WaitForMwcConfirmations {
				name: _,
				required,
				actual,
			} => {
				assert_eq!(required, 1);
				assert_eq!(actual, 0);
			}
			_ => panic!("Invalid action"),
		}

		// !!!!!!!!!!!!!!!!!!!!!!
		// Here we are changing lock order because we want to keep tests original. Waiting case is covered, can go normally
		swap_buy.seller_lock_first = false;
		swap_sell.seller_lock_first = true;
		let tx_conf = api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
			.unwrap();

		assert_eq!(
			swap_buy.state,
			StateId::BuyerPostingSecondaryToMultisigAccount
		);

		// Buyer: should deposit bitcoin
		let address = match buy_resp.action.unwrap() {
			Action::DepositSecondary {
				currency: _,
				amount,
				address,
			} => {
				assert_eq!(amount, btc_amount);
				address
			}
			_ => panic!("Invalid action"),
		};
		let address = Address::from_str(&address).unwrap();

		// Buyer: first deposit
		let tx_1 = BtcTransaction {
			version: 2,
			lock_time: 0,
			input: vec![],
			output: vec![TxOut {
				value: btc_amount_1,
				script_pubkey: address.script_pubkey(),
			}],
		};
		let txid_1 = tx_1.txid();
		btc_nc.push_transaction(&tx_1);
		let tx_conf = api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
			.unwrap();
		assert_eq!(
			swap_buy.state,
			StateId::BuyerPostingSecondaryToMultisigAccount
		);
		match buy_resp.action.unwrap() {
			Action::DepositSecondary {
				currency: _,
				amount,
				address: _,
			} => assert_eq!(amount, btc_amount_2),
			_ => panic!("Invalid action"),
		};

		// Buyer: second deposit
		btc_nc.mine_blocks(2);
		let tx_2 = BtcTransaction {
			version: 2,
			lock_time: 0,
			input: vec![],
			output: vec![TxOut {
				value: btc_amount_2,
				script_pubkey: address.script_pubkey(),
			}],
		};
		let txid_2 = tx_2.txid();
		btc_nc.push_transaction(&tx_2);
		let tx_conf = api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
			.unwrap();
		assert_eq!(swap_buy.state, StateId::BuyerWaitingForLockConfirmations);

		match buy_resp.action.unwrap() {
			Action::WaitForSecondaryConfirmations {
				name: _,
				currency: _,
				required: _,
				actual,
			} => assert_eq!(actual, 1),
			_ => panic!("Invalid action"),
		};
		btc_nc.mine_blocks(5);

		// Buyer: wait for Grin confirmations
		let tx_conf = api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
			.unwrap();
		assert_eq!(swap_buy.state, StateId::BuyerWaitingForLockConfirmations);
		match buy_resp.action.unwrap() {
			Action::WaitForMwcConfirmations {
				name: _,
				required: _,
				actual,
			} => assert_eq!(actual, 0),
			_ => panic!("Invalid action"),
		};

		// Check if buyer has correct confirmed outputs
		{
			let script = api_buy.script(&swap_buy).unwrap();
			let (pending_amount, confirmed_amount, _, conf_outputs) =
				api_buy.btc_balance(&swap_buy, &script, 1).unwrap();

			assert_eq!(pending_amount, 0);
			assert_eq!(confirmed_amount, btc_amount_1 + btc_amount_2);
			assert_eq!(conf_outputs.len(), 2);
			let mut match_1 = 0;
			let mut match_2 = 0;
			for output in &conf_outputs {
				if output.out_point.txid == txid_1 {
					match_1 += 1;
				}
				if output.out_point.txid == txid_2 {
					match_2 += 1;
				}
			}
			assert_eq!(match_1, 1);
			assert_eq!(match_2, 1);
		}

		if write_json {
			write(
				"swap_test/swap_buy_1.json",
				serde_json::to_string_pretty(&swap_buy).unwrap(),
			)
			.unwrap();
			write(
				"swap_test/message_2.json",
				serde_json::to_string_pretty(&message_2).unwrap(),
			)
			.unwrap();
			write(
				"swap_test/context_buy.json",
				serde_json::to_string_pretty(&ctx_buy).unwrap(),
			)
			.unwrap();
		} else {
			assert_eq!(
				read_to_string("swap_test/swap_buy_1.json").unwrap(),
				serde_json::to_string_pretty(&swap_buy).unwrap()
			);
			assert_eq!(
				read_to_string("swap_test/message_2.json").unwrap(),
				serde_json::to_string_pretty(&message_2).unwrap()
			);
			assert_eq!(
				read_to_string("swap_test/context_buy.json").unwrap(),
				serde_json::to_string_pretty(&ctx_buy).unwrap()
			);
		}

		// Seller: receive accepted offer
		assert_eq!(swap_sell.state, StateId::SellerWaitingForAcceptanceMessage);
		let tx_conf = api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(
				Input::IncomeMessage(message_2),
				&mut swap_sell,
				&ctx_sell,
				&tx_conf,
			)
			.unwrap();
		assert_eq!(
			sell_resp.action.unwrap().get_id_str(),
			"SellerPublishMwcLockTx"
		);
		assert_eq!(swap_sell.state, StateId::SellerPostingLockMwcSlate);

		let tx_conf = api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::execute(), &mut swap_sell, &ctx_sell, &tx_conf)
			.unwrap();
		assert_eq!(swap_sell.state, StateId::SellerWaitingForLockConfirmations);
		match sell_resp.action.unwrap() {
			Action::WaitForMwcConfirmations {
				name: _,
				required,
				actual,
			} => {
				assert_eq!(required, 30);
				assert_eq!(actual, 0)
			}
			_ => panic!("Invalid action"),
		}

		if write_json {
			write(
				"swap_test/swap_sell_2.json",
				serde_json::to_string_pretty(&swap_sell).unwrap(),
			)
			.unwrap();
		} else {
			assert_eq!(
				read_to_string("swap_test/swap_sell_2.json").unwrap(),
				serde_json::to_string_pretty(&swap_sell).unwrap()
			);
		}

		// Seller: wait for Grin confirmations
		nc.mine_blocks(10);
		let tx_conf = api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf)
			.unwrap();
		assert_eq!(swap_sell.state, StateId::SellerWaitingForLockConfirmations);
		match sell_resp.action.unwrap() {
			Action::WaitForMwcConfirmations {
				name: _,
				required,
				actual,
			} => {
				assert_eq!(required, 30);
				assert_eq!(actual, 10)
			}
			_ => panic!("Invalid action"),
		}
		let tx_conf = api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
			.unwrap();
		assert_eq!(swap_buy.state, StateId::BuyerWaitingForLockConfirmations);
		match buy_resp.action.unwrap() {
			Action::WaitForMwcConfirmations {
				name: _,
				required,
				actual,
			} => {
				assert_eq!(required, 30);
				assert_eq!(actual, 10)
			}
			_ => panic!("Invalid action"),
		}

		// Undo a BTC block to test seller
		{
			let mut state = btc_nc.state.lock();
			state.height -= 1;
		}

		// Seller: wait BTC confirmations
		nc.mine_blocks(20);
		let tx_conf = api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf)
			.unwrap();
		assert_eq!(swap_sell.state, StateId::SellerWaitingForLockConfirmations);
		match sell_resp.action.unwrap() {
			Action::WaitForSecondaryConfirmations {
				name: _,
				currency: _,
				required,
				actual,
			} => {
				assert_eq!(required, 6);
				assert_eq!(actual, 5)
			}
			_ => panic!("Invalid action"),
		}
		btc_nc.mine_block();

		if write_json {
			write(
				"swap_test/swap_sell_3.json",
				serde_json::to_string_pretty(&swap_sell).unwrap(),
			)
			.unwrap();
		} else {
			assert_eq!(
				read_to_string("swap_test/swap_sell_3.json").unwrap(),
				serde_json::to_string_pretty(&swap_sell).unwrap()
			);
		}

		// Checking if both seller & Buyer are moved to the redeem message exchange step
		let tx_conf = api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf)
			.unwrap();
		let tx_conf = api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
			.unwrap();

		assert_eq!(swap_sell.state, StateId::SellerWaitingForInitRedeemMessage);
		assert_eq!(swap_buy.state, StateId::BuyerSendingInitRedeemMessage);
		assert_eq!(
			sell_resp.action.unwrap().get_id_str(),
			"SellerWaitingForInitRedeemMessage"
		);
		let message_3 = match buy_resp.action.unwrap() {
			Action::BuyerSendInitRedeemMessage(message) => message,
			_ => panic!("Unexpected action"),
		};
		let tx_conf = api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		fsm_buy
			.process(Input::execute(), &mut swap_buy, &ctx_buy, &tx_conf)
			.unwrap();
		assert_eq!(swap_buy.state, StateId::BuyerWaitingForRespondRedeemMessage);

		if write_json {
			write(
				"swap_test/swap_buy_2.json",
				serde_json::to_string_pretty(&swap_buy).unwrap(),
			)
			.unwrap();
			write(
				"swap_test/message_3.json",
				serde_json::to_string_pretty(&message_3).unwrap(),
			)
			.unwrap();
		} else {
			assert_eq!(
				read_to_string("swap_test/swap_buy_2.json").unwrap(),
				serde_json::to_string_pretty(&swap_buy).unwrap()
			);
			assert_eq!(
				read_to_string("swap_test/message_3.json").unwrap(),
				serde_json::to_string_pretty(&message_3).unwrap()
			);
		}

		// Seller: sign redeem
		let tx_conf = api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf)
			.unwrap();
		assert_eq!(swap_sell.state, StateId::SellerWaitingForInitRedeemMessage);
		assert_eq!(
			sell_resp.action.unwrap().get_id_str(),
			"SellerWaitingForInitRedeemMessage"
		);

		let tx_conf = api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(
				Input::IncomeMessage(message_3),
				&mut swap_sell,
				&ctx_sell,
				&tx_conf,
			)
			.unwrap();
		assert_eq!(swap_sell.state, StateId::SellerSendingInitRedeemMessage);
		let message_4 = match sell_resp.action.unwrap() {
			Action::SellerSendRedeemMessage(message) => message,
			_ => panic!("Unexpected action"),
		};

		let tx_conf = api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::execute(), &mut swap_sell, &ctx_sell, &tx_conf)
			.unwrap();
		// Seller: wait for buyer's on-chain redeem tx
		assert_eq!(swap_sell.state, StateId::SellerWaitingForBuyerToRedeemMwc);
		assert_eq!(
			sell_resp.action.unwrap().get_id_str(),
			"SellerWaitForBuyerRedeemPublish"
		);

		if write_json {
			write(
				"swap_test/swap_sell_4.json",
				serde_json::to_string_pretty(&swap_sell).unwrap(),
			)
			.unwrap();
			write(
				"swap_test/message_4.json",
				serde_json::to_string_pretty(&message_4).unwrap(),
			)
			.unwrap();
		} else {
			assert_eq!(
				read_to_string("swap_test/swap_sell_4.json").unwrap(),
				serde_json::to_string_pretty(&swap_sell).unwrap()
			);
			assert_eq!(
				read_to_string("swap_test/message_4.json").unwrap(),
				serde_json::to_string_pretty(&message_4).unwrap()
			);
		}

		// Buyer: redeem
		let tx_conf = api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
			.unwrap();
		assert_eq!(swap_buy.state, StateId::BuyerWaitingForRespondRedeemMessage);
		assert_eq!(
			buy_resp.action.unwrap().get_id_str(),
			"BuyerWaitingForRedeemMessage"
		);

		let tx_conf = api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(
				Input::IncomeMessage(message_4),
				&mut swap_buy,
				&ctx_buy,
				&tx_conf,
			)
			.unwrap();
		assert_eq!(swap_buy.state, StateId::BuyerRedeemMwc);
		assert_eq!(
			buy_resp.action.unwrap().get_id_str(),
			"BuyerPublishMwcRedeemTx"
		);

		let tx_conf = &api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::execute(), &mut swap_buy, &ctx_buy, &tx_conf)
			.unwrap();
		assert_eq!(swap_buy.state, StateId::BuyerWaitForRedeemMwcConfirmations);
		assert_eq!(
			buy_resp.action.unwrap().get_id_str(),
			"WaitForMwcConfirmations"
		);

		// Buyer: almost done, just need to wait for confirmations
		nc.mine_block();

		let tx_conf = api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
			.unwrap();
		assert_eq!(swap_buy.state, StateId::BuyerWaitForRedeemMwcConfirmations);
		match buy_resp.action.unwrap() {
			Action::WaitForMwcConfirmations {
				name: _,
				required,
				actual,
			} => {
				assert_eq!(actual, 1);
				assert_eq!(required, 30);
			}
			_ => panic!("Invalid action"),
		}

		// At this point, buyer would add Grin to their outputs
		// Now seller can redeem BTC
		if write_json {
			write(
				"swap_test/swap_buy_3.json",
				serde_json::to_string_pretty(&swap_buy).unwrap(),
			)
			.unwrap();
		} else {
			assert_eq!(
				read_to_string("swap_test/swap_buy_3.json").unwrap(),
				serde_json::to_string_pretty(&swap_buy).unwrap()
			);
		}

		// Seller: publish BTC tx
		let tx_conf = api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf)
			.unwrap();
		assert_eq!(swap_sell.state, StateId::SellerRedeemSecondaryCurrency);
		assert_eq!(
			sell_resp.action.unwrap().get_id_str(),
			"SellerPublishTxSecondaryRedeem"
		);

		if write_json {
			write(
				"swap_test/swap_sell_5.json",
				serde_json::to_string_pretty(&swap_sell).unwrap(),
			)
			.unwrap();
		} else {
			assert_eq!(
				read_to_string("swap_test/swap_sell_5.json").unwrap(),
				serde_json::to_string_pretty(&swap_sell).unwrap()
			);
		}

		// Seller: publishing and wait for BTC confirmations
		let tx_conf = api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::execute(), &mut swap_sell, &ctx_sell, &tx_conf)
			.unwrap();
		assert_eq!(
			swap_sell.state,
			StateId::SellerWaitingForRedeemConfirmations
		);
		match sell_resp.action.unwrap() {
			Action::WaitForSecondaryConfirmations {
				name: _,
				currency: _,
				required,
				actual,
			} => {
				assert_eq!(required, 6);
				assert_eq!(actual, 0)
			}
			_ => panic!("Invalid action"),
		}

		btc_nc.mine_block();
		// still waiting
		let tx_conf = api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf)
			.unwrap();
		assert_eq!(
			swap_sell.state,
			StateId::SellerWaitingForRedeemConfirmations
		);
		match sell_resp.action.unwrap() {
			Action::WaitForSecondaryConfirmations {
				name: _,
				currency: _,
				required,
				actual,
			} => {
				assert_eq!(required, 6);
				assert_eq!(actual, 1)
			}
			_ => panic!("Invalid action"),
		}

		// Let's mine more blocks, so both Buyer and Seller will come to complete state
		nc.mine_blocks(30);
		btc_nc.mine_blocks(6);

		let tx_conf = api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf)
			.unwrap();
		let tx_conf = &api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
			.unwrap();

		// Seller & Buyer: complete!
		assert_eq!(swap_sell.state, StateId::SellerSwapComplete);
		assert_eq!(swap_buy.state, StateId::BuyerSwapComplete);
		assert!(sell_resp.action.is_none());
		assert!(buy_resp.action.is_none());

		if write_json {
			write(
				"swap_test/swap_sell_6.json",
				serde_json::to_string_pretty(&swap_sell).unwrap(),
			)
			.unwrap();
		} else {
			assert_eq!(
				read_to_string("swap_test/swap_sell_6.json").unwrap(),
				serde_json::to_string_pretty(&swap_sell).unwrap()
			);
		}

		assert!(!write_json, "json files written");
	}

	#[test]
	#[serial]
	fn test_swap_serde() {
		// Seller context
		let ctx_sell_str = read_to_string("swap_test/context_sell.json").unwrap();
		let ctx_sell: Context = serde_json::from_str(&ctx_sell_str).unwrap();
		assert_eq!(
			serde_json::to_string_pretty(&ctx_sell).unwrap(),
			ctx_sell_str
		);

		// Buyer context
		let ctx_buy_str = read_to_string("swap_test/context_buy.json").unwrap();
		let ctx_buy: Context = serde_json::from_str(&ctx_buy_str).unwrap();
		assert_eq!(serde_json::to_string_pretty(&ctx_buy).unwrap(), ctx_buy_str);

		// Seller's swap state in different stages
		for i in 0..6 {
			println!("TRY SELL {}", i);
			let swap_str = read_to_string(format!("swap_test/swap_sell_{}.json", i + 1)).unwrap();
			let swap: Swap = serde_json::from_str(&swap_str).unwrap();
			assert_eq!(serde_json::to_string_pretty(&swap).unwrap(), swap_str);
			println!("OK SELL {}", i);
		}

		// Buyer's swap state in different stages
		for i in 0..3 {
			println!("TRY BUY {}", i);
			let swap_str = read_to_string(format!("swap_test/swap_buy_{}.json", i + 1)).unwrap();
			let swap: Swap = serde_json::from_str(&swap_str).unwrap();
			assert_eq!(serde_json::to_string_pretty(&swap).unwrap(), swap_str);
			println!("OK BUY {}", i);
		}

		// Messages
		for i in 0..4 {
			println!("TRY MSG {}", i);
			let message_str = read_to_string(format!("swap_test/message_{}.json", i + 1)).unwrap();
			let message: Message = serde_json::from_str(&message_str).unwrap();
			assert_eq!(serde_json::to_string_pretty(&message).unwrap(), message_str);
			println!("OK MSG {}", i);
		}
	}

	// test_swap_fsm timimg config. Constans will be used to validate the timing limits.
	const START_TIME: i64 = 1568000000;
	const MWC_CONFIRMATION: u64 = 30;
	const BTC_CONFIRMATION: u64 = 6;
	const MSG_EXCHANGE_TIME: i64 = 3600;
	const REDEEM_TIME: i64 = 3600;

	pub struct Trader<'a> {
		api: &'a BtcSwapApi<'a, TestNodeClient, TestBtcNodeClient>,
		pub swap: Swap,
		fsm: StateMachine<'a>,
		pub kc: ExtKeychain,
		ctx: Context,
		swap_stack: Vec<Swap>,
	}

	impl<'a> Trader<'a> {
		pub fn process(&mut self, input: Input) -> Result<StateProcessRespond, ErrorKind> {
			let tx_conf = self.api.request_tx_confirmations(&self.kc, &self.swap)?;
			self.fsm.process(input, &mut self.swap, &self.ctx, &tx_conf)
		}

		pub fn is_cancellable(&self) -> bool {
			self.fsm.is_cancellable(&self.swap).unwrap()
		}

		pub fn pushs(&mut self) {
			self.swap_stack.push(self.swap.clone());
		}
		pub fn pops(&mut self) {
			self.swap = self.swap_stack.pop().unwrap();
		}
	}

	// Test all possible responds (covereage for all inputs and with timeouts )
	fn test_responds(
		trader: &mut Trader,
		expected_starting_state: StateId,
		timeout: Option<i64>, // timeout if possible
		cancel_expected_state: Option<StateId>,
		check_before_expected_state: StateId, // Expected state before timeput
		check_after_expected_state: StateId,  // Expected state after timeout
		execute_before_expected_state: Option<StateId>, // Expected state before timeput
		execute_after_expected_state: Option<StateId>, // Expected state after timeout
		message: Option<Message>,             // Acceptable message
		message_before_expected_state: Option<StateId>,
		message_after_expected_state: Option<StateId>,
	) {
		// Checking the timeout
		assert_eq!(trader.swap.state, expected_starting_state);

		let (time2pass, time2fail) = match timeout {
			Some(t) => (
				vec![START_TIME, (START_TIME + t) / 2, t - 1],
				vec![
					t + 1,
					t + MSG_EXCHANGE_TIME / 2,
					t + MSG_EXCHANGE_TIME,
					START_TIME + 100000000000,
				],
			),
			None => (
				vec![
					START_TIME,
					START_TIME + MSG_EXCHANGE_TIME,
					START_TIME + 100000000000,
				],
				vec![],
			),
		};
		let mut time_all = time2pass.clone();
		time_all.extend(time2fail.iter().copied());

		let start_time = swap::get_cur_time();

		// Checking what Cancel does
		for t in &time_all {
			trader.pushs();
			swap::set_testing_cur_time(*t);

			if cancel_expected_state.is_some() {
				let _sr = trader.process(Input::Cancel).unwrap();
				assert_eq!(trader.swap.state, cancel_expected_state.clone().unwrap());
			} else {
				assert_eq!(trader.is_cancellable(), false);
				let sr = trader.process(Input::Cancel);
				assert!(sr.is_err(), true);
			}
			trader.pops();
		}

		// Check Inputs
		for t in &time2pass {
			trader.pushs();
			swap::set_testing_cur_time(*t);
			let _sr = trader.process(Input::Check).unwrap();
			assert_eq!(trader.swap.state, check_before_expected_state);
			trader.pops();
		}
		for t in &time2fail {
			trader.pushs();
			swap::set_testing_cur_time(*t);
			let _sr = trader.process(Input::Check).unwrap();
			assert_eq!(trader.swap.state, check_after_expected_state);
			trader.pops();
		}

		// Execute
		for t in &time2pass {
			trader.pushs();
			swap::set_testing_cur_time(*t);
			if execute_before_expected_state.is_some() {
				let _sr = trader
					.process(Input::Execute {
						refund_address: Some("mjdcskZm4Kimq7yzUGLtzwiEwMdBdTa3No".to_string()),
						fee_satoshi_per_byte: Some(26.0),
					})
					.unwrap();
				assert_eq!(
					trader.swap.state,
					execute_before_expected_state.clone().unwrap()
				);
			} else {
				let sr = trader.process(Input::Execute {
					refund_address: Some("mjdcskZm4Kimq7yzUGLtzwiEwMdBdTa3No".to_string()),
					fee_satoshi_per_byte: Some(26.0),
				});
				assert_eq!(sr.is_err(), true);
			}
			trader.pops();
		}
		for t in &time2fail {
			trader.pushs();
			swap::set_testing_cur_time(*t);
			if execute_after_expected_state.is_some() {
				let _sr = trader
					.process(Input::Execute {
						refund_address: Some("mjdcskZm4Kimq7yzUGLtzwiEwMdBdTa3No".to_string()),
						fee_satoshi_per_byte: Some(26.0),
					})
					.unwrap();
				assert_eq!(
					trader.swap.state,
					execute_after_expected_state.clone().unwrap()
				);
			} else {
				let sr = trader.process(Input::Execute {
					refund_address: Some("mjdcskZm4Kimq7yzUGLtzwiEwMdBdTa3No".to_string()),
					fee_satoshi_per_byte: Some(26.0),
				});
				assert_eq!(sr.is_err(), true);
			}
			trader.pops();
		}

		// IncomeMessage
		for t in &time2pass {
			trader.pushs();
			swap::set_testing_cur_time(*t);
			let message = Input::IncomeMessage(message.clone().unwrap_or(Message::new(
				trader.swap.id.clone(),
				Update::None,
				SecondaryUpdate::Empty,
			)));
			if message_before_expected_state.is_some() {
				let _sr = trader.process(message).unwrap();
				assert_eq!(
					trader.swap.state,
					message_before_expected_state.clone().unwrap()
				);
			} else {
				let sr = trader.process(message);
				assert_eq!(sr.is_err(), true);
			}
			trader.pops();
		}
		for t in &time2fail {
			trader.pushs();
			swap::set_testing_cur_time(*t);
			let message = Input::IncomeMessage(message.clone().unwrap_or(Message::new(
				trader.swap.id.clone(),
				Update::None,
				SecondaryUpdate::Empty,
			)));
			if message_after_expected_state.is_some() {
				let _sr = trader.process(message).unwrap();
				assert_eq!(
					trader.swap.state,
					message_after_expected_state.clone().unwrap()
				);
			} else {
				let sr = trader.process(message);
				assert_eq!(sr.is_err(), true);
			}
			trader.pops();
		}

		// Restorign original time
		swap::set_testing_cur_time(start_time);
	}

	#[test]
	#[serial]
	// The primary goal for this test is to cover all code path for edge cases
	fn test_swap_fsm() {
		set_test_mode(true);
		swap::set_testing_cur_time(START_TIME);
		global::set_mining_mode(ChainTypes::Floonet);

		let nc = TestNodeClient::new(300_000);
		let btc_nc = TestBtcNodeClient::new(500_000);

		let amount = 100 * GRIN_UNIT;
		let btc_amount_1 = 2_000_000;
		let btc_amount_2 = 1_000_000;
		let btc_amount = btc_amount_1 + btc_amount_2;

		let mut api_sell =
			BtcSwapApi::new(Arc::new(nc.clone()), Arc::new(Mutex::new(btc_nc.clone())));
		let kc_sell = keychain(1);
		let ctx_sell = context_sell(&kc_sell);
		let secondary_redeem_address = btc_address(&kc_sell);

		let swap_sell = api_sell
			.create_swap_offer(
				&kc_sell,
				&ctx_sell,
				amount,
				btc_amount,
				Currency::Btc,
				secondary_redeem_address,
				true, // lock MWC first
				MWC_CONFIRMATION,
				BTC_CONFIRMATION,
				MSG_EXCHANGE_TIME as u64,
				REDEEM_TIME as u64,
			)
			.unwrap();
		let fsm_sell = api_sell.get_fsm(&kc_sell, &swap_sell);

		let mut seller = {
			// Seller: create swap offer
			Trader {
				api: &api_sell,
				swap: swap_sell,
				fsm: fsm_sell,
				kc: kc_sell,
				ctx: ctx_sell,
				swap_stack: Vec::new(),
			}
		};

		// Initial state test.
		test_responds(
			&mut seller,
			StateId::SellerOfferCreated,
			Some(START_TIME + MSG_EXCHANGE_TIME), // timeout if possible
			Some(StateId::SellerCancelled),
			StateId::SellerSendingOffer, // Expected state before timeput
			StateId::SellerCancelled,    // Expected state after timeout
			None,                        // Expected state before timeput
			None,                        // Expected state after timeout
			None,                        // Acceptable message
			None,
			None,
		);

		// Go to the next step
		swap::set_testing_cur_time(START_TIME + 20);
		let res = seller.process(Input::Check).unwrap();
		assert_eq!(seller.swap.state, StateId::SellerSendingOffer);
		assert_eq!(
			res.time_limit.clone().unwrap(),
			START_TIME + MSG_EXCHANGE_TIME
		);
		assert_eq!(res.next_state_id, seller.swap.state);
		let _message1 = match res.action.unwrap() {
			Action::SellerSendOfferMessage(m) => m,
			_ => panic!("Unexpected action"),
		};

		// SellerSendingOffer
		test_responds(
			&mut seller,
			StateId::SellerSendingOffer,
			Some(START_TIME + MSG_EXCHANGE_TIME), // timeout if possible
			Some(StateId::SellerCancelled),
			StateId::SellerSendingOffer, // Expected state before timeput
			StateId::SellerCancelled,    // Expected state after timeout
			Some(StateId::SellerWaitingForAcceptanceMessage), // Expected state before timeput
			Some(StateId::SellerCancelled), // Expected state after timeout
			None,                        // Acceptable message
			None,
			None,
		);

		/*
				let sr = seller.process(Input::Check).unwrap();
				assert_eq!(sr.next_state_id, StateId::SellerSendingOffer);
				assert_eq!(sr.action.clone().unwrap().get_id_str(), "SellerSendOfferMessage");
				assert_eq!(sr.time_limit.unwrap(),MSG_EXCHANGE_TIME );

				// Checking if time_limit is updated
				swap::set_testing_cur_time(START_TIME+10);
				let sr = seller.process(Input::Check).unwrap();
				assert_eq!(sr.next_state_id, StateId::SellerSendingOffer);
				assert_eq!(sr.action.clone().unwrap().get_id_str(), "SellerSendOfferMessage");
				assert_eq!(sr.time_limit.unwrap(),MSG_EXCHANGE_TIME - 10);
				let message_1: Message = match sr.action.unwrap() {
					Action::SellerSendOfferMessage(message) => message,
					_ => panic!("Unexpected action"),
				};

				// Checking the timeout
				seller.pushs();
				swap::set_testing_cur_time(START_TIME+MSG_EXCHANGE_TIME-1);
				let sr = seller.process(Input::Check).unwrap();
				assert_eq!(sr.action.clone().unwrap().get_id_str(), "SellerSendOfferMessage");
				assert_eq!(sr.time_limit.unwrap(),1);
				swap::set_testing_cur_time(START_TIME+MSG_EXCHANGE_TIME);
				let sr = seller.process(Input::Check).unwrap();
				assert_eq!(sr.next_state_id, StateId::SellerCancelled);
				assert_eq!(sr.action.is_none(), true);
				seller.pops();
				seller.pushs();
				swap::set_testing_cur_time(START_TIME+MSG_EXCHANGE_TIME + 1000 );
				let sr = seller.process(Input::Check).unwrap();
				assert_eq!(sr.next_state_id, StateId::SellerCancelled);
				assert_eq!(sr.action.is_none(), true);

				seller.pops();

				// Creating buyer
				let mut buyer = {
					let kc_buy = keychain(2);
					let ctx_buy = context_buy(&kc_buy);

					// Buyer: accept swap offer
					let api_buy = BtcSwapApi::new(Arc::new(nc.clone()), Arc::new(Mutex::new(btc_nc.clone())));

					let (id, offer, secondary_update) = message_1.unwrap_offer().unwrap();
					let mut swap_buy =
						BuyApi::accept_swap_offer(&kc_buy, &ctx_buy, id, offer, secondary_update, &nc).unwrap();

					let mut fsm_buy = api_buy.get_fsm(&kc_buy, &swap_buy);


					let kc_sell = keychain(1);
					let ctx_sell = context_sell(&kc_sell);
					let secondary_redeem_address = btc_address(&kc_sell);

					let api_sell =
						BtcSwapApi::new(Arc::new(nc.clone()), Arc::new(Mutex::new(btc_nc.clone())));
					let swap_sell = api_sell
						.create_swap_offer(
							&kc_sell,
							&ctx_sell,
							amount,
							btc_amount,
							Currency::Btc,
							secondary_redeem_address,
							true, // lock MWC first
							MWC_CONFIRMATION,
							BTC_CONFIRMATION,
							MSG_EXCHANGE_TIME,
							REDEEM_TIME,
						)
						.unwrap();
					let fsm_sell = api_sell.get_fsm(&kc_sell, &swap_sell);

					// Seller: create swap offer
					Trader {
						api: api_sell,
						swap: swap_sell,
						fsm: fsm_sell,
						kc: kc_sell,
						ctx: ctx_sell,
						swap_stack: Vec::new();
					}
				};


				swap::set_testing_cur_time(START_TIME - 20 );


				let tx_conf = api_sell
					.request_tx_confirmations(&kc_sell, &swap_sell)
					.unwrap();
				let sell_resp = fsm_sell
					.process(Input::execute(), &mut swap_sell, &ctx_sell, &tx_conf)
					.unwrap();
				assert_eq!(
					sell_resp.action.unwrap().get_id_str(),
					"SellerWaitForOfferMessage"
				);
				assert_eq!(swap_sell.state, StateId::SellerWaitingForAcceptanceMessage);



				// Add inputs to utxo set
				nc.mine_blocks(2);
				for input in swap_sell.lock_slate.tx.inputs() {
					nc.push_output(input.commit.clone());
				}

				let kc_buy = keychain(2);
				let ctx_buy = context_buy(&kc_buy);

				// Buyer: accept swap offer
				let api_buy = BtcSwapApi::new(Arc::new(nc.clone()), Arc::new(Mutex::new(btc_nc.clone())));

				let (id, offer, secondary_update) = message_1.unwrap_offer().unwrap();
				let mut swap_buy =
					BuyApi::accept_swap_offer(&kc_buy, &ctx_buy, id, offer, secondary_update, &nc).unwrap();

				let mut fsm_buy = api_buy.get_fsm(&kc_buy, &swap_buy);
				let tx_conf = api_buy
					.request_tx_confirmations(&kc_buy, &swap_buy)
					.unwrap();
				let buy_resp = fsm_buy
					.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
					.unwrap();

				assert_eq!(swap_buy.state, StateId::BuyerSendingAcceptOfferMessage);
				let message_2 = match buy_resp.action.unwrap() {
					Action::BuyerSendAcceptOfferMessage(message) => message,
					_ => panic!("Unexpected action"),
				};
				let tx_conf = api_buy
					.request_tx_confirmations(&kc_buy, &swap_buy)
					.unwrap();
				let buy_resp = fsm_buy
					.process(Input::execute(), &mut swap_buy, &ctx_buy, &tx_conf)
					.unwrap();
				assert_eq!(swap_buy.state, StateId::BuyerWaitingForSellerToLock);

				// Expected to wait for the Seller to deposit MWC and wait for 1 block
				match buy_resp.action.unwrap() {
					Action::WaitForMwcConfirmations {
						name: _,
						required,
						actual,
					} => {
						assert_eq!(required, 1);
						assert_eq!(actual, 0);
					}
					_ => panic!("Invalid action"),
				}

				// !!!!!!!!!!!!!!!!!!!!!!
				// Here we are changing lock order because we want to keep tests original. Waiting case is covered, can go normally
				swap_buy.seller_lock_first = false;
				swap_sell.seller_lock_first = true;
				let tx_conf = api_buy
					.request_tx_confirmations(&kc_buy, &swap_buy)
					.unwrap();
				let buy_resp = fsm_buy
					.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
					.unwrap();

				assert_eq!(
					swap_buy.state,
					StateId::BuyerPostingSecondaryToMultisigAccount
				);

				// Buyer: should deposit bitcoin
				let address = match buy_resp.action.unwrap() {
					Action::DepositSecondary {
						currency: _,
						amount,
						address,
					} => {
						assert_eq!(amount, btc_amount);
						address
					}
					_ => panic!("Invalid action"),
				};
				let address = Address::from_str(&address).unwrap();

				// Buyer: first deposit
				let tx_1 = BtcTransaction {
					version: 2,
					lock_time: 0,
					input: vec![],
					output: vec![TxOut {
						value: btc_amount_1,
						script_pubkey: address.script_pubkey(),
					}],
				};
				let txid_1 = tx_1.txid();
				btc_nc.push_transaction(&tx_1);
				let tx_conf = api_buy
					.request_tx_confirmations(&kc_buy, &swap_buy)
					.unwrap();
				let buy_resp = fsm_buy
					.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
					.unwrap();
				assert_eq!(
					swap_buy.state,
					StateId::BuyerPostingSecondaryToMultisigAccount
				);
				match buy_resp.action.unwrap() {
					Action::DepositSecondary {
						currency: _,
						amount,
						address: _,
					} => assert_eq!(amount, btc_amount_2),
					_ => panic!("Invalid action"),
				};

				// Buyer: second deposit
				btc_nc.mine_blocks(2);
				let tx_2 = BtcTransaction {
					version: 2,
					lock_time: 0,
					input: vec![],
					output: vec![TxOut {
						value: btc_amount_2,
						script_pubkey: address.script_pubkey(),
					}],
				};
				let txid_2 = tx_2.txid();
				btc_nc.push_transaction(&tx_2);
				let tx_conf = api_buy
					.request_tx_confirmations(&kc_buy, &swap_buy)
					.unwrap();
				let buy_resp = fsm_buy
					.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
					.unwrap();
				assert_eq!(swap_buy.state, StateId::BuyerWaitingForLockConfirmations);

				match buy_resp.action.unwrap() {
					Action::WaitForSecondaryConfirmations {
						name: _,
						currency: _,
						required: _,
						actual,
					} => assert_eq!(actual, 1),
					_ => panic!("Invalid action"),
				};
				btc_nc.mine_blocks(5);

				// Buyer: wait for Grin confirmations
				let tx_conf = api_buy
					.request_tx_confirmations(&kc_buy, &swap_buy)
					.unwrap();
				let buy_resp = fsm_buy
					.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
					.unwrap();
				assert_eq!(swap_buy.state, StateId::BuyerWaitingForLockConfirmations);
				match buy_resp.action.unwrap() {
					Action::WaitForMwcConfirmations {
						name: _,
						required: _,
						actual,
					} => assert_eq!(actual, 0),
					_ => panic!("Invalid action"),
				};

				// Check if buyer has correct confirmed outputs
				{
					let script = api_buy.script(&swap_buy).unwrap();
					let (pending_amount, confirmed_amount, _, conf_outputs) =
						api_buy.btc_balance(&swap_buy, &script, 1).unwrap();

					assert_eq!(pending_amount, 0);
					assert_eq!(confirmed_amount, btc_amount_1 + btc_amount_2);
					assert_eq!(conf_outputs.len(), 2);
					let mut match_1 = 0;
					let mut match_2 = 0;
					for output in &conf_outputs {
						if output.out_point.txid == txid_1 {
							match_1 += 1;
						}
						if output.out_point.txid == txid_2 {
							match_2 += 1;
						}
					}
					assert_eq!(match_1, 1);
					assert_eq!(match_2, 1);
				}

				// Seller: receive accepted offer
				assert_eq!(swap_sell.state, StateId::SellerWaitingForAcceptanceMessage);
				let tx_conf = api_sell
					.request_tx_confirmations(&kc_sell, &swap_sell)
					.unwrap();
				let sell_resp = fsm_sell
					.process(
						Input::IncomeMessage(message_2),
						&mut swap_sell,
						&ctx_sell,
						&tx_conf,
					)
					.unwrap();
				assert_eq!(
					sell_resp.action.unwrap().get_id_str(),
					"SellerPublishMwcLockTx"
				);
				assert_eq!(swap_sell.state, StateId::SellerPostingLockMwcSlate);

				let tx_conf = api_sell
					.request_tx_confirmations(&kc_sell, &swap_sell)
					.unwrap();
				let sell_resp = fsm_sell
					.process(Input::execute(), &mut swap_sell, &ctx_sell, &tx_conf)
					.unwrap();
				assert_eq!(swap_sell.state, StateId::SellerWaitingForLockConfirmations);
				match sell_resp.action.unwrap() {
					Action::WaitForMwcConfirmations {
						name: _,
						required,
						actual,
					} => {
						assert_eq!(required, 30);
						assert_eq!(actual, 0)
					}
					_ => panic!("Invalid action"),
				}

				// Seller: wait for Grin confirmations
				nc.mine_blocks(10);
				let tx_conf = api_sell
					.request_tx_confirmations(&kc_sell, &swap_sell)
					.unwrap();
				let sell_resp = fsm_sell
					.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf)
					.unwrap();
				assert_eq!(swap_sell.state, StateId::SellerWaitingForLockConfirmations);
				match sell_resp.action.unwrap() {
					Action::WaitForMwcConfirmations {
						name: _,
						required,
						actual,
					} => {
						assert_eq!(required, 30);
						assert_eq!(actual, 10)
					}
					_ => panic!("Invalid action"),
				}
				let tx_conf = api_buy
					.request_tx_confirmations(&kc_buy, &swap_buy)
					.unwrap();
				let buy_resp = fsm_buy
					.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
					.unwrap();
				assert_eq!(swap_buy.state, StateId::BuyerWaitingForLockConfirmations);
				match buy_resp.action.unwrap() {
					Action::WaitForMwcConfirmations {
						name: _,
						required,
						actual,
					} => {
						assert_eq!(required, 30);
						assert_eq!(actual, 10)
					}
					_ => panic!("Invalid action"),
				}

				// Undo a BTC block to test seller
				{
					let mut state = btc_nc.state.lock();
					state.height -= 1;
				}

				// Seller: wait BTC confirmations
				nc.mine_blocks(20);
				let tx_conf = api_sell
					.request_tx_confirmations(&kc_sell, &swap_sell)
					.unwrap();
				let sell_resp = fsm_sell
					.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf)
					.unwrap();
				assert_eq!(swap_sell.state, StateId::SellerWaitingForLockConfirmations);
				match sell_resp.action.unwrap() {
					Action::WaitForSecondaryConfirmations {
						name: _,
						currency: _,
						required,
						actual,
					} => {
						assert_eq!(required, 6);
						assert_eq!(actual, 5)
					}
					_ => panic!("Invalid action"),
				}
				btc_nc.mine_block();

				// Checking if both seller & Buyer are moved to the redeem message exchange step
				let tx_conf = api_sell
					.request_tx_confirmations(&kc_sell, &swap_sell)
					.unwrap();
				let sell_resp = fsm_sell
					.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf)
					.unwrap();
				let tx_conf = api_buy
					.request_tx_confirmations(&kc_buy, &swap_buy)
					.unwrap();
				let buy_resp = fsm_buy
					.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
					.unwrap();

				assert_eq!(swap_sell.state, StateId::SellerWaitingForInitRedeemMessage);
				assert_eq!(swap_buy.state, StateId::BuyerSendingInitRedeemMessage);
				assert_eq!(
					sell_resp.action.unwrap().get_id_str(),
					"SellerWaitingForInitRedeemMessage"
				);
				let message_3 = match buy_resp.action.unwrap() {
					Action::BuyerSendInitRedeemMessage(message) => message,
					_ => panic!("Unexpected action"),
				};
				let tx_conf = api_buy
					.request_tx_confirmations(&kc_buy, &swap_buy)
					.unwrap();
				fsm_buy
					.process(Input::execute(), &mut swap_buy, &ctx_buy, &tx_conf)
					.unwrap();
				assert_eq!(swap_buy.state, StateId::BuyerWaitingForRespondRedeemMessage);

				// Seller: sign redeem
				let tx_conf = api_sell
					.request_tx_confirmations(&kc_sell, &swap_sell)
					.unwrap();
				let sell_resp = fsm_sell
					.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf)
					.unwrap();
				assert_eq!(swap_sell.state, StateId::SellerWaitingForInitRedeemMessage);
				assert_eq!(
					sell_resp.action.unwrap().get_id_str(),
					"SellerWaitingForInitRedeemMessage"
				);

				let tx_conf = api_sell
					.request_tx_confirmations(&kc_sell, &swap_sell)
					.unwrap();
				let sell_resp = fsm_sell
					.process(
						Input::IncomeMessage(message_3),
						&mut swap_sell,
						&ctx_sell,
						&tx_conf,
					)
					.unwrap();
				assert_eq!(swap_sell.state, StateId::SellerSendingInitRedeemMessage);
				let message_4 = match sell_resp.action.unwrap() {
					Action::SellerSendRedeemMessage(message) => message,
					_ => panic!("Unexpected action"),
				};

				let tx_conf = api_sell
					.request_tx_confirmations(&kc_sell, &swap_sell)
					.unwrap();
				let sell_resp = fsm_sell
					.process(Input::execute(), &mut swap_sell, &ctx_sell, &tx_conf)
					.unwrap();
				// Seller: wait for buyer's on-chain redeem tx
				assert_eq!(swap_sell.state, StateId::SellerWaitingForBuyerToRedeemMwc);
				assert_eq!(
					sell_resp.action.unwrap().get_id_str(),
					"SellerWaitForBuyerRedeemPublish"
				);

				// Buyer: redeem
				let tx_conf = api_buy
					.request_tx_confirmations(&kc_buy, &swap_buy)
					.unwrap();
				let buy_resp = fsm_buy
					.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
					.unwrap();
				assert_eq!(swap_buy.state, StateId::BuyerWaitingForRespondRedeemMessage);
				assert_eq!(
					buy_resp.action.unwrap().get_id_str(),
					"BuyerWaitingForRedeemMessage"
				);

				let tx_conf = api_buy
					.request_tx_confirmations(&kc_buy, &swap_buy)
					.unwrap();
				let buy_resp = fsm_buy
					.process(
						Input::IncomeMessage(message_4),
						&mut swap_buy,
						&ctx_buy,
						&tx_conf,
					)
					.unwrap();
				assert_eq!(swap_buy.state, StateId::BuyerRedeemMwc);
				assert_eq!(
					buy_resp.action.unwrap().get_id_str(),
					"BuyerPublishMwcRedeemTx"
				);

				let tx_conf = &api_buy
					.request_tx_confirmations(&kc_buy, &swap_buy)
					.unwrap();
				let buy_resp = fsm_buy
					.process(Input::execute(), &mut swap_buy, &ctx_buy, &tx_conf)
					.unwrap();
				assert_eq!(swap_buy.state, StateId::BuyerWaitForRedeemMwcConfirmations);
				assert_eq!(
					buy_resp.action.unwrap().get_id_str(),
					"WaitForMwcConfirmations"
				);

				// Buyer: almost done, just need to wait for confirmations
				nc.mine_block();

				let tx_conf = api_buy
					.request_tx_confirmations(&kc_buy, &swap_buy)
					.unwrap();
				let buy_resp = fsm_buy
					.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
					.unwrap();
				assert_eq!(swap_buy.state, StateId::BuyerWaitForRedeemMwcConfirmations);
				match buy_resp.action.unwrap() {
					Action::WaitForMwcConfirmations {
						name: _,
						required,
						actual,
					} => {
						assert_eq!(actual, 1);
						assert_eq!(required, 30);
					}
					_ => panic!("Invalid action"),
				}

				// Seller: publish BTC tx
				let tx_conf = api_sell
					.request_tx_confirmations(&kc_sell, &swap_sell)
					.unwrap();
				let sell_resp = fsm_sell
					.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf)
					.unwrap();
				assert_eq!(swap_sell.state, StateId::SellerRedeemSecondaryCurrency);
				assert_eq!(
					sell_resp.action.unwrap().get_id_str(),
					"SellerPublishTxSecondaryRedeem"
				);

				// Seller: publishing and wait for BTC confirmations
				let tx_conf = api_sell
					.request_tx_confirmations(&kc_sell, &swap_sell)
					.unwrap();
				let sell_resp = fsm_sell
					.process(Input::execute(), &mut swap_sell, &ctx_sell, &tx_conf)
					.unwrap();
				assert_eq!(
					swap_sell.state,
					StateId::SellerWaitingForRedeemConfirmations
				);
				match sell_resp.action.unwrap() {
					Action::WaitForSecondaryConfirmations {
						name: _,
						currency: _,
						required,
						actual,
					} => {
						assert_eq!(required, 6);
						assert_eq!(actual, 0)
					}
					_ => panic!("Invalid action"),
				}

				btc_nc.mine_block();
				// still waiting
				let tx_conf = api_sell
					.request_tx_confirmations(&kc_sell, &swap_sell)
					.unwrap();
				let sell_resp = fsm_sell
					.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf)
					.unwrap();
				assert_eq!(
					swap_sell.state,
					StateId::SellerWaitingForRedeemConfirmations
				);
				match sell_resp.action.unwrap() {
					Action::WaitForSecondaryConfirmations {
						name: _,
						currency: _,
						required,
						actual,
					} => {
						assert_eq!(required, 6);
						assert_eq!(actual, 1)
					}
					_ => panic!("Invalid action"),
				}

				// Let's mine more blocks, so both Buyer and Seller will come to complete state
				nc.mine_blocks(30);
				btc_nc.mine_blocks(6);

				let tx_conf = api_sell
					.request_tx_confirmations(&kc_sell, &swap_sell)
					.unwrap();
				let sell_resp = fsm_sell
					.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf)
					.unwrap();
				let tx_conf = &api_buy
					.request_tx_confirmations(&kc_buy, &swap_buy)
					.unwrap();
				let buy_resp = fsm_buy
					.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
					.unwrap();

				// Seller & Buyer: complete!
				assert_eq!(swap_sell.state, StateId::SellerSwapComplete);
				assert_eq!(swap_buy.state, StateId::BuyerSwapComplete);
				assert!(sell_resp.action.is_none());
				assert!(buy_resp.action.is_none());
		*/
	}
}
