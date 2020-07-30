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

use super::error::ErrorKind;
use super::swap::Swap;
use super::types::{Context, Currency};
use super::Keychain;
use crate::swap::bitcoin::{BtcSwapApi, ElectrumNodeClient};
use crate::swap::fsm::machine::StateMachine;
use crate::swap::message::SecondaryUpdate;
use crate::swap::types::SwapTransactionsConfirmations;
use crate::NodeClient;
use grin_core::global;
use grin_keychain::Identifier;
use grin_util::Mutex;
use std::sync::Arc;

/// Swap API trait that is used by both Buyer and Seller.
/// Every currency that Swap want to support, need to implement
/// this trait. Current we have only implementaiton: api::BtcSwapApi
pub trait SwapApi<K: Keychain>: Sync + Send {
	/// Number of the keys at the create_context, keys (For BTC it is 4)
	fn context_key_count(
		&mut self,
		_keychain: &K,
		secondary_currency: Currency,
		is_seller: bool,
	) -> Result<usize, ErrorKind>;

	/// Creating buyer/seller context. Keys are used to generate this session secrets.
	/// Number of them defined by context_key_count
	fn create_context(
		&mut self,
		keychain: &K,
		secondary_currency: Currency,
		is_seller: bool,
		inputs: Option<Vec<(Identifier, Option<u64>, u64)>>, // inputs with amounts that sellect is agree to use.
		change_amount: u64,
		keys: Vec<Identifier>,
	) -> Result<Context, ErrorKind>;

	/// Seller creates a swap offer and creates the core Swap Object.
	/// It is a starting point for Seller swap workflow
	fn create_swap_offer(
		&mut self,
		keychain: &K,
		context: &Context,
		primary_amount: u64,   // mwc amount to sell
		secondary_amount: u64, // btc amount to buy
		secondary_currency: Currency,
		secondary_redeem_address: String, // redeed address for BTC
		seller_lock_first: bool,
		mwc_confirmations: u64, // Needed conformation numbers for mwc & btc
		secondary_confirmations: u64,
		message_exchange_time_sec: u64,
		redeem_time_sec: u64,
	) -> Result<Swap, ErrorKind>;

	/// get state machine fro this trade.
	fn get_fsm(&self, keychain: &K, swap: &Swap) -> StateMachine;

	/// Request confirmation numberss for all transactions that are known and in the in the swap
	fn request_tx_confirmations(
		&self,
		_keychain: &K,
		swap: &Swap,
	) -> Result<SwapTransactionsConfirmations, ErrorKind>;

	/// Build secondary update part of the offer message
	fn build_offer_message_secondary_update(
		&self,
		_keychain: &K, // To make compiler happy
		swap: &mut Swap,
	) -> SecondaryUpdate;

	/// Build secondary update part of the accept offer message
	fn build_accept_offer_message_secondary_update(
		&self,
		_keychain: &K, // To make compiler happy
		swap: &mut Swap,
	) -> SecondaryUpdate;

	/// Publishing Secinadary (BTC) transactions
	/// Seller: redeep BTC transaction at State RedeemSecondary
	fn publish_secondary_transaction(
		&self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		fee_satoshi_per_byte: Option<f32>,
	) -> Result<(), ErrorKind>;
}

/// Create an appropriate instance for the Currency
/// electrumx_uri - mandatory for BTC
/// Note: Result lifetime is equal of arguments lifetime!
pub fn create_instance<'a, C, K>(
	currency: &Currency,
	node_client: C,
) -> Result<Box<dyn SwapApi<K> + 'a>, ErrorKind>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	match currency {
		Currency::Btc => {
			let electrumx_uri = crate::swap::trades::get_electrumx_uri();
			if electrumx_uri.is_none() {
				return Err(ErrorKind::UndefinedElectrumXURI);
			}

			let btc_node_client = ElectrumNodeClient::new(
				electrumx_uri.expect("BTC API requires BTC node client"),
				!global::is_mainnet(),
			);
			Ok(Box::new(BtcSwapApi::new(
				Arc::new(node_client),
				Arc::new(Mutex::new(btc_node_client)),
			)))
		}
	}
}
