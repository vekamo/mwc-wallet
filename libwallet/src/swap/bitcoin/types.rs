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

use super::client::Output;
use crate::swap::message::SecondaryUpdate;
use crate::swap::ser::*;
use crate::swap::swap;
use crate::swap::types::{Currency, Network, SecondaryData};
use crate::swap::{ErrorKind, Keychain};
use bitcoin::blockdata::opcodes::{all::*, OP_FALSE, OP_TRUE};
use bitcoin::blockdata::script::Builder;
use bitcoin::consensus::Encodable;
use bitcoin::network::constants::Network as BtcNetwork;
#[cfg(test)]
use bitcoin::OutPoint;
use bitcoin::{Address, Script, Transaction, TxIn, TxOut, VarInt};
use bitcoin_hashes::sha256d;
use byteorder::{ByteOrder, LittleEndian};
use grin_keychain::{Identifier, SwitchCommitmentType};
use grin_util::secp::key::{PublicKey, SecretKey};
use grin_util::secp::{Message, Secp256k1, Signature};
use std::io::Cursor;
use std::ops::Deref;

use bch::messages::{Tx as BchTx, TxIn as BchTxIn, TxOut as BchTxOut};
use bitcoin_hashes::hex::ToHex;
use bitcoin_hashes::{hash160, Hash};

/// BTC transaction ready to post (any type). Here it is a redeem tx
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BtcTtansaction {
	pub txid: sha256d::Hash,
	#[serde(serialize_with = "bytes_to_hex", deserialize_with = "bytes_from_hex")]
	pub tx: Vec<u8>,
}

/// BTC operations context
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BtcData {
	/// Key owned by seller. Private key: keychain + BtcSellerContext::cosign
	#[serde(serialize_with = "pubkey_to_hex", deserialize_with = "pubkey_from_hex")]
	pub cosign: PublicKey,
	/// Key owned by buyer
	#[serde(
		serialize_with = "option_pubkey_to_hex",
		deserialize_with = "option_pubkey_from_hex"
	)]
	pub refund: Option<PublicKey>,
	/// Refund transaction Hash
	pub refund_tx: Option<sha256d::Hash>,
	/// BTX redeem transaction hash, needed for checking if it is posted
	pub redeem_tx: Option<sha256d::Hash>,
	/// Last transaction fee that was used for BTC. Needed to detect the fact that it is changed.
	pub tx_fee: Option<f32>,
}

impl BtcData {
	/// Create seller BTC data (party that receive BTC).
	pub(crate) fn new<K>(
		keychain: &K,               // Private key
		context: &BtcSellerContext, // Derivarive index
	) -> Result<Self, ErrorKind>
	where
		K: Keychain,
	{
		let cosign = PublicKey::from_secret_key(
			keychain.secp(),
			&keychain.derive_key(0, &context.cosign, SwitchCommitmentType::None)?,
		)?;

		Ok(Self {
			cosign,
			refund: None,
			refund_tx: None,
			redeem_tx: None,
			tx_fee: None,
		})
	}

	/// Create buyer BTC data (party that sell BTC)
	pub(crate) fn from_offer<K>(
		keychain: &K,
		offer: BtcOfferUpdate,
		context: &BtcBuyerContext,
	) -> Result<Self, ErrorKind>
	where
		K: Keychain,
	{
		let key = keychain.derive_key(0, &context.refund, SwitchCommitmentType::None)?;

		Ok(Self {
			cosign: offer.cosign,
			refund: Some(PublicKey::from_secret_key(keychain.secp(), &key)?),
			refund_tx: None,
			redeem_tx: None,
			tx_fee: None,
		})
	}

	/// Seller applies accepted offer message from the buyer
	pub(crate) fn accepted_offer(
		&mut self,
		accepted_offer: BtcAcceptOfferUpdate,
	) -> Result<(), ErrorKind> {
		self.refund = Some(accepted_offer.refund);
		Ok(())
	}
	/// Return BTC related data
	pub(crate) fn wrap(self) -> SecondaryData {
		SecondaryData::Btc(self)
	}

	/// Generate the multisig-with-timelocked-refund script
	pub fn script(&self, redeem: &PublicKey, btc_lock_time: u64) -> Result<Script, ErrorKind> {
		// Don't lock for more than 4 weeks. 4 weeks + 2 day, because max locking is expecting 2 weeks and 1 day to do the swap and 1 extra day for Byer
		if btc_lock_time > (swap::get_cur_time() + 3600 * 24 * (7 * 4 + 2)) as u64 {
			return Err(ErrorKind::Generic(
				"BTC locking time interval is larger than 4 weeks. Rejecting, looks like a scam."
					.to_string(),
			));
		}

		if btc_lock_time >= u32::MAX as u64 {
			return Err(ErrorKind::Generic(
				"BTC locking time is out of range. Rejecting, looks like a scam.".to_string(),
			));
		}

		// Locking for the past is very expected. We build this script every time when we need to calculate hash for the address.

		let mut time = [0; 4];
		let btc_lock_time: u32 = btc_lock_time as u32;
		LittleEndian::write_u32(&mut time, btc_lock_time);

		let refund = self
			.refund
			.ok_or(ErrorKind::SecondaryDataIncomplete)?
			.serialize_vec(true);
		let cosign = self.cosign.serialize_vec(true);
		let redeem = redeem.serialize_vec(true);

		let builder = Builder::new()
			.push_opcode(OP_IF) // Refund path
			.push_slice(&time)
			.push_opcode(OP_CLTV) // Check transaction lock time
			.push_opcode(OP_DROP)
			.push_slice(refund.as_slice())
			.push_opcode(OP_CHECKSIG) // Check signature
			.push_opcode(OP_ELSE) // Redeem path
			.push_opcode(OP_PUSHNUM_2)
			.push_slice(cosign.as_slice())
			.push_slice(redeem.as_slice())
			.push_opcode(OP_PUSHNUM_2)
			.push_opcode(OP_CHECKMULTISIG) // Check 2-of-2 multisig
			.push_opcode(OP_ENDIF);

		Ok(builder.into_script())
	}

	/// Generate the P2SH address for the script
	pub fn address(
		&self,
		currency: Currency,
		script: &Script,
		network: Network,
	) -> Result<String, ErrorKind> {
		match currency {
			Currency::Btc => {
				let address = Address::p2sh(script, btc_network(network));
				Ok(address.to_string())
			}
			Currency::Bch => {
				let address = bch::address::cashaddr_encode(
					&hash160::Hash::hash(&script[..]),
					bch::address::AddressType::P2SH,
					bch_network(network),
				)
				.map_err(|e| {
					ErrorKind::BchError(format!(
						"Unable to encode BCH address fron script hash, {}",
						e
					))
				})?;
				Ok(address)
			}
		}
	}

	// Build input/output for redeem or refund btc transaciton
	// Inputs need to have amounts for BCH signature
	fn build_input_outputs(
		&self,
		currency: &Currency,
		redeem_address: &String,
		conf_outputs: &Vec<Output>,
	) -> Result<(Vec<(TxIn, u64)>, Vec<TxOut>, u64), ErrorKind> {
		// Input(s)
		let mut input = Vec::with_capacity(conf_outputs.len());
		let mut total_amount = 0;
		for o in conf_outputs {
			total_amount += o.value;
			input.push((
				TxIn {
					previous_output: o.out_point.clone(),
					script_sig: Script::new(),
					sequence: 0,
					witness: Vec::new(),
				},
				o.value,
			));
		}

		if input.is_empty() {
			return Err(ErrorKind::Generic(
				"Unable to build refund transaction, no inputs are found".to_string(),
			));
		}
		// Output
		let mut output = Vec::with_capacity(1);
		output.push(TxOut {
			value: total_amount, // Will be overwritten later
			script_pubkey: currency.address_2_script_pubkey(redeem_address)?,
		});

		Ok((input, output, total_amount))
	}

	// Because BCH library can calculate the hash, but for the core we are using BTC, that is
	// why we have this ugly solution. In any case it is better then have 2 separate implemenattions.
	fn convert_tx_to_bch(tx: &Transaction) -> BchTx {
		let mut inputs: Vec<BchTxIn> = vec![];
		let mut outputs: Vec<BchTxOut> = vec![];

		for tx_in in &tx.input {
			let mut sig_script = bch::script::Script::new();
			sig_script.append_slice(tx_in.script_sig.as_bytes());

			let prev_output = bch::messages::OutPoint {
				hash: bch::util::Hash256::decode(tx_in.previous_output.txid.to_hex().as_str())
					.unwrap(),
				index: tx_in.previous_output.vout,
			};

			inputs.push(BchTxIn {
				prev_output,
				/// Signature script for confirming authorization
				sig_script,
				sequence: tx_in.sequence,
			})
		}

		for tx_out in &tx.output {
			outputs.push(BchTxOut {
				amount: bch::util::Amount(tx_out.value as i64),
				/// Public key script to claim the output
				pk_script: bch::script::Script(tx_out.script_pubkey.to_bytes()),
			})
		}

		BchTx {
			lock_time: tx.lock_time,
			version: tx.version,
			inputs,
			outputs,
		}
	}

	/// Build BTC redeem transactions
	/// Update self.redeem_tx  with result
	pub(crate) fn build_redeem_tx(
		&self,
		currency: &Currency,
		secp: &Secp256k1,
		redeem_address: &String,
		input_script: &Script,
		fee_sat_per_byte: f32,
		cosign_secret: &SecretKey,
		redeem_secret: &SecretKey,
		conf_outputs: &Vec<Output>,
	) -> Result<(BtcTtansaction, Transaction, usize, usize), ErrorKind> {
		let (input, output, total_amount) =
			self.build_input_outputs(currency, redeem_address, conf_outputs)?;

		let mut tx = Transaction {
			version: 2,
			lock_time: 0,
			input: input.iter().map(|i| i.0.clone()).collect(),
			output,
		};

		// Calculate tx size
		let mut script_sig_size = input_script.len();
		script_sig_size += VarInt(script_sig_size as u64).len();
		script_sig_size += 2 * (1 + 72 + 1); // Signatures
		script_sig_size += 2; // Opcodes
		let tx_size = tx.get_weight() / 4 + script_sig_size * tx.input.len();

		// Subtract fee from output
		tx.output[0].value =
			total_amount.saturating_sub((tx_size as f32 * fee_sat_per_byte + 0.5) as u64);

		match currency {
			Currency::Btc => {
				// Sign for inputs
				for idx in 0..tx.input.len() {
					let hash = tx.signature_hash(idx, &input_script, 0x01);
					let msg = Message::from_slice(hash.deref())?;

					tx.input
						.get_mut(idx)
						.ok_or(ErrorKind::Generic("Not found expected input".to_string()))?
						.script_sig = self.redeem_script_sig(
						currency,
						input_script,
						&mut secp.sign(&msg, cosign_secret)?,
						&mut secp.sign(&msg, redeem_secret)?,
					)?;
				}
			}
			Currency::Bch => {
				// Sign for inputs
				let bch_tx = Self::convert_tx_to_bch(&tx);

				for idx in 0..tx.input.len() {
					// Actually BCH team doesn't allow to reuse the cache. REALLY?  WHY?
					let mut cache = bch::transaction::sighash::SigHashCache::new();

					let sighash_type = bch::transaction::sighash::SIGHASH_ALL
						| bch::transaction::sighash::SIGHASH_FORKID;
					let hash = bch::transaction::sighash::sighash(
						&bch_tx,
						idx,
						input_script.as_bytes(),
						bch::util::Amount(input[idx].1 as i64),
						sighash_type,
						&mut cache,
					)
					.map_err(|e| ErrorKind::BchError(format!("sighash failed, {}", e)))?;

					let msg = Message::from_slice(&hash.0)?;

					tx.input
						.get_mut(idx)
						.ok_or(ErrorKind::Generic("Not found expected input".to_string()))?
						.script_sig = self.redeem_script_sig(
						currency,
						input_script,
						&mut secp.sign(&msg, cosign_secret)?,
						&mut secp.sign(&msg, redeem_secret)?,
					)?;
				}
			}
		};

		let mut cursor = Cursor::new(Vec::with_capacity(tx_size));
		let actual_size = tx
			.consensus_encode(&mut cursor)
			.map_err(|e| ErrorKind::Generic(format!("Unable to encode redeem tx, {}", e)))?;

		Ok((
			BtcTtansaction {
				txid: tx.txid(),
				tx: cursor.into_inner(),
			},
			tx,
			tx_size,
			actual_size,
		))
	}

	fn redeem_script_sig(
		&self,
		currency: &Currency,
		input_script: &Script,
		cosign_signature: &mut Signature,
		redeem_signature: &mut Signature,
	) -> Result<Script, ErrorKind> {
		let (cosign_ser, redeem_ser) = match currency {
			Currency::Btc => {
				let mut cosign_ser = cosign_signature.serialize_der();
				cosign_ser.push(0x01); // SIGHASH_ALL

				let mut redeem_ser = redeem_signature.serialize_der();
				redeem_ser.push(0x01); // SIGHASH_ALL

				(cosign_ser, redeem_ser)
			}
			Currency::Bch => {
				cosign_signature.normalize_s();
				let mut cosign_ser = cosign_signature.serialize_der();
				cosign_ser.push(0x41); // SIGHASH_ALL

				redeem_signature.normalize_s();
				let mut redeem_ser = redeem_signature.serialize_der();
				redeem_ser.push(0x41); // SIGHASH_ALL

				(cosign_ser, redeem_ser)
			}
		};

		let script_sig = Builder::new()
			.push_opcode(OP_FALSE) // Bitcoin multisig bug
			.push_slice(&cosign_ser)
			.push_slice(&redeem_ser)
			.push_opcode(OP_FALSE) // Choose redeem path in original script
			.push_slice(input_script.as_bytes())
			.into_script();

		Ok(script_sig)
	}

	/// Build BTC redeem transactions
	/// Update self.redeem_tx  with result
	pub(crate) fn refund_tx(
		&mut self,
		currency: &Currency,
		secp: &Secp256k1,
		refund_address: &String,
		input_script: &Script,
		fee_sat_per_byte: f32,
		btc_lock_time: i64,
		buyer_btc_secret: &SecretKey,
		conf_outputs: &Vec<Output>,
	) -> Result<BtcTtansaction, ErrorKind> {
		let (input, output, total_amount) =
			self.build_input_outputs(currency, refund_address, conf_outputs)?;
		let mut tx = Transaction {
			version: 2,
			lock_time: (btc_lock_time + 1) as u32, // lock time must be larger for BCH
			input: input.iter().map(|i| i.0.clone()).collect(),
			output,
		};

		// Calculate tx size
		let mut script_sig_size = input_script.len();
		script_sig_size += VarInt(script_sig_size as u64).len();
		script_sig_size += 1 * (1 + 72 + 1); // Signature (uno for refund)
		script_sig_size += 1; // Opcodes
		let tx_size = tx.get_weight() / 4 + script_sig_size * tx.input.len();

		// Subtract fee from output
		tx.output[0].value =
			total_amount.saturating_sub((tx_size as f32 * fee_sat_per_byte + 0.5) as u64);

		match currency {
			Currency::Btc => {
				// Sign for inputs
				for idx in 0..tx.input.len() {
					let hash = tx.signature_hash(idx, input_script, 0x01);
					let msg = Message::from_slice(hash.deref())?;

					tx.input
						.get_mut(idx)
						.ok_or(ErrorKind::Generic("Not found expected input".to_string()))?
						.script_sig = self.refund_script_sig(
						currency,
						&mut secp.sign(&msg, buyer_btc_secret)?,
						input_script,
					)?;
				}
			}
			Currency::Bch => {
				let bch_tx = Self::convert_tx_to_bch(&tx);

				// Sign for inputs
				for idx in 0..tx.input.len() {
					// Actually BCH team doesn't allow to reuse the cache. REALLY?  WHY?
					let mut cache = bch::transaction::sighash::SigHashCache::new();

					let sighash_type = bch::transaction::sighash::SIGHASH_ALL
						| bch::transaction::sighash::SIGHASH_FORKID;
					let hash = bch::transaction::sighash::sighash(
						&bch_tx,
						0,
						input_script.as_bytes(),
						bch::util::Amount(input[idx].1 as i64),
						sighash_type,
						&mut cache,
					)
					.map_err(|e| ErrorKind::BchError(format!("sighash failed, {}", e)))?;

					let msg = Message::from_slice(&hash.0)?;

					tx.input
						.get_mut(idx)
						.ok_or(ErrorKind::Generic("Not found expected input".to_string()))?
						.script_sig = self.refund_script_sig(
						currency,
						&mut secp.sign(&msg, buyer_btc_secret)?,
						input_script,
					)?;
				}
			}
		};

		let mut cursor = Cursor::new(Vec::with_capacity(tx_size));
		let actual_size = tx
			.consensus_encode(&mut cursor)
			.map_err(|e| ErrorKind::Generic(format!("Unable to encode redeem tx, {}", e)))?;

		// By some reasons length is floating, probably encoding can do some optimization . Let'e keep an eye on it, we don't want to calcucate fee badly.
		debug_assert!(actual_size <= tx_size);
		debug_assert!(actual_size >= tx_size - 5);

		Ok(BtcTtansaction {
			txid: tx.txid(),
			tx: cursor.into_inner(),
		})
	}

	fn refund_script_sig(
		&self,
		currency: &Currency,
		signature: &mut Signature,
		input_script: &Script,
	) -> Result<Script, ErrorKind> {
		let sign_ser = match currency {
			Currency::Bch => {
				signature.normalize_s();
				let mut sign_ser = signature.serialize_der();
				sign_ser.push(0x41); // SIGHASH_ALL
				sign_ser
			}
			Currency::Btc => {
				let mut sign_ser = signature.serialize_der();
				sign_ser.push(0x01); // SIGHASH_ALL
				sign_ser
			}
		};

		let script_sig = Builder::new()
			.push_slice(&sign_ser)
			.push_opcode(OP_TRUE) // Choose refund path in original script
			.push_slice(input_script.as_bytes())
			.into_script();

		Ok(script_sig)
	}

	/// Seller init BTC offer for buyer
	pub(crate) fn offer_update(&self) -> BtcUpdate {
		BtcUpdate::Offer(BtcOfferUpdate {
			cosign: self.cosign.clone(), // Buyer part of Schnorr multisig.
		})
	}

	/// Seller apply respond for the Buyer.
	pub(crate) fn accept_offer_update(&self) -> BtcUpdate {
		BtcUpdate::AcceptOffer(BtcAcceptOfferUpdate {
			refund: self
				.refund
				.expect("BTC refund pubkey is not defined at BtcAcceptOfferUpdate payload")
				.clone(),
		})
	}
}

/// Context for the Seller (party that receive BTC)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BtcSellerContext {
	/// Seller, cosign index for derivative key.
	pub cosign: Identifier,
}

/// Context for the Buyer (party that sell BTC)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BtcBuyerContext {
	/// Buyer refund index for derivative key
	pub refund: Identifier,
}

/// Messages regarding BTC part of the deal
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum BtcUpdate {
	/// Seller send offer to Buyer. Here is details about BTC deal
	Offer(BtcOfferUpdate),
	/// Buyer message back to Seller. Offer is accepted
	AcceptOffer(BtcAcceptOfferUpdate),
}

impl BtcUpdate {
	/// Unwrap BtcOfferUpdate  with data type verification
	pub fn unwrap_offer(self) -> Result<BtcOfferUpdate, ErrorKind> {
		match self {
			BtcUpdate::Offer(u) => Ok(u),
			_ => Err(ErrorKind::UnexpectedMessageType(
				"Fn unwrap_offer() expecting BtcUpdate::Offer".to_string(),
			)),
		}
	}

	/// Unwrap BtcAcceptOfferUpdate  with data type verification
	pub fn unwrap_accept_offer(self) -> Result<BtcAcceptOfferUpdate, ErrorKind> {
		match self {
			BtcUpdate::AcceptOffer(u) => Ok(u),
			_ => Err(ErrorKind::UnexpectedMessageType(
				"Fn unwrap_accept_offer() expecting BtcUpdate::AcceptOffer".to_string(),
			)),
		}
	}

	/// Wrap thos BTC object into SecondaryUpdate message.
	pub fn wrap(self) -> SecondaryUpdate {
		SecondaryUpdate::BTC(self)
	}
}

/// Seller send offer to Buyer. Here is details about BTC deal
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct BtcOfferUpdate {
	/// Public key to do cosign with Schnorr signature.
	#[serde(serialize_with = "pubkey_to_hex", deserialize_with = "pubkey_from_hex")]
	pub cosign: PublicKey,
}

/// Buyer message back to Seller. Offer is accepted
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct BtcAcceptOfferUpdate {
	/// Buyer public key for refund
	#[serde(serialize_with = "pubkey_to_hex", deserialize_with = "pubkey_from_hex")]
	pub refund: PublicKey,
}

/// Map MWC network to matched BTC network
fn btc_network(network: Network) -> BtcNetwork {
	match network {
		Network::Floonet => BtcNetwork::Testnet,
		Network::Mainnet => BtcNetwork::Bitcoin,
	}
}

fn bch_network(network: Network) -> bch::network::Network {
	match network {
		Network::Floonet => bch::network::Network::Testnet,
		Network::Mainnet => bch::network::Network::Mainnet,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::util::address::Payload;
	use bitcoin::util::key::PublicKey as BTCPublicKey;
	use grin_core::global;
	use grin_core::global::ChainTypes;
	use grin_util::from_hex;
	use grin_util::secp::key::PublicKey;
	use grin_util::secp::{ContextFlag, Secp256k1};
	use rand::{thread_rng, Rng, RngCore};
	use std::collections::HashMap;

	#[test]
	/// Test vector from the PoC
	fn test_lock_script() {
		let lock_time = 1541355813;

		let data = BtcData {
			cosign: PublicKey::from_slice(
				&from_hex(
					"02b4e59070d367a364a31981a71fc5ab6c5034d0e279eecec19287f3c95db84aef".into(),
				)
				.unwrap(),
			)
			.unwrap(),
			refund: Some(
				PublicKey::from_slice(
					&from_hex(
						"022fd8c0455bede249ad3b9a9fb8159829e8cfb2c360863896e5309ea133d122f2".into(),
					)
					.unwrap(),
				)
				.unwrap(),
			),
			refund_tx: None,
			redeem_tx: None,
			tx_fee: None,
		};

		let input_script = data
			.script(
				&PublicKey::from_slice(
					&from_hex(
						"03cf15041579b5fb7accbac2997fb2f3e1001e9a522a19c83ceabe5ae51a596c7c".into(),
					)
					.unwrap(),
				)
				.unwrap(),
				lock_time,
			)
			.unwrap();
		let script_ref = from_hex("63042539df5bb17521022fd8c0455bede249ad3b9a9fb8159829e8cfb2c360863896e5309ea133d122f2ac67522102b4e59070d367a364a31981a71fc5ab6c5034d0e279eecec19287f3c95db84aef2103cf15041579b5fb7accbac2997fb2f3e1001e9a522a19c83ceabe5ae51a596c7c52ae68".into()).unwrap();
		assert_eq!(input_script.clone().to_bytes(), script_ref);

		assert_eq!(
			format!(
				"{}",
				data.address(Currency::Btc, &input_script, Network::Floonet)
					.unwrap()
			),
			String::from("2NEwEAG9VyFYt2sjLpuHrU4Abb7nGJfc7PR")
		);
	}

	#[test]
	fn test_redeem_script() {
		global::set_local_chain_type(ChainTypes::Floonet);
		let network = Network::Floonet;
		swap::set_testing_cur_time(1567632152);

		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let rng = &mut thread_rng();

		let cosign = SecretKey::new(rng);
		let refund = SecretKey::new(rng);
		let redeem = SecretKey::new(rng);

		let lock_time = swap::get_cur_time() as u64;

		let data = BtcData {
			cosign: PublicKey::from_secret_key(&secp, &cosign).unwrap(),
			refund: Some(PublicKey::from_secret_key(&secp, &refund).unwrap()),
			refund_tx: None,
			redeem_tx: None,
			tx_fee: None,
		};
		let input_script = data
			.script(
				&PublicKey::from_secret_key(&secp, &redeem).unwrap(),
				lock_time,
			)
			.unwrap();
		let lock_address = data.address(Currency::Btc, &input_script, network).unwrap();
		let lock_script_pubkey = Currency::Btc
			.address_2_script_pubkey(&lock_address)
			.unwrap();

		// Create a bunch of funding transactions
		let count = rng.gen_range(3, 7);
		let mut funding_txs = HashMap::with_capacity(count);

		let mut confirmed_outputs = Vec::new();

		for i in 0..count {
			let value = (i as u64 + 1) * 1_000_000;

			// Generate a bunch of trash P2PKH and P2SH outputs
			let vout = rng.gen_range(0usize, 5);
			let mut output = Vec::with_capacity(vout + 1);
			for _ in 0..vout {
				let mut hash: Vec<u8> = vec![0; 20];
				rng.fill_bytes(&mut hash);
				let hash = hash160::Hash::from_slice(&hash).unwrap();
				let payload = if rng.gen_bool(0.5) {
					Payload::PubkeyHash(hash)
				} else {
					Payload::ScriptHash(hash)
				};
				let script_pubkey = payload.script_pubkey();
				output.push(TxOut {
					value: rng.gen(),
					script_pubkey,
				});
			}
			output.push(TxOut {
				value,
				script_pubkey: lock_script_pubkey.clone(),
			});

			let tx = Transaction {
				version: 2,
				lock_time: lock_time as u32 - 1,
				input: vec![],
				output,
			};

			let txid = tx.txid();
			confirmed_outputs.push(Output {
				out_point: OutPoint {
					txid: txid.clone(),
					vout: vout as u32,
				},
				value,
				height: 1,
			});
			funding_txs.insert(tx.txid(), tx);
		}

		let redeem_address = Address::p2pkh(
			&BTCPublicKey {
				compressed: true,
				key: PublicKey::from_secret_key(&secp, &SecretKey::new(rng)).unwrap(),
			},
			btc_network(network),
		);

		// Generate redeem transaction
		let (_btc_tx, tx, est_size, actual_size) = data
			.build_redeem_tx(
				&Currency::Btc,
				&secp,
				&redeem_address.to_string(),
				&input_script,
				10.0,
				&cosign,
				&redeem,
				&confirmed_outputs,
			)
			.unwrap();
		let diff = (est_size as i64 - actual_size as i64).abs() as usize;
		assert!(diff <= count); // Our size estimation should be very close to the real size

		// Moment of truth: our redeem tx should be valid
		tx.verify(&funding_txs).unwrap();
	}
}
