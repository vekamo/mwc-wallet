// Copyright 2020 The MWC Develope;
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

//! Generic implementation libp2p related communication functionality

use crate::grin_util::secp::key::SecretKey;
use crate::grin_util::Mutex;

use crate::api_impl::{foreign, owner};
use crate::grin_keychain::Keychain;
use crate::internal::{keys, updater};
use crate::swap::error::ErrorKind;
use crate::types::NodeClient;
use crate::Context;
use crate::{wallet_lock, WalletInst, WalletLCProvider};
use crate::{AcctPathMapping, Error, InitTxArgs, OutputCommitMapping, OutputStatus};
use grin_core::core::hash::Hash;
use grin_core::libtx::{aggsig, tx_fee};
use grin_core::ser;
use grin_keychain::{ExtKeychainPath, Identifier};
use grin_util::secp;
use grin_util::secp::pedersen::Commitment;
use grin_util::secp::{Message, PublicKey};
use grin_wallet_util::grin_util::secp::Signature;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// Identity Index for integrity account. Let's put it at the end, so we can be sure that it exist
pub const INTEGRITY_ACCOUNT_ID: u32 = 65534;
/// account name for integrity outputs
pub const INTEGRITY_ACCOUNT_NAME: &str = "integrity";
/// Number of top block when integrity fee is valid
pub const INTEGRITY_FEE_VALID_BLOCKS: u64 = 1440;
/// Minimum integrity fee value in term of Base fees
pub const INTEGRITY_FEE_MIN_X: u64 = 10;

/// Integral fee proof data. It build form the both contexts and a transaction.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IntegrityContext {
	/// Sender account id. Might be needed to request a transaction detail
	pub sender_parent_key_id: Identifier,
	/// Transaction details
	pub tx_uuid: Uuid,
	/// Fee that was paid to miners
	pub fee: u64,

	/// Secret key (of which public is shared)
	pub sec_key0: SecretKey,
	/// Secret nonce (of which public is shared)
	/// (basically a SecretKey)
	pub sec_nonce0: SecretKey,
	/// Secret key (of which public is shared)
	pub sec_key1: SecretKey,
	/// Secret nonce (of which public is shared)
	/// (basically a SecretKey)
	pub sec_nonce1: SecretKey,
}

impl IntegrityContext {
	// context0 - sender context, participant id 0
	// context1 - receiver context, participant id 1
	/// Build context needed to generate signature for the kernel excess (public key)
	pub fn build(tx_uuid: &Uuid, fee: u64, context0: &Context, context1: &Context) -> Self {
		Self {
			sender_parent_key_id: context0.parent_key_id.clone(),
			tx_uuid: tx_uuid.clone(),
			fee,

			sec_key0: context0.sec_key.clone(),
			sec_nonce0: context0.sec_nonce.clone(),

			sec_key1: context1.sec_key.clone(),
			sec_nonce1: context1.sec_nonce.clone(),
		}
	}

	// see for details: pub fn calc_excess<K>(&self, keychain: Option<&K>) -> Result<Commitment, Error>
	/// Calculate a kernel commit for this context, sign the message that can be verifiable with this context
	pub fn calc_kernel_excess(
		&self,
		secp: &secp::Secp256k1,
		message: &Message,
	) -> Result<(Commitment, Signature), Error> {
		// This magic comes from the slate
		let pub_key0 = PublicKey::from_secret_key(secp, &self.sec_key0)?;
		let pub_key1 = PublicKey::from_secret_key(secp, &self.sec_key1)?;

		let pub_nonce0 = PublicKey::from_secret_key(secp, &self.sec_nonce0)?;
		let pub_nonce1 = PublicKey::from_secret_key(secp, &self.sec_nonce1)?;

		// It is kernel commit
		let pub_blind_sum = PublicKey::from_combination(vec![&pub_key0, &pub_key1])?;
		// It is PK to sign the message...
		let pub_nonce_sum = PublicKey::from_combination(vec![&pub_nonce0, &pub_nonce1])?;

		// Building signature...
		//let msg_hash = Hash::from_vec(message);
		//let msg_message = Message::from_slice(msg_hash.as_bytes())?;

		let signature1 = aggsig::calculate_partial_sig(
			secp,
			&self.sec_key1,
			&self.sec_nonce1,
			&pub_nonce_sum,
			Some(&pub_blind_sum),
			message,
		)?;

		let signature0 = aggsig::calculate_partial_sig(
			secp,
			&self.sec_key0,
			&self.sec_nonce0,
			&pub_nonce_sum,
			Some(&pub_blind_sum),
			message,
		)?;

		let final_sig =
			aggsig::add_signatures(secp, vec![&signature0, &signature1], &pub_nonce_sum)?;

		#[cfg(debug_assertions)]
		{
			// Sanity check is done for debug build only
			aggsig::verify_completed_sig(
				secp,
				&final_sig,
				&pub_blind_sum,
				Some(&pub_blind_sum),
				&message,
			)?;
		}

		let kernel_excess = Commitment::from_pubkey(&pub_blind_sum)?;
		Ok((kernel_excess, final_sig))
	}
}

impl ser::Writeable for IntegrityContext {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let data = serde_json::to_vec(self).map_err(|e| {
			ser::Error::CorruptedData(format!("IntegrityContext to json conversion failed, {}", e))
		})?;
		if data.len() > ser::READ_CHUNK_LIMIT {
			return Err(ser::Error::TooLargeWriteErr(format!(
				"IntegrityContext data length is {}",
				data.len()
			)));
		}

		writer.write_bytes(&data)
	}
}

impl ser::Readable for IntegrityContext {
	fn read<R: ser::Reader>(reader: &mut R) -> Result<IntegrityContext, ser::Error> {
		let data = reader.read_bytes_len_prefix()?;
		serde_json::from_slice(&data[..]).map_err(|e| {
			ser::Error::CorruptedData(format!("json to IntegrityContext conversion failed, {}", e))
		})
	}
}

/// Start swap trade process. Return SwapID that can be used to check the status or perform further action.
/// Return <integrity account>, <unspent outputs>, <tip height>, <(best valid fee context, confirmed, height until fee is valid)>
pub fn get_integral_balance<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
) -> Result<
	(
		Option<AcctPathMapping>,
		Vec<OutputCommitMapping>,
		u64,
		Vec<(IntegrityContext, bool, u64)>,
	),
	Error,
>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);

	let integrity_account = w
		.acct_path_iter()
		.filter(|a| {
			u32::from(ExtKeychainPath::from_identifier(&a.path).path[0]) == INTEGRITY_ACCOUNT_ID
		})
		.next();
	if integrity_account.is_none() {
		return Ok((None, vec![], 0, vec![]));
	}

	let integrity_account = integrity_account.unwrap();
	let mut outputs = updater::retrieve_outputs(
		&mut **w,
		keychain_mask,
		false,
		None,
		&integrity_account.path,
		None,
		None,
	)?;

	outputs.retain(|o| o.output.status == OutputStatus::Unspent);

	// Let's check if fee already paid.
	let log_entry = updater::retrieve_txs(
		&mut **w,
		keychain_mask,
		None,
		None,
		Some(&integrity_account.path),
		false,
		None,
		None,
	)?;

	let tip_height = {
		let client = w.w2n_client();
		client.get_chain_tip()?.0
	};

	let mut tx_uuid: HashMap<Uuid, (bool, u64)> = HashMap::new();

	// Checking log entry in THIS side only. But we still need to handle receive transactions because of the fees.
	// And we need to provide both contexts for every transaction.
	// Note in case of receive transaction, we will return the send from another account.
	// Reason: Tx Kernel & fees.
	for log_entry in log_entry {
		let height = if log_entry.confirmed {
			log_entry.output_height
		} else {
			log_entry.kernel_lookup_min_height.unwrap_or(0)
		};
		if log_entry.tx_slate_id.is_none()
			|| height < tip_height - INTEGRITY_FEE_VALID_BLOCKS
			|| log_entry.is_cancelled()
		{
			continue;
		}

		tx_uuid.insert(
			log_entry.tx_slate_id.unwrap(),
			(log_entry.confirmed, height),
		);
	}

	let mut integrity_tx: Vec<(IntegrityContext, bool, u64)> = Vec::new();
	for (uuid, (confirmed, height)) in tx_uuid {
		// Requesting both contexts...
		let integrity_context = {
			let mut batch = w.batch(keychain_mask)?;
			match batch.load_integrity_context(uuid.as_bytes()) {
				Ok(ctx) => ctx,
				Err(_) => continue,
			}
		};
		integrity_tx.push((
			integrity_context,
			confirmed,
			height + INTEGRITY_FEE_VALID_BLOCKS,
		));
	}

	Ok((Some(integrity_account), outputs, tip_height, integrity_tx))
}

/// Create integral kernel if needed. Return back the fee and height.
/// Height will be none if transaction note mined yet.
/// Return: Integrity context, confirmed flag, height until fee is valid
pub fn create_integral_balance<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	amount: u64,
	fee: &Vec<u64>, // We might have several message threads that runs in parallel. The fee need to be paid for each of them
	account_from: &Option<String>,
) -> Result<Vec<(Option<IntegrityContext>, bool, u64)>, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	debug_assert!(amount > *fee.iter().max().unwrap());

	let (account, outputs, tip_height, mut transactions) =
		get_integral_balance(wallet_inst.clone(), keychain_mask)?;

	// Let's try to satisfy the requirements..
	let mut results: Vec<(Option<IntegrityContext>, bool, u64)> = Vec::new();
	// Sorting because we want to apply the best choice (minimal fee that is needed) first
	transactions.sort_by(|t1, t2| t1.0.fee.partial_cmp(&t2.0.fee).unwrap());

	for f in fee {
		match transactions.iter().position(|tx| tx.0.fee >= *f) {
			Some(idx) => {
				let (c, conf, height_until) = transactions.remove(idx);
				results.push((Some(c), conf, height_until));
			}
			None => results.push((None, false, 0)),
		}
	}

	// Check if integrity outputs still in the waiting state
	if outputs
		.iter()
		.find(|o| o.output.status == OutputStatus::Unconfirmed)
		.is_some()
	{
		return Ok(results);
	}

	for i in 0..fee.len() {
		if results[i].0.is_some() {
			continue;
		}

		let fee = fee[i];

		// Found that some fee we can pay now. Will process only one transaction

		wallet_lock!(wallet_inst, w);

		if account.is_none() {
			// Creating integrity account
			let path = ExtKeychainPath::new(2, INTEGRITY_ACCOUNT_ID, 0, 0, 0).to_identifier();
			let label = INTEGRITY_ACCOUNT_NAME.to_string();
			keys::set_acct_path(&mut **w, keychain_mask, &label, &path)?;
		};

		let total_amount: u64 = outputs.iter().map(|o| o.output.value).sum();
		let mut amount = amount;
		let src_account_name = if total_amount < fee {
			// Need move some coins here
			account_from.clone().unwrap_or("default".to_string())
		} else {
			amount = total_amount;
			INTEGRITY_ACCOUNT_NAME.to_string()
		};

		let mut args = InitTxArgs::default();
		args.src_acct_name = Some(src_account_name.clone());
		args.amount = amount - fee;
		args.minimum_confirmations = 1;
		args.target_slate_version = Some(4); // Need Compact slate
		args.address = Some("Integrity fee".to_string());
		args.min_fee = Some(fee);
		args.ttl_blocks = Some(3);
		args.late_lock = Some(true);

		let slate = owner::init_send_tx(&mut **w, keychain_mask, &args, false, 1)?;

		owner::tx_lock_outputs(
			&mut **w,
			keychain_mask,
			&slate,
			args.address.clone(),
			0,
			false,
		)?;

		let (slate, context1) = foreign::receive_tx(
			&mut **w,
			keychain_mask,
			&slate,
			args.address.clone(),
			None,
			None,
			Some(INTEGRITY_ACCOUNT_NAME),
			None,
			false,
			false,
		)?;

		let (slate, context0) = owner::finalize_tx(&mut **w, keychain_mask, &slate, false, false)?;

		// Posting transaction...
		owner::post_tx(w.w2n_client(), &slate.tx, false)?;

		// Build and store integral fee data...
		let integrity_context = IntegrityContext::build(&slate.id, slate.fee, &context0, &context1);
		{
			let mut batch = w.batch(keychain_mask)?;
			batch.save_integrity_context(slate.id.as_bytes(), &integrity_context)?;
			batch.commit()?;
		}

		#[cfg(debug_assertions)]
		{
			// Let's run some test while we are in debug mode. Building full test is hard. We don't have self transactions tests
			// Let's check if the context is valid
			let keychain = w.keychain(keychain_mask)?;
			let kernel = &slate.tx.body.kernels[0];
			let (excess, signature) =
				integrity_context.calc_kernel_excess(keychain.secp(), &kernel.msg_to_sign()?)?;

			debug_assert_eq!(excess, kernel.excess);
			debug_assert_eq!(signature, kernel.excess_sig);

			// Checking if we can generate another signature and them validate it.
			let test_msg_hash = Hash::from_vec(&vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
			let test_message = Message::from_slice(test_msg_hash.as_bytes())?;

			// Generation (on wallet side) and verity (mwc-node) side
			let secp = secp::Secp256k1::new();
			let (excess, signature) = integrity_context.calc_kernel_excess(&secp, &test_message)?;
			debug_assert_eq!(excess, kernel.excess);
			let pk_to_check = excess.to_pubkey()?;

			aggsig::verify_completed_sig(
				&secp,
				&signature,
				&pk_to_check,
				Some(&pk_to_check),
				&test_message,
			)?;
		}

		results[i] = (
			Some(integrity_context),
			false,
			tip_height + INTEGRITY_FEE_VALID_BLOCKS,
		);
		break; // Processing only one iteration at a time
	}

	Ok(results)
}

/// Move all integral coins back to some account.
pub fn withdraw_integral_balance<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	account_withdraw_to: &String,
) -> Result<u64, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let (_account, outputs, _tip_height, _transactions) =
		get_integral_balance(wallet_inst.clone(), keychain_mask)?;

	if outputs.is_empty() {
		return Ok(0);
	}

	wallet_lock!(wallet_inst, w);

	let total_amount: u64 = outputs.iter().map(|o| o.output.value).sum();
	let fee = tx_fee(outputs.len(), 1, 1, None);
	if total_amount <= fee {
		return Err(ErrorKind::Generic("Reserved amount for Integrity fees is smaller then a transaction fee. It is impossible to move dust funds.".to_string()).into());
	}

	let mut args = InitTxArgs::default();
	args.src_acct_name = Some(INTEGRITY_ACCOUNT_NAME.to_string());
	args.amount = total_amount - fee;
	args.minimum_confirmations = 1;
	args.target_slate_version = Some(4); // Need Compact slate
	args.address = Some("Withdraw Integrity funds".to_string());
	args.ttl_blocks = Some(3);
	args.late_lock = Some(true);

	let slate = owner::init_send_tx(&mut **w, keychain_mask, &args, false, 1)?;

	let (slate, _context2) = foreign::receive_tx(
		&mut **w,
		keychain_mask,
		&slate,
		args.address.clone(),
		None,
		None,
		Some(account_withdraw_to),
		None,
		false,
		false,
	)?;

	// Lock is skipped because we have lock later flag

	let (slate, _context1) = owner::finalize_tx(&mut **w, keychain_mask, &slate, false, false)?;

	// Posting transaction...
	owner::post_tx(w.w2n_client(), &slate.tx, false)?;

	Ok(args.amount)
}
