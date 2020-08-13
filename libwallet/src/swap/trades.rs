// Copyright 2020 The MWC Developers
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

use super::ErrorKind;
use crate::swap::types::Context;
use crate::swap::Swap;
use base64;
use grin_util::secp::key::SecretKey;
use grin_util::{from_hex, to_hex};
use grin_util::{Mutex, RwLock};
use rand::{thread_rng, Rng};
use ring::aead;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

/// Lacation of the swaps states
pub const SWAP_DEAL_SAVE_DIR: &'static str = "saved_swap_deal";

lazy_static! {
	static ref TRADE_DEALS_PATH: RwLock<Option<PathBuf>> = RwLock::new(None);
	static ref ELECTRUM_X_URI: RwLock<Option<HashMap<String, String>>> = RwLock::new(None);
	// Locks for the swap reads. Note, all instances are in the memory, we don't expect too many of them
	static ref SWAP_LOCKS: RwLock<HashMap< String, Arc<Mutex<()>>>> = RwLock::new(HashMap::new());
}

/// Init for file storage for saving swap deals
pub fn init_swap_trade_backend(data_file_dir: &str, electrumx_uri: HashMap<String, String>) {
	let stored_swap_deal_path = Path::new(data_file_dir).join(SWAP_DEAL_SAVE_DIR);
	fs::create_dir_all(&stored_swap_deal_path)
		.expect("Could not create swap deal storage directory!");

	TRADE_DEALS_PATH.write().replace(stored_swap_deal_path);

	if electrumx_uri.capacity() > 0 {
		ELECTRUM_X_URI.write().replace(electrumx_uri);
	}
}

/// Get ElextrumX URL.
pub fn get_electrumx_uri() -> Option<HashMap<String, String>> {
	ELECTRUM_X_URI.read().clone()
}

/// List available swap trades.
pub fn list_swap_trades() -> Result<Vec<String>, ErrorKind> {
	let mut result: Vec<String> = Vec::new();

	for entry in fs::read_dir(TRADE_DEALS_PATH.read().clone().unwrap())? {
		let entry = entry?;
		if let Some(name) = entry.file_name().to_str() {
			if name.ends_with(".swap") {
				let name = String::from(name.split(".swap").next().unwrap_or("?"));
				result.push(name);
			}
		}
	}
	Ok(result)
}

/// Caller suppose to lock the swap object first before call other swap related functions.
pub fn get_swap_lock(swap_id: &String) -> Arc<Mutex<()>> {
	let mut swap_lock_hash = SWAP_LOCKS.write();
	match swap_lock_hash.get(swap_id) {
		Some(l) => l.clone(),
		None => {
			let l = Arc::new(Mutex::new(()));
			swap_lock_hash.insert(swap_id.to_string(), l.clone());
			l
		}
	}
}

/// Remove swap trade record.
/// Note! You don't want to remove the non compelete deal. You can loose funds because of that.
pub fn delete_swap_trade(
	swap_id: &str,
	dec_key: &SecretKey,
	lock: &Mutex<()>,
) -> Result<(), ErrorKind> {
	if lock.try_lock().is_some() {
		return Err(ErrorKind::Generic(format!(
			"delete_swap_trade processing unlocked instance {}",
			swap_id
		)));
	}

	let (_context, swap) = get_swap_trade(swap_id, dec_key, lock)?;
	if !swap.state.is_final_state() {
		return Err(ErrorKind::Generic(format!(
			"Swap {} is still in the progress. Please finish or cancel this trade",
			swap_id
		)));
	}

	let target_path = TRADE_DEALS_PATH
		.read()
		.clone()
		.unwrap()
		.join(format!("{}.swap", swap_id));
	let deleted_path = TRADE_DEALS_PATH
		.read()
		.clone()
		.unwrap()
		.join(format!("{}.swap.del", swap_id));

	fs::rename(target_path, deleted_path).map_err(|e| {
		ErrorKind::TradeIoError(swap_id.to_string(), format!("Unable to delete, {}", e))
	})?;
	Ok(())
}

/// Get swap trade from the storage.
/// Mutex is provided for the locking. We want to restrict an access to it
pub fn get_swap_trade(
	swap_id: &str,
	dec_key: &SecretKey,
	lock: &Mutex<()>,
) -> Result<(Context, Swap), ErrorKind> {
	if lock.try_lock().is_some() {
		return Err(ErrorKind::Generic(format!(
			"get_swap_trade processing unlocked instance {}",
			swap_id
		)));
	}

	let path = TRADE_DEALS_PATH
		.read()
		.clone()
		.unwrap()
		.join(format!("{}.swap", swap_id));
	if !path.exists() {
		return Err(ErrorKind::TradeNotFound(swap_id.to_string()));
	}
	let mut swap_deal_f = File::open(path.clone()).map_err(|e| {
		ErrorKind::TradeIoError(
			swap_id.to_string(),
			format!("Unable to open file {}, {}", path.to_str().unwrap(), e),
		)
	})?;
	let mut content = String::new();
	swap_deal_f.read_to_string(&mut content).map_err(|e| {
		ErrorKind::TradeIoError(
			swap_id.to_string(),
			format!("Unable to read data from {}, {}", path.to_str().unwrap(), e),
		)
	})?;
	let enc_swap_content: EncryptedSwap = serde_json::from_str(&content)?;
	let dec_swap_content = enc_swap_content.decrypt(&dec_key)?;

	let mut split = dec_swap_content.split("<#>");

	let context_str = split.next();
	let swap_str = split.next();

	if context_str.is_none() || swap_str.is_none() {
		return Err(ErrorKind::TradeIoError(
			swap_id.to_string(),
			"Not found all packages".to_string(),
		));
	}

	let context: Context = serde_json::from_str(context_str.unwrap()).map_err(|e| {
		ErrorKind::TradeIoError(
			swap_id.to_string(),
			format!("Unable to parce Swap data from Json, {}", e),
		)
	})?;
	let swap: Swap = serde_json::from_str(swap_str.unwrap()).map_err(|e| {
		ErrorKind::TradeIoError(
			swap_id.to_string(),
			format!("Unable to parce Swap data from Json, {}", e),
		)
	})?;

	Ok((context, swap))
}

/// Store swap deal to a file
pub fn store_swap_trade(
	context: &Context,
	swap: &Swap,
	enc_key: &SecretKey,
	lock: &Mutex<()>,
) -> Result<(), ErrorKind> {
	if lock.try_lock().is_some() {
		return Err(ErrorKind::Generic(format!(
			"store_swap_trade processing unlocked instance {}",
			swap.id
		)));
	}

	// Writing to bak file. We don't want to loose the data in case of failure. It least the prev step will be left
	let swap_id = swap.id.to_string();
	let mut rng = thread_rng();
	let r: u64 = rng.gen();
	let path = TRADE_DEALS_PATH
		.read()
		.clone()
		.unwrap()
		.join(format!("{}.swap_{}.bak", swap_id, r));
	{
		let mut stored_swap = File::create(path.clone()).map_err(|e| {
			ErrorKind::TradeIoError(
				swap_id.clone(),
				format!(
					"Unable to create the file {} to store swap trade, {}",
					path.to_str().unwrap(),
					e
				),
			)
		})?;

		let context_ser = serde_json::to_string(context).map_err(|e| {
			ErrorKind::TradeIoError(
				swap_id.clone(),
				format!("Unable to convert context to Json, {}", e),
			)
		})?;
		let swap_ser = serde_json::to_string(swap).map_err(|e| {
			ErrorKind::TradeIoError(
				swap_id.clone(),
				format!("Unable to convert swap to Json, {}", e),
			)
		})?;
		let res_str = context_ser + "<#>" + swap_ser.as_str();
		let encrypted_swap = EncryptedSwap::from_json(&res_str, enc_key)?;
		let enc_swap_ser = serde_json::to_string(&encrypted_swap).map_err(|e| {
			ErrorKind::TradeEncDecError(format!("Unable to serialize encrypted swap, {}", e))
		})?;

		stored_swap
			.write_all(&enc_swap_ser.as_bytes())
			.map_err(|e| {
				ErrorKind::TradeIoError(
					swap_id.clone(),
					format!(
						"Unable to write swap deal to file {}, {}",
						path.to_str().unwrap(),
						e
					),
				)
			})?;
		stored_swap.sync_all().map_err(|e| {
			ErrorKind::TradeIoError(
				swap_id.clone(),
				format!(
					"Unable to sync file {} all after writing swap deal, {}",
					path.to_str().unwrap(),
					e
				),
			)
		})?;
	}

	let path_target = TRADE_DEALS_PATH
		.read()
		.clone()
		.unwrap()
		.join(format!("{}.swap", swap.id.to_string()));
	fs::rename(path, path_target).map_err(|e| {
		ErrorKind::TradeIoError(
			swap_id.clone(),
			format!("Unable to finalize writing, rename failed with error {}", e),
		)
	})?;

	Ok(())
}

/// Dump the content of swap file
pub fn dump_swap_trade(
	swap_id: &str,
	dec_key: &SecretKey,
	lock: &Mutex<()>,
) -> Result<String, ErrorKind> {
	if lock.try_lock().is_some() {
		return Err(ErrorKind::Generic(format!(
			"dump_swap_trade processing unlocked instance {}",
			swap_id
		)));
	}

	let path = TRADE_DEALS_PATH
		.read()
		.clone()
		.unwrap()
		.join(format!("{}.swap", swap_id));
	if !path.exists() {
		return Err(ErrorKind::TradeNotFound(swap_id.to_string()));
	}
	let mut swap_deal_f = File::open(path.clone()).map_err(|e| {
		ErrorKind::TradeIoError(
			swap_id.to_string(),
			format!("Unable to open file {}, {}", path.to_str().unwrap(), e),
		)
	})?;
	let mut content = String::new();
	swap_deal_f.read_to_string(&mut content).map_err(|e| {
		ErrorKind::TradeIoError(
			swap_id.to_string(),
			format!("Unable to read data from {}, {}", path.to_str().unwrap(), e),
		)
	})?;
	let enc_swap_content: EncryptedSwap = serde_json::from_str(&content)?;
	let dec_swap_content = enc_swap_content.decrypt(&dec_key)?;

	Ok(dec_swap_content)
}

/// Encrypt and decrypt swap files
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedSwap {
	/// nonce used for encryption
	pub nonce: String,
	/// Encrypted base64 body swap + context
	pub body_enc: String,
}

impl EncryptedSwap {
	/// Encrypts and encodes json as base 64
	pub fn from_json(json_in: &String, enc_key: &SecretKey) -> Result<Self, ErrorKind> {
		let mut to_encrypt = serde_json::to_string(&json_in)
			.map_err(|e| {
				ErrorKind::TradeEncDecError(format!(
					"EncryptSwap Enc: unable to encode Json, {}",
					e
				))
			})?
			.as_bytes()
			.to_vec();

		let nonce: [u8; 12] = thread_rng().gen();
		let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &enc_key.0)
			.map_err(|e| ErrorKind::Generic(format!("Unable to build a key, {}", e)))?;
		let sealing_key: aead::LessSafeKey = aead::LessSafeKey::new(unbound_key);
		let aad = aead::Aad::from(&[]);
		let res = sealing_key.seal_in_place_append_tag(
			aead::Nonce::assume_unique_for_key(nonce),
			aad,
			&mut to_encrypt,
		);
		if let Err(e) = res {
			return Err(ErrorKind::TradeEncDecError(format!(
				"EncryptedSwap Enc: Encryption failed, {}",
				e
			))
			.into());
		}

		Ok(EncryptedSwap {
			nonce: to_hex(nonce.to_vec()),
			body_enc: base64::encode(&to_encrypt),
		})
	}

	/// Decrypts and returns the original swap+context
	pub fn decrypt(&self, dec_key: &SecretKey) -> Result<String, ErrorKind> {
		let mut to_decrypt = base64::decode(&self.body_enc).map_err(|e| {
			ErrorKind::TradeEncDecError(format!(
				"EncryptedSwap Dec: Encrypted swap contains invalid Base64, {}",
				e
			))
		})?;

		let nonce = from_hex(&self.nonce).map_err(|e| {
			ErrorKind::TradeEncDecError(format!(
				"EncryptedSwap Dec: Encrypted request contains invalid nonce, {}",
				e
			))
		})?;
		if nonce.len() < 12 {
			return Err(ErrorKind::TradeEncDecError(
				"EncryptedSwap Dec: Invalid Nonce length".to_string(),
			)
			.into());
		}

		let mut n = [0u8; 12];
		n.copy_from_slice(&nonce[0..12]);
		let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &dec_key.0)
			.map_err(|e| ErrorKind::Generic(format!("Unable to build a key, {}", e)))?;
		let opening_key: aead::LessSafeKey = aead::LessSafeKey::new(unbound_key);
		let aad = aead::Aad::from(&[]);

		opening_key
			.open_in_place(aead::Nonce::assume_unique_for_key(n), aad, &mut to_decrypt)
			.map_err(|e| {
				ErrorKind::TradeEncDecError(format!("EncryptedSwap Dec: Decryption failed, {}", e))
			})?;

		for _ in 0..aead::AES_256_GCM.tag_len() {
			to_decrypt.pop();
		}

		let decrypted = String::from_utf8(to_decrypt).map_err(|_| {
			ErrorKind::TradeEncDecError("EncryptedSwap Dec: Invalid UTF-8".to_string())
		})?;

		Ok(serde_json::from_str(&decrypted).map_err(|e| {
			ErrorKind::TradeEncDecError(format!("EncryptedSwap Dec: Invalid JSON, {}", e))
		})?)
	}
}
