// Copyright 2020 The Grin Developers
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

use crate::Error;
use crate::{Slate, SlateVersion, Slatepack, SlatepackArmor};

use ed25519_dalek::SecretKey as DalekSecretKey;
use x25519_dalek::PublicKey as xDalekPublicKey;

use crate::slatepack::slatepack::SlatePurpose;
use uuid::Uuid;

#[derive(Clone, Debug)]
/// Arguments, mostly for encrypting decrypting a slatepack
pub struct Slatepacker {
	/// Working context.
	context: Slatepack,
}

impl Slatepacker {
	/// Swap a slate with the packer. Slate is expecte to be full
	pub fn wrap_slate(slate: Slate) -> Self {
		Slatepacker {
			context: Slatepack {
				sender: None,
				recipients: vec![],
				content: SlatePurpose::FullSlate,
				slate,
			},
		}
	}

	/// Pack everything into the armored slatepack
	pub fn encrypt_to_send(
		slate: &Slate,
		slate_version: SlateVersion,
		content: SlatePurpose,
		sender: &Option<xDalekPublicKey>,
		recipients: &Vec<xDalekPublicKey>,
	) -> Result<String, Error> {
		let pack = Slatepack {
			sender: sender.clone(),
			recipients: recipients.clone(),
			content,
			slate: slate.clone(),
		};

		let slate_bin = pack.to_binary(slate_version)?;

		SlatepackArmor::encode(&slate_bin)
	}

	/// return slatepack
	pub fn decrypt_slatepack(data: &[u8], dec_key: Option<&DalekSecretKey>) -> Result<Self, Error> {
		let slate_bytes = SlatepackArmor::decode(data)?;

		let slatepack = Slatepack::from_binary(&slate_bytes, dec_key)?;

		Ok(Self { context: slatepack })
	}

	/// Get Transaction ID related into form this slatepack
	pub fn get_tx_info(&self) -> (Uuid, SlatePurpose) {
		(self.context.slate.id.clone(), self.context.content.clone())
	}

	/// Get Sender info. It is needed to send the response back
	pub fn get_sender(&self) -> Option<xDalekPublicKey> {
		self.context.sender.clone()
	}

	/// Convert this slate back to the resulting slate. Since the slate pack contain only the change set,
	/// to recover the data it is required original slate to merge with.
	pub fn to_result_slate(self) -> Slate {
		self.context.slate
	}
}

#[test]
fn slatepack_io_test() {
	use crate::grin_util as util;
	use crate::grin_util::secp::Signature;
	use crate::proof::proofaddress::ProvableAddress;
	use crate::slate::{PaymentInfo, VersionCompatInfo};
	use crate::ParticipantData;
	use grin_core::core::KernelFeatures;
	use grin_core::core::{Input, Output, OutputFeatures, Transaction, TxKernel};
	use grin_core::global;
	use grin_keychain::ExtKeychain;
	use grin_util::secp::pedersen::{Commitment, RangeProof};
	use grin_util::secp::{PublicKey, Secp256k1, SecretKey};
	use grin_wallet_util::grin_keychain::BlindingFactor;

	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

	let bytes_16: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
	let bytes_32: [u8; 32] = [
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
		26, 27, 28, 29, 30, 31, 32,
	];
	let bytes_33: [u8; 33] = [
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
		26, 27, 28, 29, 30, 31, 32, 33,
	];
	let bytes_64: [u8; 64] = [
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
		26, 27, 28, 29, 30, 31, 32, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
		19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	];

	let sk = SecretKey::from_slice(&bytes_32).unwrap();
	let secp = Secp256k1::new();

	let mut slate = Slate {
		compact_slate: true, // Slatepack works only for compact models.
		num_participants: 2,
		id: Uuid::from_bytes(bytes_16),
		tx: Transaction::empty()
			.with_offset(BlindingFactor::from_slice(&bytes_32) )
			.with_input( Input::new( OutputFeatures::Plain, Commitment(bytes_33)) )
			.with_output( Output::new(OutputFeatures::Plain, Commitment(bytes_33), RangeProof::zero()))
			.with_kernel( TxKernel::with_features(KernelFeatures::Plain { fee: 321 }) ),
		offset: BlindingFactor::from_slice(&bytes_32),
		amount: 30000000000000000,
		fee: 321,
		height: 67,
		lock_height: 0,
		ttl_cutoff_height: Some(54),
		coin_type: None, // N/A for slatepack
		network_type: None, // N/A  build in at SP
		participant_data: vec![
			ParticipantData {
				id: 0,
				public_blind_excess: PublicKey::from_secret_key( &secp, &sk).unwrap(),
				public_nonce:  PublicKey::from_secret_key( &secp, &sk).unwrap(),
				part_sig: None,
				message: Some("message 1 to send".to_string()),
				message_sig: None, // N/A
			},
			ParticipantData {
				id: 1,
				public_blind_excess: PublicKey::from_secret_key( &secp, &sk).unwrap(),
				public_nonce:  PublicKey::from_secret_key( &secp, &sk).unwrap(),
				part_sig: Some(Signature::from_compact(&util::from_hex("89cc3c1480fea655f29d300fcf68d0cfbf53f96a1d6b1219486b64385ed7ed89acf96f1532b31ac8309e611583b1ecf37090e79700fae3683cf682c0043b3029").unwrap()).unwrap()),
				message: Some("message 2 to send".to_string()),
				message_sig: None, // N/A
			}
		],
		version_info: VersionCompatInfo {
			version: 3,
			block_header_version: 1,
		},
		payment_proof: Some(PaymentInfo {
				sender_address: ProvableAddress::from_str("a5ib4b2l5snzdgxzpdzouwxwvn4c3setpp5t5j2tr37n3uy3665qwnqd").unwrap(),
				receiver_address: ProvableAddress::from_str("a5ib4b2l5snzdgxzpdzouwxwvn4c3setpp5t5j2tr37n3uy3665qwnqd").unwrap(),
				receiver_signature: Some( util::to_hex(&bytes_64) ),
		}),
	};
	// updating kernel excess
	slate.tx.body.kernels[0].excess = slate.calc_excess::<ExtKeychain>(None).unwrap();

	let slate1_str = format!("{:?}", slate);
	println!("start slate = {}", slate1_str);

	// Not encoded, just want to review the data...
	let slatepack_string = Slatepacker::encrypt_to_send(
		&slate,
		SlateVersion::SP,
		SlatePurpose::FullSlate,
		&Some(xDalekPublicKey::from(bytes_32)),
		&vec![],
	)
	.unwrap();
	println!("slatepack_string = {}", slatepack_string);

	let slatepack = Slatepacker::decrypt_slatepack(slatepack_string.as_bytes(), None).unwrap();
	let res_slate = slatepack.to_result_slate();
	let slate2_str = format!("{:?}", res_slate);
	println!("res_slate = {:?}", slate2_str);

	assert_eq!(slate1_str, slate2_str);
}
