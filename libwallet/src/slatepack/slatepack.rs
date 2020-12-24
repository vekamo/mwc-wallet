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

/// Slatepack Types + Serialization implementation
use ed25519_dalek::{PublicKey as DalekPublicKey, SecretKey as DalekSecretKey, PUBLIC_KEY_LENGTH};
use x25519_dalek::PublicKey as xDalekPublicKey;

use crate::grin_util::secp::key::PublicKey;

use sha2::{Digest, Sha512};
use x25519_dalek::StaticSecret;

use crate::{Error, ErrorKind};
use crate::{ParticipantData, Slate, SlateVersion};

use crate::proof::proofaddress::ProvableAddress;
use std::io;
use std::io::{Read, Write};

use crate::slate::PaymentInfo;
use bitstream_io::{BigEndian, BitReader, BitWriter, Endianness};
use grin_core::core::{
	Input, Inputs, KernelFeatures, Output, OutputFeatures, OutputIdentifier, TxKernel,
};
use grin_core::global;
use grin_keychain::{BlindingFactor, ExtKeychain};
use grin_util::secp::constants::{PEDERSEN_COMMITMENT_SIZE, SECRET_KEY_SIZE};
use grin_util::secp::pedersen::{Commitment, RangeProof};
use grin_util::secp::Signature;
use grin_util::{from_hex, to_hex};
use grin_wallet_util::grin_core::core::CommitWrapper;
use grin_wallet_util::grin_util::static_secp_instance;
use smaz;
use uuid::Uuid;

/// Basic Slatepack definition
#[derive(Debug, Clone)]
pub struct Slatepack {
	// Optional Fields
	/// Optional Sender address
	pub sender: Option<xDalekPublicKey>,
	/// Optional recipient addresses.
	pub recipients: Vec<xDalekPublicKey>,
	/// The content purpose. It customize serializer/deserializer for us.
	pub content: SlatePurpose,

	/// Slate data.
	pub slate: Slate,
}

/// Slate state definition
#[derive(Debug, Clone)]
pub enum SlatePurpose {
	/// Standard flow, freshly init
	SendSend,
	/// Standard flow, return journey
	SendResponse,
	///Invoice flow, init
	InvoiceSend,
	///Invoice flow, return journey
	InvoiceResponse,
	///Invoice optional return (full slate is encoded, just for caller)
	FullSlate,
}

impl SlatePurpose {
	/// Create from integer value
	pub fn from_int(i: u8) -> Result<Self, Error> {
		let res: Self = match i {
			0 => SlatePurpose::SendSend,
			1 => SlatePurpose::SendResponse,
			2 => SlatePurpose::InvoiceSend,
			3 => SlatePurpose::InvoiceResponse,
			4 => SlatePurpose::FullSlate,
			_ => {
				return Err(ErrorKind::SlatepackDecodeError(format!(
					"SlatePackPurpose wrong value {}",
					i
				))
				.into())
			}
		};
		Ok(res)
	}

	/// Convert to integer value
	pub fn to_int(&self) -> u8 {
		match self {
			SlatePurpose::SendSend => 0,
			SlatePurpose::SendResponse => 1,
			SlatePurpose::InvoiceSend => 2,
			SlatePurpose::InvoiceResponse => 3,
			SlatePurpose::FullSlate => 4,
		}
	}
}

impl Slatepack {
	/// Decode and decrypt the Slatepack
	/// Note:  from_binary & to_binary - are NOT serializers, minimum amount of the data is transported.
	/// from_binary & to_binary are symmetrical
	pub fn from_binary(data: &Vec<u8>, dec_key: Option<&DalekSecretKey>) -> Result<Self, Error> {
		let mut r = BitReader::endian(data.as_slice(), BigEndian);
		let version: u8 = r.read(4)?;
		if version != 0 {
			return Err(
				ErrorKind::SlatepackDecodeError("Wrong slatepack version".to_string()).into(),
			);
		}
		let enc_len: u32 = r.read(16 + 4)?;
		let mut data_to_decrypt: Vec<u8> = vec![0; enc_len as usize];
		r.read_bytes(&mut data_to_decrypt)?;
		let payload = Self::try_decrypt_payload(data_to_decrypt, dec_key)?;

		let mut r = BitReader::endian(payload.as_slice(), BigEndian);
		let content = SlatePurpose::from_int(r.read(3)?)?;

		let sender = if r.read::<u8>(1)? == 1 {
			let mut data: [u8; 32] = [0; 32];
			r.read_bytes(&mut data)?;
			Some(xDalekPublicKey::from(data))
		} else {
			None
		};

		let mut slate = match content {
			SlatePurpose::InvoiceSend => Self::read_slate_data(
				true, false, false, false, false, false, true, false, false, false, &mut r,
			)?,
			SlatePurpose::InvoiceResponse => Self::read_slate_data(
				true, true, true, true, true, true, false, true, false, false, &mut r,
			)?,
			SlatePurpose::FullSlate => Self::read_slate_data(
				true, true, true, true, true, true, true, true, true, true, &mut r,
			)?,
			SlatePurpose::SendSend => Self::read_slate_data(
				true, true, false, false, false, false, true, false, true, false, &mut r,
			)?,
			SlatePurpose::SendResponse => Self::read_slate_data(
				false, false, true, false, true, true, false, true, true, true, &mut r,
			)?,
		};

		Self::update_tx_from_slate(&mut slate)?;

		Ok(Slatepack {
			sender,
			recipients: vec![],
			content,
			slate,
		})
	}

	/// Encode this slatepack into the binary format, version and recipients will be truncated and not encoded,
	/// The rest will be encrypted, there is no reason to know who isi the sender.
	/// Note:  from_binary & to_binary - are NOT serializers, minimum amount of the data is transported
	/// from_binary & to_binary are symmetrical
	pub fn to_binary(&self, slate_version: SlateVersion) -> Result<Vec<u8>, Error> {
		if !self.slate.compact_slate {
			return Err(ErrorKind::SlatepackEncodeError(
				"Slatepack expecting only compact model".to_string(),
			)
			.into());
		}

		// Here we can calculate the version of the slatepack that it needed. Currently there is no choices, just a single version.
		match slate_version {
			SlateVersion::SP => (),
			_ => return Err(ErrorKind::SlatepackEncodeError("Slate is plain".to_string()).into()),
		}

		let mut encrypted_data = Vec::new();

		let mut w = BitWriter::endian(&mut encrypted_data, BigEndian);
		w.write(3, self.content.to_int())?;
		match &self.sender {
			None => w.write(1, 0)?,
			Some(sender) => {
				w.write(1, 1)?;
				debug_assert!(sender.as_bytes().len() == 32);
				w.write_bytes(sender.as_bytes())?;
			}
		}
		// Receiver are not included, so far we don't need them. Format is compact, so no usage, no data

		match self.content {
			SlatePurpose::InvoiceSend => {
				Self::write_slate_data(
					&self.slate,
					true,
					false,
					false,
					false,
					false,
					false,
					true,
					false,
					false,
					false,
					&mut w,
				)?;
			}
			SlatePurpose::InvoiceResponse => {
				Self::write_slate_data(
					&self.slate,
					true,
					true,
					true,
					true,
					true,
					true,
					false,
					true,
					false,
					false,
					&mut w,
				)?;
			}
			SlatePurpose::FullSlate => {
				Self::write_slate_data(
					&self.slate,
					true,
					true,
					true,
					true,
					true,
					true,
					true,
					true,
					true,
					true,
					&mut w,
				)?;
			}
			SlatePurpose::SendSend => {
				Self::write_slate_data(
					&self.slate,
					true,
					true,
					false,
					false,
					false,
					false,
					true,
					false,
					true,
					false,
					&mut w,
				)?;
			}
			SlatePurpose::SendResponse => {
				Self::write_slate_data(
					&self.slate,
					false,
					false,
					true,
					false,
					true,
					true,
					false,
					true,
					true,
					true,
					&mut w,
				)?;
			}
		}

		// Flushing of the last byte into encrypted_data
		w.write::<u8>(7, 0)?;

		let encrypted_data = Self::try_encrypt_payload(encrypted_data, &self.recipients)?;

		// Here is a binary that we will use
		let mut pack_binary = Vec::new();
		let mut w = BitWriter::endian(&mut pack_binary, BigEndian);

		// Writing the version 0. The version is global for all slatepack.
		w.write(4, 0)?;
		let enc_len = encrypted_data.len();
		if enc_len > 65535 * 16 {
			return Err(ErrorKind::SlatepackEncodeError(
				"Slate too large for encoding".to_string(),
			)
			.into());
		}
		w.write(16 + 4, enc_len as u32)?; // Need to keep byte aligned
		w.write_bytes(&encrypted_data)?;
		Ok(pack_binary)
	}

	fn write_u64<W: io::Write, E: Endianness>(
		amount: u64,
		has_hundreds: bool,
		writer: &mut BitWriter<W, E>,
	) -> Result<(), Error> {
		// amount normally has many zeroes and not much digits as decimal. Let's use this fact
		let mut hundreds: u8 = 0;
		let mut amount = amount;
		if has_hundreds {
			while amount % 100 == 0 && hundreds < 7 {
				amount /= 100;
				hundreds += 1;
			}
		}
		// now calculating the used digits
		let mut d: u64 = 1;
		let mut dn = 1;
		while dn < 64 && d < amount {
			dn += 1;
			d <<= 1;
		}
		if has_hundreds {
			writer.write(3, hundreds)?; // 8 max value
		}
		writer.write(6, dn - 1)?; // 64 max value, 1 min
		writer.write(dn, amount)?;

		Ok(())
	}

	fn write_participant_data<W: io::Write, E: Endianness>(
		part_data: &ParticipantData,
		w: &mut BitWriter<W, E>,
	) -> Result<(), Error> {
		Self::write_publick_key(&part_data.public_blind_excess, w)?;
		Self::write_publick_key(&part_data.public_nonce, w)?;

		match part_data.part_sig {
			Some(sig) => {
				w.write(1, 1)?;
				let sig_dt = sig.serialize_compact();
				w.write_bytes(&sig_dt)?;
			}
			None => {
				w.write(1, 0)?;
			}
		}

		match &part_data.message {
			Some(message) => {
				w.write(1, 1)?;
				let mut message = message.clone();
				// let's limit message with 32 k
				let mut msg_enc = smaz::compress(message.as_bytes());
				while msg_enc.len() > 30000 {
					message.truncate(message.len() / 2);
					msg_enc = smaz::compress(message.as_bytes());
				}
				w.write(16, msg_enc.len() as u16)?;
				w.write_bytes(&msg_enc)?;
			}
			None => w.write::<u8>(1, 0)?,
		}
		Ok(())
	}

	fn write_publick_key<W: io::Write, E: Endianness>(
		pk: &PublicKey,
		w: &mut BitWriter<W, E>,
	) -> Result<(), Error> {
		let xs = pk.serialize_vec(true);
		w.write(7, xs.len() as u32)?;
		w.write_bytes(&xs)?;
		Ok(())
	}

	// Write this address 'efficeint' way. The problem that it can be PublicKey aka MQS address
	// or DalekPublicKey aka Tor Address.
	// We will need to save a a binary
	fn write_provable_address<W: io::Write, E: Endianness>(
		address: &ProvableAddress,
		w: &mut BitWriter<W, E>,
	) -> Result<(), Error> {
		match address.public_key() {
			Ok(pk) => {
				//
				w.write(1, 1)?;
				Self::write_publick_key(&pk, w)?;
			}
			Err(_) => {
				// it must be tor address.
				w.write(1, 0)?;
				// len is 32 bytes
				w.write_bytes(address.tor_public_key()?.as_bytes())?;
			}
		}
		Ok(())
	}

	fn write_slate_data<W: io::Write, E: Endianness>(
		slate: &Slate,
		write_amount: bool,
		write_fee: bool,
		write_offset: bool,
		write_inputs: bool,
		write_outputs: bool,
		write_kernels: bool,
		write_participan_data_0: bool,
		write_participan_data_1: bool,
		write_proof_addresses: bool,
		write_proof_signature: bool,
		w: &mut BitWriter<W, E>,
	) -> Result<(), Error> {
		// stransaction Id is included in every paylod
		// 16 bytes
		w.write_bytes(slate.id.as_bytes())?;
		// Add network Info. 1 for mainnet, 0 for for the rest...
		if global::is_mainnet() {
			w.write(1, 1)?;
		} else {
			w.write(1, 0)?;
		}

		if write_amount {
			Self::write_u64(slate.amount, true, w)?;
		}
		if write_fee {
			Self::write_u64(slate.fee, true, w)?;
		}

		Self::write_u64(slate.height, false, w)?;
		Self::write_u64(slate.lock_height, false, w)?;

		match slate.ttl_cutoff_height {
			Some(h) => {
				w.write(1, 1)?;
				Self::write_u64(h, false, w)?;
			}
			None => {
				w.write(1, 0)?;
			}
		}

		if write_offset {
			// size: SECRET_KEY_SIZE
			let offset = slate.offset.as_ref();
			w.write_bytes(offset)?;
		}

		if write_inputs {
			match &slate.tx.body.inputs {
				Inputs::CommitOnly(commit_wrapper) => {
					w.write(1, 0)?;
					// Using stop bit because normally we have few inputs...
					let mut has_data = false;
					for commit in commit_wrapper {
						if has_data {
							w.write(1, 1)?; // go bit
						}
						// Len: constants::PEDERSEN_COMMITMENT_SIZE
						w.write_bytes(&commit.commitment().0)?;
						has_data = true;
					}
					w.write(1, 0)?; // stop bit
				}
				Inputs::FeaturesAndCommit(inputs) => {
					w.write(1, 1)?;
					// Using stop bit because normally we have few inputs...
					let mut has_data = false;
					for inp in inputs {
						if has_data {
							w.write(1, 1)?; // go bit
						}
						w.write(1, inp.features as u8)?;
						w.write_bytes(&inp.commit.0)?;
						has_data = true;
					}
					w.write(1, 0)?; // stop bit
				}
			}
		}

		if write_outputs {
			// Using stop bit because normally we have few inputs...
			let mut has_data = false;
			// Because usually expecting 1 output, it is better to use a stop symbol instead on length
			for out in &slate.tx.body.outputs {
				if has_data {
					w.write(1, 1)?; // go bit
				}
				// Feature can be only plain
				// Len: constants::PEDERSEN_COMMITMENT_SIZE
				w.write_bytes(&out.identifier.commit.0)?;
				w.write(10, out.proof.plen as u32)?; // max 675 - should fit 10 bits
				w.write_bytes(out.proof.bytes())?;
				has_data = true;
			}
			w.write(1, 0)?; // stop bit
		}

		if write_kernels {
			// Using stop bit because normally there is only one kernel
			let mut has_data = false;
			// Because usually expecting 1 output, it is better to use a stop symbol instead on length
			for kernel in &slate.tx.body.kernels {
				if has_data {
					w.write(1, 1)?; // go bit
				}
				// Expecting only Plain kernels. It is about wallet basic operations, so nothing extra
				match kernel.features {
					KernelFeatures::Plain { fee } => {
						Self::write_u64(fee, true, w)?;
					}
					_ => {
						return Err(ErrorKind::SlatepackEncodeError(
							"Slatepack expecting only Plain Kernels".to_string(),
						)
						.into())
					}
				}
				w.write_bytes(&kernel.excess.0)?;
				w.write_bytes(&kernel.excess_sig.serialize_compact())?;
				has_data = true;
			}
			w.write(1, 0)?; // stop bit
		}

		if write_participan_data_0 {
			let part_data =
				slate
					.participant_data
					.get(0)
					.ok_or(ErrorKind::SlatepackEncodeError(
						"Not found slate participant data".to_string(),
					))?;
			Self::write_participant_data(part_data, w)?;
		}
		if write_participan_data_1 {
			let part_data =
				slate
					.participant_data
					.get(1)
					.ok_or(ErrorKind::SlatepackEncodeError(
						"Not found slate participant data".to_string(),
					))?;
			Self::write_participant_data(part_data, w)?;
		}

		if write_proof_addresses {
			match &slate.payment_proof {
				Some(pp) => {
					w.write(1, 1)?;
					// len is 32 bytes
					Self::write_provable_address(&pp.sender_address, w)?;
					Self::write_provable_address(&pp.receiver_address, w)?;
					// signature is None
				}
				None => w.write(1, 0)?,
			}
		}

		if write_proof_signature {
			match &slate.payment_proof {
				Some(pp) => {
					w.write(1, 1)?;
					let sign_str =
						pp.receiver_signature
							.clone()
							.ok_or(ErrorKind::SlatepackEncodeError(
								"Not found expected payment proof signature".to_string(),
							))?;
					let sign_v = from_hex(&sign_str).map_err(|e| {
						ErrorKind::SlatepackEncodeError(format!(
							"Wrong signature at slate data, {}",
							e
						))
					})?;
					if sign_v.len() != 64 {
						return Err(ErrorKind::SlatepackEncodeError(
							"Invalid Signature length".to_string(),
						)
						.into());
					}
					w.write_bytes(&sign_v)?;
				}
				None => w.write(1, 0)?,
			}
		}

		Ok(())
	}

	// see write_amount for details
	fn read_u64<R: io::Read, E: Endianness>(
		r: &mut BitReader<R, E>,
		has_hundreds: bool,
	) -> Result<u64, Error> {
		let hundreds: u16 = if has_hundreds { r.read(3)? } else { 0 };

		let digits: u32 = r.read(6)?;
		let mut amount: u64 = r.read(digits + 1)?;

		for _i in 0..hundreds {
			amount *= 100;
		}
		Ok(amount)
	}

	fn read_participant_data<R: io::Read, E: Endianness>(
		r: &mut BitReader<R, E>,
		id: u64,
	) -> Result<ParticipantData, Error> {
		let blind_excess = Self::read_publick_key(r)?;
		let nonce = Self::read_publick_key(r)?;

		let signature = if r.read::<u8>(1)? == 1 {
			let mut sig_dt: [u8; 64] = [0; 64];
			r.read_bytes(&mut sig_dt)?;
			Some(Signature::from_compact(&sig_dt)?)
		} else {
			None
		};

		let message = if r.read::<u8>(1)? == 1 {
			let sz: u32 = r.read(16)?;
			let mut msg: Vec<u8> = vec![0; sz as usize];
			r.read_bytes(&mut msg)?;
			let msg = smaz::decompress(&msg).map_err(|e| {
				ErrorKind::SlatepackDecodeError(format!("Unable to decode message, {}", e))
			})?;
			Some(String::from_utf8(msg).map_err(|e| {
				ErrorKind::SlatepackDecodeError(format!("Unable to decode message, {}", e))
			})?)
		} else {
			None
		};

		Ok(ParticipantData {
			id,
			public_blind_excess: blind_excess,
			public_nonce: nonce,
			part_sig: signature,
			message,
			message_sig: None,
		})
	}

	fn read_publick_key<R: io::Read, E: Endianness>(
		r: &mut BitReader<R, E>,
	) -> Result<PublicKey, Error> {
		let xs_len: u32 = r.read(7)?;
		let mut xs: Vec<u8> = vec![0; xs_len as usize];
		r.read_bytes(&mut xs)?;
		let pk = PublicKey::from_slice(&xs)?;
		Ok(pk)
	}

	fn read_provable_address<R: io::Read, E: Endianness>(
		r: &mut BitReader<R, E>,
	) -> Result<ProvableAddress, Error> {
		let pa = if r.read::<u8>(1)? == 1 {
			// PublicKey (MQS)
			let pk = Self::read_publick_key(r)?;
			ProvableAddress::from_pub_key(&pk)
		} else {
			let mut pk: [u8; PUBLIC_KEY_LENGTH] = [0; PUBLIC_KEY_LENGTH];
			r.read_bytes(&mut pk)?;
			let dalek_pk = DalekPublicKey::from_bytes(&pk).map_err(|e| {
				ErrorKind::SlatepackDecodeError(format!("Unable decode Public Key data, {}", e))
			})?;

			ProvableAddress::from_tor_pub_key(&dalek_pk)
		};

		Ok(pa)
	}

	fn read_slate_data<R: io::Read, E: Endianness>(
		read_amount: bool,
		read_fee: bool,
		read_offset: bool,
		read_inputs: bool,
		read_outputs: bool,
		read_kernels: bool,
		read_participan_data_0: bool,
		read_participan_data_1: bool,
		read_proof_addresses: bool,
		read_proof_signature: bool,
		r: &mut BitReader<R, E>,
	) -> Result<Slate, Error> {
		let mut slate = Slate::blank(2, true);
		let mut slate_id: [u8; 16] = [0; 16];
		r.read_bytes(&mut slate_id)?;
		slate.id = Uuid::from_slice(&slate_id).map_err(|e| {
			ErrorKind::SlatepackDecodeError(format!("Unable to encode UUID data, {}", e))
		})?;

		let network: u8 = r.read(1)?;

		if (network == 1) ^ global::is_mainnet() {
			return Err(
				ErrorKind::SlatepackDecodeError("Slate from wrong network".to_string()).into(),
			);
		}

		if read_amount {
			slate.amount = Self::read_u64(r, true)?;
		}
		if read_fee {
			slate.fee = Self::read_u64(r, true)?;
		}

		slate.height = Self::read_u64(r, false)?;
		slate.lock_height = Self::read_u64(r, false)?;

		if r.read::<u8>(1)? == 1 {
			slate.ttl_cutoff_height = Some(Self::read_u64(r, false)?);
		} else {
			slate.ttl_cutoff_height = None;
		}

		if read_offset {
			let mut offset: [u8; SECRET_KEY_SIZE] = [0; SECRET_KEY_SIZE];
			r.read_bytes(&mut offset)?;
			slate.offset = BlindingFactor::from_slice(&offset);
		}

		if read_inputs {
			if r.read::<u8>(1)? == 0 {
				// Inputs::CommitOnly  type
				let mut input_commit: Vec<CommitWrapper> = vec![];
				loop {
					let mut commit: [u8; PEDERSEN_COMMITMENT_SIZE] = [0; PEDERSEN_COMMITMENT_SIZE];
					r.read_bytes(&mut commit)?;
					input_commit.push(CommitWrapper::from(Commitment(commit)));
					if r.read::<u8>(1)? == 0 {
						break;
					}
				}
				slate.tx.body.inputs = Inputs::CommitOnly(input_commit);
			} else {
				// Inputs::FeaturesAndCommit(Vec<Input>) type
				let mut inputs: Vec<Input> = vec![];
				loop {
					let of: OutputFeatures = if r.read::<u8>(1)? == 0 {
						OutputFeatures::Plain
					} else {
						OutputFeatures::Coinbase
					};
					let mut commit: [u8; PEDERSEN_COMMITMENT_SIZE] = [0; PEDERSEN_COMMITMENT_SIZE];
					r.read_bytes(&mut commit)?;
					inputs.push(Input::new(of, Commitment(commit)));
					if r.read::<u8>(1)? == 0 {
						break;
					}
				}
				slate.tx.body.inputs = Inputs::FeaturesAndCommit(inputs);
			}
		}

		if read_outputs {
			loop {
				let mut commit: [u8; PEDERSEN_COMMITMENT_SIZE] = [0; PEDERSEN_COMMITMENT_SIZE];
				r.read_bytes(&mut commit)?;

				let proof_len: u32 = r.read(10)?;
				let mut proof_data: Vec<u8> = vec![0; proof_len as usize];
				r.read_bytes(&mut proof_data)?;

				let mut proof = RangeProof::zero();
				proof.plen = proof_len as usize;
				for i in 0..proof_len {
					proof.proof[i as usize] = proof_data[i as usize];
				}

				slate.tx.body.outputs.push(Output {
					identifier: OutputIdentifier {
						features: OutputFeatures::Plain,
						commit: Commitment(commit),
					},
					proof,
				});

				if r.read::<u8>(1)? == 0 {
					break;
				}
			}
		}

		if read_kernels {
			loop {
				let fee = Self::read_u64(r, true)?;

				let mut excess: [u8; PEDERSEN_COMMITMENT_SIZE] = [0; PEDERSEN_COMMITMENT_SIZE];
				r.read_bytes(&mut excess)?;

				let mut signature: [u8; 64] = [0; 64];
				r.read_bytes(&mut signature)?;

				slate.tx.body.kernels.push(TxKernel {
					features: KernelFeatures::Plain { fee },
					excess: Commitment(excess),
					excess_sig: Signature::from_compact(&signature)?,
				});

				if r.read::<u8>(1)? == 0 {
					break;
				}
			}
		}

		if read_participan_data_0 {
			slate
				.participant_data
				.push(Self::read_participant_data(r, 0)?);
		}

		if read_participan_data_1 {
			slate
				.participant_data
				.push(Self::read_participant_data(r, 1)?);
		}

		if read_proof_addresses {
			if r.read::<u8>(1)? == 1 {
				let sender_address = Self::read_provable_address(r)?;
				let receiver_address = Self::read_provable_address(r)?;

				match &mut slate.payment_proof {
					Some(proof) => {
						proof.sender_address = sender_address;
						proof.receiver_address = receiver_address;
					}
					None => {
						slate.payment_proof = Some(PaymentInfo {
							sender_address,
							receiver_address,
							receiver_signature: None,
						});
					}
				}
			}
		}

		if read_proof_signature {
			if r.read::<u8>(1)? == 1 {
				let mut signature: [u8; 64] = [0; 64];
				r.read_bytes(&mut signature)?;

				match &mut slate.payment_proof {
					Some(proof) => {
						proof.receiver_signature = Some(to_hex(&signature));
					}
					None => {
						slate.payment_proof = Some(PaymentInfo {
							sender_address: ProvableAddress::blank(),
							receiver_address: ProvableAddress::blank(),
							receiver_signature: Some(to_hex(&signature)),
						});
					}
				}
			}
		}

		Ok(slate)
	}

	/// age encrypt the payload with the given public key
	fn try_encrypt_payload(
		payload: Vec<u8>,
		recipients: &Vec<xDalekPublicKey>,
	) -> Result<Vec<u8>, Error> {
		if recipients.is_empty() {
			return Ok(payload);
		}

		// Create encrypted metadata, which will be length prefixed
		let rec_keys: Result<Vec<_>, _> = recipients
			.into_iter()
			.map(|pk| {
				let key = age::keys::RecipientKey::X25519(pk.clone());
				Ok(key)
			})
			.collect();

		let keys = match rec_keys {
			Ok(k) => k,
			Err(e) => return Err(e),
		};

		let encryptor = age::Encryptor::with_recipients(keys);
		let mut encrypted = vec![];
		let mut writer = encryptor.wrap_output(&mut encrypted, age::Format::Binary)?;
		writer.write_all(&payload)?;
		writer.finish()?;
		Ok(encrypted.to_vec())
	}

	/// As above, decrypt if needed
	/// dec_key - is a secret that is used for all types of weallet addresses.
	fn try_decrypt_payload(
		payload: Vec<u8>,
		dec_key: Option<&DalekSecretKey>,
	) -> Result<Vec<u8>, Error> {
		let dec_key = match dec_key {
			Some(k) => k,
			None => return Ok(payload),
		};
		let mut b = [0u8; 32];
		b.copy_from_slice(&dec_key.as_bytes()[0..32]);
		let mut hasher = Sha512::new();
		hasher.input(&b);
		let result = hasher.result();
		b.copy_from_slice(&result[0..32]);

		let x_dec_secret = StaticSecret::from(b);
		let key = age::keys::SecretKey::X25519(x_dec_secret);

		let decryptor = match age::Decryptor::new(&payload[..]).map_err(|e| {
			ErrorKind::SlatepackDecodeError(format!("Unable to build age decryptor, {}", e))
		})? {
			age::Decryptor::Recipients(d) => d,
			_ => {
				return Err(ErrorKind::SlatepackDecodeError(
					"Payload using unexpected decryptor".to_string(),
				)
				.into())
			}
		};
		let mut decrypted = vec![];
		let mut reader = decryptor.decrypt(&[key.into()]).map_err(|e| {
			ErrorKind::SlatepackDecodeError(format!("Unable to decrypt the payload, {}", e))
		})?;
		reader.read_to_end(&mut decrypted)?;
		Ok(decrypted)
	}

	// Update a transaction form the slate data.
	fn update_tx_from_slate(slate: &mut Slate) -> Result<(), Error> {
		let secp = static_secp_instance();
		let secp = secp.lock();
		debug_assert!(slate.compact_slate);
		// Passing None to calc_excess because it is not needed for compact_slate.
		let excess = match slate.calc_excess::<ExtKeychain>(None) {
			Ok(e) => e,
			Err(_) => Commitment::from_vec(vec![0]),
		};
		let excess_sig = match slate.finalize_signature(&secp) {
			Ok(s) => s,
			Err(_) => Signature::from_raw_data(&[0; 64])?,
		};
		let kernel = TxKernel {
			features: slate.kernel_features(),
			excess,
			excess_sig,
		};

		// Updating tx kernel and offset with what slate has
		if slate.tx.body.kernels.is_empty() {
			slate.tx.body.kernels.push(kernel);
		} else {
			slate.tx.body.kernels[0] = kernel;
		}
		slate.tx.offset = slate.offset.clone();

		Ok(())
	}
}
