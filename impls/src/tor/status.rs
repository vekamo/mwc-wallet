// Copyright 2021 The MWC Developers
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

//! Tor status for the wallet. That data can be sharable by many components. We just
//! need to know how it is running.
use std::sync::RwLock;

lazy_static! {
	// Current address that is tor is listening on (also mean that listener is running)
	static ref TOR_ONION_ADDRESS: RwLock<Option<String>> = RwLock::new(None);

	// Flag if listener tor process is running. (we want to keep listener and sender separately)
	// And we want to have them single socks port to use. That is why the tor starting process args
	// can be adjusted

	static ref TOR_SENDER_RUNNING: RwLock<bool> = RwLock::new(false);
}

pub fn set_tor_address(address: Option<String>) {
	match address {
		Some(address) => (*TOR_ONION_ADDRESS.write().unwrap()).replace(address),
		None => (*TOR_ONION_ADDRESS.write().unwrap()).take(),
	};
}

pub fn get_tor_address() -> Option<String> {
	(*TOR_ONION_ADDRESS.read().unwrap()).clone()
}

pub fn set_tor_sender_running(running: bool) {
	(*TOR_SENDER_RUNNING.write().unwrap()) = running;
}

pub fn get_tor_sender_running() -> bool {
	(*TOR_SENDER_RUNNING.read().unwrap()).clone()
}
