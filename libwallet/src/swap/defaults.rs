use std::collections::HashMap;

/// Create a map of the resources nneded for the swap. If resources are not defined at the config file,
/// deafult values will be used
pub fn get_swap_support_servers(
	electrumx_mainnet_bch_node_addr: &Option<String>,
	electrumx_testnet_bch_node_addr: &Option<String>,
	electrumx_mainnet_btc_node_addr: &Option<String>,
	electrumx_testnet_btc_node_addr: &Option<String>,
) -> HashMap<String, String> {
	let mut node_addrs = HashMap::new();
	node_addrs.insert(
		"electrumx_mainnet_bch_node_addr".to_string(),
		electrumx_mainnet_bch_node_addr
			.clone()
			.unwrap_or("52.23.248.83:8000".to_string()),
	);
	node_addrs.insert(
		"electrumx_testnet_bch_node_addr".to_string(),
		electrumx_testnet_bch_node_addr
			.clone()
			.unwrap_or("52.23.248.83:8000".to_string()),
	);
	node_addrs.insert(
		"electrumx_mainnet_btc_node_addr".to_string(),
		electrumx_mainnet_btc_node_addr
			.clone()
			.unwrap_or("52.23.248.83:8000".to_string()),
	);
	node_addrs.insert(
		"electrumx_testnet_btc_node_addr".to_string(),
		electrumx_testnet_btc_node_addr
			.clone()
			.unwrap_or("52.23.248.83:8000".to_string()),
	);
	node_addrs
}
