use std::{
	fs::{self, File},
	io::{BufRead, BufReader, Write},
	net::{IpAddr, Ipv4Addr},
	path::PathBuf,
};

use anyhow::{bail, Context, Result};
use aptos_config::{
	config::{
		DiscoveryMethod, Identity, IdentityBlob, InitialSafetyRulesConfig, NetworkConfig,
		NodeConfig, OnDiskStorageConfig, OverrideNodeConfig, PersistableConfig, SafetyRulesService,
		SecureBackend, WaypointConfig,
	},
	network_id::NetworkId,
};
use aptos_crypto::{
	bls12381, ed25519::Ed25519PrivateKey, x25519, PrivateKey, ValidCryptoMaterialStringExt,
};
use aptos_genesis::{
	builder::GenesisConfiguration,
	config::{HostAndPort, Layout, ValidatorConfiguration},
	GenesisInfo,
};
use aptos_keygen::KeyGen;
use aptos_types::{
	account_address::{self},
	network_address::{DnsName, NetworkAddress, Protocol},
	on_chain_config::{
		ConsensusAlgorithmConfig, OnChainConsensusConfig, OnChainExecutionConfig,
		ValidatorTxnConfig,
	},
	transaction::authenticator::AuthenticationKey,
	waypoint::Waypoint,
};
use aptos_vm_genesis::AccountBalance;
use clap::Parser;

const CONFIG_FILE: &str = "node.yaml";
const VALIDATOR_FILE: &str = "validator-identity.yaml";
const GENESIS_BLOB: &str = "genesis.blob";
const ROOT_KEY: &str = "root_key";
const ACCOUNTS_FILE: &str = "accounts.yaml";
const NODES_FILE: &str = "nodes.yaml";

const INITIAL_BALANCE: u64 = 100_000_000_000_000;

struct Node {
	host: DnsName,
	validator_port: u16,
	vfn_port: u16,
	pfn_port: u16,
	api_port: u16,
	inspection_port: u16,
	backup_port: u16,
	account_key: Ed25519PrivateKey,
	account_address: account_address::AccountAddress,
	consensus_key: bls12381::PrivateKey,
	validator_network_key: x25519::PrivateKey,
	full_node_network_key: x25519::PrivateKey,
}

impl Node {
	fn new(keygen: &mut KeyGen, offset: u16, host: DnsName) -> Result<Node> {
		let account_key = keygen.generate_ed25519_private_key();
		let account_address =
			AuthenticationKey::ed25519(&account_key.public_key()).account_address();
		let consensus_key = keygen.generate_bls12381_private_key();
		let validator_network_key = keygen.generate_x25519_private_key()?;
		let full_node_network_key = keygen.generate_x25519_private_key()?;

		Ok(Node {
			host,
			validator_port: 6000 + offset,
			vfn_port: 7000 + offset,
			pfn_port: 11000 + offset,
			api_port: 8000 + offset,
			inspection_port: 9000 + offset,
			backup_port: 10000 + offset,
			account_key,
			account_address,
			consensus_key,
			validator_network_key,
			full_node_network_key,
		})
	}

	fn api_address(&self) -> String {
		format!("{}:{}", self.host, self.api_port)
	}

	fn new_validator_config(
		&self,
		stake_amount: u64,
		commission_percentage: u64,
		join_during_genesis: bool,
	) -> ValidatorConfiguration {
		let account_key = self.account_key.public_key();
		let proof_of_possession = bls12381::ProofOfPossession::create(&self.consensus_key);

		ValidatorConfiguration {
			owner_account_address: self.account_address.into(),
			owner_account_public_key: account_key.to_owned(),
			operator_account_address: self.account_address.into(),
			operator_account_public_key: account_key.to_owned(),
			voter_account_address: self.account_address.into(),
			voter_account_public_key: account_key.to_owned(),
			consensus_public_key: Some(self.consensus_key.public_key()),
			proof_of_possession: Some(proof_of_possession),
			validator_network_public_key: Some(self.validator_network_key.public_key()),
			validator_host: Some(HostAndPort {
				host: self.host.to_owned(),
				port: self.validator_port,
			}),
			full_node_network_public_key: Some(self.full_node_network_key.public_key()),
			full_node_host: Some(HostAndPort {
				host: self.host.to_owned(),
				port: self.pfn_port,
			}),
			stake_amount,
			commission_percentage,
			join_during_genesis,
		}
	}

	fn new_validator_identity(&self) -> IdentityBlob {
		IdentityBlob {
			account_address: Some(self.account_address),
			account_private_key: Some(self.account_key.to_owned()),
			consensus_private_key: Some(self.consensus_key.to_owned()),
			network_private_key: self.validator_network_key.to_owned(),
		}
	}

	fn new_validator_node_config(
		&self,
		template: &NodeConfig,
		data_dir: &PathBuf,
		waypoint: &Waypoint,
	) -> Result<OverrideNodeConfig> {
		let mut config = template.to_owned();

		config.base.data_dir = data_dir.to_owned();
		config.base.waypoint = WaypointConfig::FromConfig(*waypoint);

		config.consensus.safety_rules.service = SafetyRulesService::Local;
		config.consensus.safety_rules.backend =
			SecureBackend::OnDiskStorage(OnDiskStorageConfig::default());
		config.consensus.safety_rules.initial_safety_rules_config =
			InitialSafetyRulesConfig::from_file(
				data_dir.join(VALIDATOR_FILE),
				vec![],
				config.base.waypoint.to_owned(),
			);

		config.execution.genesis_file_location = data_dir.join(GENESIS_BLOB);

		let validator_network = config
			.validator_network
			.as_mut()
			.context("validator network missing")?;
		validator_network.discovery_method = DiscoveryMethod::Onchain;
		validator_network.listen_address = NetworkAddress::from_protocols(vec![
			Protocol::Ip4(Ipv4Addr::UNSPECIFIED),
			Protocol::Tcp(self.validator_port),
		])?;
		validator_network.identity =
			Identity::from_config(self.validator_network_key.to_owned(), self.account_address);

		let full_node_network = config
			.full_node_networks
			.first_mut()
			.context("full node network missing")?;
		if !full_node_network.network_id.is_vfn_network() {
			bail!("expected vfn to be present");
		}
		full_node_network.discovery_method = DiscoveryMethod::Onchain;
		full_node_network.listen_address = NetworkAddress::from_protocols(vec![
			Protocol::Ip4(Ipv4Addr::UNSPECIFIED),
			Protocol::Tcp(self.vfn_port),
		])?;
		full_node_network.identity =
			Identity::from_config(self.full_node_network_key.to_owned(), self.account_address);

		config.full_node_networks.push(NetworkConfig {
			network_id: NetworkId::Public,
			discovery_method: DiscoveryMethod::Onchain,
			listen_address: NetworkAddress::from_protocols(vec![
				Protocol::Ip4(Ipv4Addr::UNSPECIFIED),
				Protocol::Tcp(self.pfn_port),
			])?,
			identity: Identity::from_config(
				self.full_node_network_key.to_owned(),
				self.account_address,
			),
			..Default::default()
		});

		config.api.address.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
		config.api.address.set_port(self.api_port);
		config.inspection_service.port = self.inspection_port;
		config
			.storage
			.backup_service_address
			.set_port(self.backup_port);

		Ok(OverrideNodeConfig::new_with_default_base(config))
	}

	fn new_public_full_node_config(
		&self,
		template: &NodeConfig,
		data_dir: &PathBuf,
		waypoint: &Waypoint,
	) -> Result<OverrideNodeConfig> {
		let mut config = template.to_owned();

		config.base.data_dir = data_dir.to_owned();
		config.base.waypoint = WaypointConfig::FromConfig(*waypoint);

		config.execution.genesis_file_location = data_dir.join(GENESIS_BLOB);

		let full_node_network = config
			.full_node_networks
			.first_mut()
			.context("full node network missing")?;
		if !full_node_network.network_id.is_public_network() {
			bail!("expected pfn to be present");
		}
		full_node_network.discovery_method = DiscoveryMethod::Onchain;
		full_node_network.listen_address = NetworkAddress::from_protocols(vec![
			Protocol::Ip4(Ipv4Addr::UNSPECIFIED),
			Protocol::Tcp(self.pfn_port),
		])?;
		full_node_network.identity = Identity::from_config(
			self.full_node_network_key.to_owned(),
			account_address::from_identity_public_key(self.full_node_network_key.public_key()),
		);

		config.api.address.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
		config.api.address.set_port(self.api_port);
		config.inspection_service.port = self.inspection_port;
		config
			.storage
			.backup_service_address
			.set_port(self.backup_port);

		Ok(OverrideNodeConfig::new_with_default_base(config))
	}
}

#[derive(Parser)]
struct Args {
	// Path to behaviors file
	#[arg(short, long)]
	behaviors_file: PathBuf,

	// Path to deploy directory
	#[arg(short, long)]
	deploy_dir: PathBuf,

	// Number of accounts to create
	#[arg(short, long, default_value_t = 10000)]
	num_accounts: usize,

	// Path to prepare directory
	#[arg(short, long)]
	prepare_dir: PathBuf,

	// Optional flag to disable quorum store
	#[arg(long)]
	disable_quorum_store: bool,

	#[arg(long)]
	num_validators: Option<usize>,
}

fn main() -> Result<()> {
	let mut keygen = KeyGen::from_seed([0; 32]);

	let args = Args::parse();
	let deploy_dir = args.deploy_dir;
	if !deploy_dir.is_absolute() {
		bail!("path to deploy directory should be absolute");
	}

	let behaviors_file = File::open(args.behaviors_file)?;
	let mut nodes = Vec::new();
	for line in BufReader::new(behaviors_file).lines() {
		let line = line?;
		let (addr, number) = line.split_once(':').context("Failed to split node line")?;
		let number = number.parse::<u16>()?;
		for i in 0..number {
			nodes.push(Node::new(&mut keygen, i, addr.to_string().try_into()?)?)
		}
	}

	let num_validators = args.num_validators.unwrap_or(nodes.len());
	if num_validators > nodes.len() {
		bail!(
			"Number of validators ({}) exceeds number of nodes ({})",
			num_validators,
			nodes.len()
		);
	}
	let (validators, pfns) = nodes.split_at(num_validators);
	println!(
		"Using {} validators and {} public full nodes",
		validators.len(),
		pfns.len()
	);

	let mut keygen = KeyGen::from_seed([1; 32]);
	let layout = Layout::default();
	let root_key = keygen.generate_ed25519_private_key();
	let account_private_keys = (0..args.num_accounts)
		.map(|_| keygen.generate_ed25519_private_key())
		.collect::<Vec<_>>();
	let accounts = account_private_keys
		.iter()
		.map(|key| AccountBalance {
			account_address: AuthenticationKey::ed25519(&key.public_key()).account_address(),
			balance: INITIAL_BALANCE,
		})
		.collect::<Vec<_>>();
	let on_chain_consensus_config = if args.disable_quorum_store {
		OnChainConsensusConfig::V3 {
			alg: ConsensusAlgorithmConfig::default_with_quorum_store_disabled(),
			vtxn: ValidatorTxnConfig::default_if_missing(),
		}
	} else {
		OnChainConsensusConfig::default()
	};
	let mut genesis_info = GenesisInfo::new(
		layout.chain_id,
		root_key.public_key(),
		accounts,
		validators
			.iter()
			.map(|n| n.new_validator_config(layout.min_stake, 0, true))
			.collect(),
		aptos_cached_packages::head_release_bundle().clone(),
		&GenesisConfiguration {
			allow_new_validators: layout.allow_new_validators,
			epoch_duration_secs: layout.epoch_duration_secs,
			is_test: layout.is_test,
			min_stake: layout.min_stake,
			min_voting_threshold: layout.min_voting_threshold,
			max_stake: layout.max_stake,
			recurring_lockup_duration_secs: layout.recurring_lockup_duration_secs,
			required_proposer_stake: layout.required_proposer_stake,
			rewards_apy_percentage: layout.rewards_apy_percentage,
			voting_duration_secs: layout.voting_duration_secs,
			voting_power_increase_limit: layout.voting_power_increase_limit,
			employee_vesting_start: layout.employee_vesting_start,
			employee_vesting_period_duration: layout.employee_vesting_period_duration,
			consensus_config: on_chain_consensus_config,
			execution_config: OnChainExecutionConfig::default_for_genesis(),
			gas_schedule: aptos_vm_genesis::default_gas_schedule(),
			initial_features_override: None,
			randomness_config_override: None,
			jwk_consensus_config_override: None,
			initial_jwks: vec![],
			keyless_groth16_vk_override: None,
		},
	)?;
	let waypoint = genesis_info.generate_waypoint()?;
	let genesis = genesis_info.get_genesis();

	let validator_config = NodeConfig::get_default_validator_config();
	let pfn_config = NodeConfig::get_default_pfn_config();

	let prepare_dir = args.prepare_dir;
	if prepare_dir.exists() {
		fs::remove_dir_all(&prepare_dir)?;
	}
	fs::create_dir_all(&prepare_dir)?;
	File::create(prepare_dir.join(ROOT_KEY))?
		.write_all(root_key.to_encoded_string()?.as_bytes())?;
	File::create(prepare_dir.join(ACCOUNTS_FILE))?
		.write_all(serde_yaml::to_string(&account_private_keys)?.as_bytes())?;
	File::create(prepare_dir.join(NODES_FILE))?.write_all(
		serde_yaml::to_string(&nodes.iter().map(Node::api_address).collect::<Vec<_>>())?.as_bytes(),
	)?;
	for (i, node) in validators.iter().enumerate() {
		let name = format!("n{}", i);
		let deploy_dir = deploy_dir.join(&name);
		let prepare_dir = prepare_dir.join(&name);
		fs::create_dir_all(&prepare_dir)?;
		File::create(prepare_dir.join(GENESIS_BLOB))?.write_all(&bcs::to_bytes(genesis)?)?;

		let identity = node.new_validator_identity();
		File::create(prepare_dir.join(VALIDATOR_FILE))?
			.write_all(serde_yaml::to_string(&identity)?.as_bytes())?;

		node.new_validator_node_config(&validator_config, &deploy_dir, &waypoint)?
			.save_config(prepare_dir.join(CONFIG_FILE))?;
	}

	for (i, node) in pfns.iter().enumerate() {
		let name = format!("n{}", i + validators.len());
		let deploy_dir = deploy_dir.join(&name);
		let prepare_dir = prepare_dir.join(&name);
		fs::create_dir_all(&prepare_dir)?;
		File::create(prepare_dir.join(GENESIS_BLOB))?.write_all(&bcs::to_bytes(genesis)?)?;

		node.new_public_full_node_config(&pfn_config, &deploy_dir, &waypoint)?
			.save_config(prepare_dir.join(CONFIG_FILE))?;
	}

	Ok(())
}
