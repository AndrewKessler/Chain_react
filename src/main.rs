use anyhow::{bail, Context, Result};
use bip39::{Language, Mnemonic};
use bitcoin::{bip32::{ChildNumber, Xpriv}, Network};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Signer, Verifier, SigningKey, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::{fs, path::{Path, PathBuf}, time::{SystemTime, UNIX_EPOCH}};

const DEFAULT_MEMPOOL: &str = "https://mempool.lineage.to";
const DEFAULT_GAME_CONFIG: &str = "Game.toml";
const DEFAULT_WALLET: &str = "wallet.json";
const DEFAULT_REGISTRY: &str = "registry.json";
const DEFAULT_CHALLENGE: &str = "challenge.json";
const TOKEN_FRACTION: u64 = 72_072_000;
const CHALLENGE_PREFIX: u8 = 0x6a;
const CHALLENGE_SUFFIX: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];

#[derive(Parser)]
#[command(name = "chain_react", about = "Minimal client/server chain-state authentication demo")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Register the wallet's address and public key in the local server registry.
    Register {
        #[arg(short, long, default_value = DEFAULT_WALLET)]
        wallet: PathBuf,
        #[arg(short, long, default_value = DEFAULT_GAME_CONFIG)]
        config: PathBuf,
    },
    /// Generate and store a server challenge.
    Challenge {
        #[arg(short, long, default_value = DEFAULT_GAME_CONFIG)]
        config: PathBuf,
    },
    /// Sign a server challenge with the private key matching the supplied public key.
    Validate {
        public_key: String,
        challenge: String,
        #[arg(short, long, default_value = DEFAULT_WALLET)]
        wallet: PathBuf,
    },
    /// Validate a signed challenge and current on-chain ownership.
    Authenticate {
        public_key: String,
        challenge: String,
        signature: String,
        #[arg(short, long, default_value = DEFAULT_GAME_CONFIG)]
        config: PathBuf,
    },
}

#[derive(Debug, Deserialize)]
struct GameConfig {
    use_blockchain_auth: u8,
    required_item: String,
    mempool: MempoolConfig,
    server: ServerConfig,
}

#[derive(Debug, Deserialize)]
struct MempoolConfig { url: String }

#[derive(Debug, Deserialize)]
struct ServerConfig {
    #[serde(default = "default_registry")]
    registry_file: String,
    #[serde(default = "default_challenge")]
    challenge_file: String,
}

fn default_registry() -> String { DEFAULT_REGISTRY.to_string() }
fn default_challenge() -> String { DEFAULT_CHALLENGE.to_string() }

#[derive(Debug, Serialize, Deserialize)]
struct WalletFile {
    network: String,
    seed_phrase: String,
    bip39_passphrase: String,
    address_index: u32,
    address: String,
    public_key_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RegisteredUser {
    address: String,
    public_key: String,
    registered_at_utc: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ChallengeFile {
    challenge: String,
    issued_at_utc: u64,
    used: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Register { wallet, config } => register(&wallet, &config),
        Command::Challenge { config } => create_challenge(&config),
        Command::Validate { public_key, challenge, wallet } => {
            validate_client(&public_key, &challenge, &wallet)
        }
        Command::Authenticate { public_key, challenge, signature, config } => {
            authenticate(&public_key, &challenge, &signature, &config).await
        }
    }
}

fn register(wallet_path: &Path, config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let wallet = load_wallet(wallet_path)?;

    let mut registry: Vec<RegisteredUser> = load_json_or_default(&config.server.registry_file)?;
    if let Some(existing) = registry.iter_mut().find(|u| u.address == wallet.address) {
        existing.public_key = wallet.public_key_hex.clone();
    } else {
        registry.push(RegisteredUser {
            address: wallet.address.clone(),
            public_key: wallet.public_key_hex.clone(),
            registered_at_utc: now_utc(),
        });
    }
    save_json(&config.server.registry_file, &registry)?;

    println!("registered user.");
    println!("Address: {}", wallet.address);
    println!("Public key: {}", wallet.public_key_hex);
    Ok(())
}

fn create_challenge(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let mut nonce = [0u8; 8];
    OsRng.fill_bytes(&mut nonce);

    let mut bytes = Vec::with_capacity(13);
    bytes.push(CHALLENGE_PREFIX);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&CHALLENGE_SUFFIX);
    let challenge = hex_encode(&bytes);

    let file = ChallengeFile { challenge: challenge.clone(), issued_at_utc: now_utc(), used: false };
    save_json(&config.server.challenge_file, &file)?;

    println!("{}", challenge);
    Ok(())
}

fn validate_client(public_key_hex: &str, challenge_hex: &str, wallet_path: &Path) -> Result<()> {
    let wallet = load_wallet(wallet_path)?;
    let expected_public = wallet.public_key_hex.to_lowercase();
    if expected_public != public_key_hex.to_lowercase() {
        bail!("public key does not belong to the local wallet");
    }
    let challenge = parse_challenge(challenge_hex)?;
    let key = derive_keypair(
        &Mnemonic::parse_in_normalized(Language::English, &wallet.seed_phrase)?,
        &wallet.bip39_passphrase,
        wallet.address_index,
    )?;

    let signature = key.signing_key.sign(&challenge);
    println!("public_key={}", wallet.public_key_hex);
    println!("signature={}", hex_encode(&signature.to_bytes()));
    println!("challenge={}", hex_encode(&challenge));
    Ok(())
}

async fn authenticate(
    public_key_hex: &str,
    challenge_hex: &str,
    signature_hex: &str,
    config_path: &Path,
) -> Result<()> {
    let config = load_config(config_path)?;

    if config.use_blockchain_auth == 0 {
        println!("authenticated user.");
        return Ok(());
    }

    let challenge = parse_challenge(challenge_hex)?;
    let signature_bytes = hex_decode(signature_hex)?;
    let signature = Signature::from_slice(&signature_bytes).context("invalid Ed25519 signature")?;
    let public_bytes = hex_decode(public_key_hex)?;
    let public_key = VerifyingKey::from_bytes(
        public_bytes.as_slice().try_into().map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))?
    ).context("invalid Ed25519 public key")?;

    // Server-side registration check.
    let registry: Vec<RegisteredUser> = load_json_or_default(&config.server.registry_file)?;
    let user = registry.iter().find(|u| u.public_key.eq_ignore_ascii_case(public_key_hex))
        .context("public key is not registered")?;

    // Prove possession of the private key.
    public_key.verify(&challenge, &signature).context("signature verification failed")?;

    // The registered address must be the address derived from this public key.
    let derived_address = address_from_public_key(&public_key.to_bytes());
    if !derived_address.eq_ignore_ascii_case(&user.address) {
        bail!("registered public key does not match registered address");
    }

    // React to current chain state: ownership must exist NOW.
    if !owns_item(&config.mempool.url, &user.address, &config.required_item).await? {
        bail!("authentication failed: required item is not currently owned by this address");
    }

    // A successful authentication consumes the challenge.
    let mut challenge_file: ChallengeFile = load_json_or_default(&config.server.challenge_file)?;
    if !challenge_file.challenge.eq_ignore_ascii_case(challenge_hex) {
        bail!("challenge is not the current server challenge");
    }
    if challenge_file.used {
        bail!("challenge has already been used");
    }
    challenge_file.used = true;
    save_json(&config.server.challenge_file, &challenge_file)?;

    println!("authenticated user.");
    Ok(())
}

async fn owns_item(mempool: &str, address: &str, required_genesis: &str) -> Result<bool> {
    let url = format!("{}/v1/balances/query", mempool.trim_end_matches('/'));
    let body = serde_json::json!({ "addresses": [address] });
    let response = reqwest::Client::new().post(&url).json(&body).send().await
        .with_context(|| format!("failed to contact {url}"))?;
    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() { bail!("Lineage API returned {status}: {text}"); }
    let value: serde_json::Value = serde_json::from_str(&text).context("invalid Lineage JSON")?;

    let root = value.get("balance").unwrap_or(&value);
    let list = root.get("address_list").and_then(|v| v.get(address));
    let Some(entries) = list.and_then(|v| v.as_array()) else { return Ok(false); };

    for entry in entries {
        let Some(item) = entry.get("value").and_then(|v| v.get("Item")) else { continue; };
        let genesis = item.get("genesis_hash").and_then(|v| v.as_str()).unwrap_or_default();
        let amount = item.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
        if amount > 0 && genesis.eq_ignore_ascii_case(required_genesis) {
            return Ok(true);
        }
    }
    Ok(false)
}

struct DerivedKey {
    address: String,
    public_key: [u8; 32],
    signing_key: SigningKey,
}

fn derive_keypair(mnemonic: &Mnemonic, passphrase: &str, index: u32) -> Result<DerivedKey> {
    let seed = mnemonic.to_seed(passphrase);
    let master = Xpriv::new_master(Network::Bitcoin, &seed)
        .context("failed to construct BIP32 master key")?;
    let child = master.derive_priv(
        &bitcoin::secp256k1::Secp256k1::new(),
        &[ChildNumber::from_hardened_idx(index)?],
    ).context("failed to derive Lineage child key")?;

    let xpriv_string = child.to_string();
    let xpriv_bytes = xpriv_string.as_bytes();
    if xpriv_bytes.len() < 32 { bail!("unexpectedly short xpriv string"); }
    let mut ed_seed = [0u8; 32];
    ed_seed.copy_from_slice(&xpriv_bytes[..32]);
    let signing_key = SigningKey::from_bytes(&ed_seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let address = address_from_public_key(&public_key);
    Ok(DerivedKey { address, public_key, signing_key })
}

fn address_from_public_key(public_key: &[u8; 32]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(public_key);
    hex_encode(&hasher.finalize())
}

fn parse_challenge(hex: &str) -> Result<Vec<u8>> {
    let bytes = hex_decode(hex)?;
    if bytes.len() != 13 { bail!("challenge must be exactly 13 bytes"); }
    if bytes[0] != CHALLENGE_PREFIX { bail!("challenge must start with 0x6a"); }
    if bytes[9..13] != CHALLENGE_SUFFIX { bail!("challenge must end with 0xF9BEB4D9"); }
    Ok(bytes)
}

fn load_config(path: &Path) -> Result<GameConfig> {
    let data = fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    toml::from_str(&data).with_context(|| format!("invalid Game.toml: {}", path.display()))
}

fn load_wallet(path: &Path) -> Result<WalletFile> {
    let data = fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&data).with_context(|| format!("invalid wallet file {}", path.display()))
}

fn load_json_or_default<T>(path: &str) -> Result<T>
where T: serde::de::DeserializeOwned + Default {
    if !Path::new(path).exists() { return Ok(T::default()); }
    let data = fs::read_to_string(path).with_context(|| format!("failed to read {path}"))?;
    serde_json::from_str(&data).with_context(|| format!("invalid JSON file {path}"))
}

fn save_json<T: Serialize>(path: &str, value: &T) -> Result<()> {
    fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))
        .with_context(|| format!("failed to write {path}"))
}

fn now_utc() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes { out.push(HEX[(b >> 4) as usize] as char); out.push(HEX[(b & 0x0f) as usize] as char); }
    out
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 { bail!("hex string must have even length"); }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).context("invalid hex")).collect()
}

// Keep the unit visible in the project so token accounting cannot accidentally
// drift into decimal/floating-point arithmetic if this project grows later.
#[allow(dead_code)]
const _LNGX_FRACTION: u64 = TOKEN_FRACTION;
