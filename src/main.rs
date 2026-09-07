use anyhow::{bail, Context, Result};
use bip39::{Language, Mnemonic};
use bitcoin::{
    bip32::{ChildNumber, Xpriv},
    Network,
};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Signer, Verifier, SigningKey, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const DEFAULT_MEMPOOL: &str = "https://mempool.lineage.to";
const DEFAULT_GAME_CONFIG: &str = "Game.toml";
const DEFAULT_WALLET: &str = "wallet.json";
const DEFAULT_REGISTRY: &str = "registry.json";
const DEFAULT_CHALLENGE: &str = "challenge.json";

const TOKEN_FRACTION: u64 = 72_072_000;

const CHALLENGE_PREFIX: u8 = 0x6a;
const CHALLENGE_SUFFIX: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];

#[derive(Parser)]
#[command(
    name = "chain_react",
    about = "Minimal client/server chain-state authentication demo"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Register one wallet address and its public key in the local server registry.
    ///
    /// If --address-index is omitted, the highest registered wallet address is used.
    Register {
        #[arg(short, long, default_value = DEFAULT_WALLET)]
        wallet: PathBuf,

        #[arg(short, long, default_value = DEFAULT_GAME_CONFIG)]
        config: PathBuf,

        #[arg(long)]
        address_index: Option<u32>,
    },

    /// Generate and store a server challenge.
    Challenge {
        #[arg(short, long, default_value = DEFAULT_GAME_CONFIG)]
        config: PathBuf,
    },

    /// Sign a server challenge with the private key matching the supplied public key.
    ///
    /// If --address-index is supplied, that wallet address is used.
    /// Otherwise the wallet address whose public key matches the supplied public key
    /// is selected.
    Validate {
        public_key: String,
        challenge: String,

        #[arg(short, long, default_value = DEFAULT_WALLET)]
        wallet: PathBuf,

        #[arg(long)]
        address_index: Option<u32>,
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
struct MempoolConfig {
    #[serde(default = "default_mempool")]
    url: String,
}

#[derive(Debug, Deserialize)]
struct ServerConfig {
    #[serde(default = "default_registry")]
    registry_file: String,

    #[serde(default = "default_challenge")]
    challenge_file: String,
}

fn default_mempool() -> String {
    DEFAULT_MEMPOOL.to_string()
}

fn default_registry() -> String {
    DEFAULT_REGISTRY.to_string()
}

fn default_challenge() -> String {
    DEFAULT_CHALLENGE.to_string()
}


// -----------------------------------------------------------------------------
// Tiny Wallet format
// -----------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct WalletFile {
    network: String,
    seed_phrase: String,
    bip39_passphrase: String,

    #[serde(default)]
    addresses: Vec<WalletAddress>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct WalletAddress {
    index: u32,
    address: String,
    public_key_hex: String,
}


// -----------------------------------------------------------------------------
// Server registry
// -----------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone)]
struct RegisteredUser {
    address: String,
    public_key: String,

    #[serde(default)]
    address_index: Option<u32>,

    registered_at_utc: u64,
}


// -----------------------------------------------------------------------------
// Challenge
// -----------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
struct ChallengeFile {
    challenge: String,
    issued_at_utc: u64,
    used: bool,
}


// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Register {
            wallet,
            config,
            address_index,
        } => register(&wallet, &config, address_index),

        Command::Challenge { config } => {
            create_challenge(&config)
        }

        Command::Validate {
            public_key,
            challenge,
            wallet,
            address_index,
        } => {
            validate_client(
                &public_key,
                &challenge,
                &wallet,
                address_index,
            )
        }

        Command::Authenticate {
            public_key,
            challenge,
            signature,
            config,
        } => {
            authenticate(
                &public_key,
                &challenge,
                &signature,
                &config,
            )
            .await
        }
    }
}


// -----------------------------------------------------------------------------
// Register
// -----------------------------------------------------------------------------

fn register(
    wallet_path: &Path,
    config_path: &Path,
    address_index: Option<u32>,
) -> Result<()> {
    let config = load_config(config_path)?;
    let wallet = load_wallet(wallet_path)?;

    let selected = select_wallet_address(&wallet, address_index)?;

    let mut registry: Vec<RegisteredUser> =
        load_json_or_default(&config.server.registry_file)?;

    if let Some(existing) = registry
        .iter_mut()
        .find(|u| u.address.eq_ignore_ascii_case(&selected.address))
    {
        existing.public_key = selected.public_key_hex.clone();
        existing.address_index = Some(selected.index);
        existing.registered_at_utc = now_utc();
    } else {
        registry.push(RegisteredUser {
            address: selected.address.clone(),
            public_key: selected.public_key_hex.clone(),
            address_index: Some(selected.index),
            registered_at_utc: now_utc(),
        });
    }

    save_json(&config.server.registry_file, &registry)?;

    println!("registered user.");
    println!("Address index: {}", selected.index);
    println!("Address: {}", selected.address);
    println!("Public key: {}", selected.public_key_hex);

    Ok(())
}


// -----------------------------------------------------------------------------
// Challenge generation
// -----------------------------------------------------------------------------

fn create_challenge(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;

    let mut nonce = [0u8; 8];
    OsRng.fill_bytes(&mut nonce);

    let mut bytes = Vec::with_capacity(13);

    bytes.push(CHALLENGE_PREFIX);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&CHALLENGE_SUFFIX);

    let challenge = hex_encode(&bytes);

    let file = ChallengeFile {
        challenge: challenge.clone(),
        issued_at_utc: now_utc(),
        used: false,
    };

    save_json(&config.server.challenge_file, &file)?;

    println!("{}", challenge);

    Ok(())
}


// -----------------------------------------------------------------------------
// Client-side validation / signing
// -----------------------------------------------------------------------------

fn validate_client(
    public_key_hex: &str,
    challenge_hex: &str,
    wallet_path: &Path,
    address_index: Option<u32>,
) -> Result<()> {
    let wallet = load_wallet(wallet_path)?;

    let selected = if let Some(index) = address_index {
        let address = wallet
            .addresses
            .iter()
            .find(|a| a.index == index)
            .with_context(|| {
                format!(
                    "wallet does not contain registered address index {}",
                    index
                )
            })?;

        if !address
            .public_key_hex
            .eq_ignore_ascii_case(public_key_hex)
        {
            bail!(
                "public key does not belong to wallet address index {}",
                index
            );
        }

        address.clone()
    } else {
        wallet
            .addresses
            .iter()
            .find(|a| a.public_key_hex.eq_ignore_ascii_case(public_key_hex))
            .cloned()
            .with_context(|| {
                "public key does not belong to any address in the local wallet"
            })?
    };

    let challenge = parse_challenge(challenge_hex)?;

    let mnemonic = Mnemonic::parse_in_normalized(
        Language::English,
        &wallet.seed_phrase,
    )?;

    let key = derive_keypair(
        &mnemonic,
        &wallet.bip39_passphrase,
        selected.index,
    )?;

    // Make sure the wallet file and derivation algorithm agree.
    if !key
        .public_key
        .iter()
        .zip(hex_decode(&selected.public_key_hex)?)
        .all(|(a, b)| *a == b)
    {
        bail!(
            "derived public key does not match wallet.json for address index {}",
            selected.index
        );
    }

    if !key.address.eq_ignore_ascii_case(&selected.address) {
        bail!(
            "derived address does not match wallet.json for address index {}",
            selected.index
        );
    }

    let signature = key.signing_key.sign(&challenge);

    println!("public_key={}", selected.public_key_hex);
    println!("address_index={}", selected.index);
    println!("address={}", selected.address);
    println!("signature={}", hex_encode(&signature.to_bytes()));
    println!("challenge={}", hex_encode(&challenge));

    Ok(())
}


// -----------------------------------------------------------------------------
// Server-side authentication
// -----------------------------------------------------------------------------

async fn authenticate(
    public_key_hex: &str,
    challenge_hex: &str,
    signature_hex: &str,
    config_path: &Path,
) -> Result<()> {
    let config = load_config(config_path)?;

    // Development bypass.
    if config.use_blockchain_auth == 0 {
        println!("authenticated user.");
        return Ok(());
    }

    // Parse and validate supplied cryptographic material.
    let challenge = parse_challenge(challenge_hex)?;

    let signature_bytes = hex_decode(signature_hex)?;

    let signature = Signature::from_slice(&signature_bytes)
        .context("invalid Ed25519 signature")?;

    let public_bytes = hex_decode(public_key_hex)?;

    let public_key = VerifyingKey::from_bytes(
        public_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))?,
    )
    .context("invalid Ed25519 public key")?;

    // -------------------------------------------------------------------------
    // 1. Server-side registration check
    // -------------------------------------------------------------------------

    let registry: Vec<RegisteredUser> =
        load_json_or_default(&config.server.registry_file)?;

    let user = registry
        .iter()
        .find(|u| {
            u.public_key
                .eq_ignore_ascii_case(public_key_hex)
        })
        .context("public key is not registered")?;

    // -------------------------------------------------------------------------
    // 2. Prove possession of the private key
    // -------------------------------------------------------------------------

    public_key
        .verify(&challenge, &signature)
        .context("signature verification failed")?;

    // -------------------------------------------------------------------------
    // 3. Derive the Lineage address from the public key
    // -------------------------------------------------------------------------

    let derived_address =
        address_from_public_key(&public_key.to_bytes());

    if !derived_address.eq_ignore_ascii_case(&user.address) {
        bail!("registered public key does not match registered address");
    }

    // -------------------------------------------------------------------------
    // 4. React to current chain state
    //
    // The entitlement must be owned NOW.
    //
    // This deliberately does not trust registration state. If the item has
    // subsequently been transferred away, authentication fails.
    // -------------------------------------------------------------------------

    if !owns_item(
        &config.mempool.url,
        &user.address,
        &config.required_item,
    )
    .await?
    {
        bail!(
            "authentication failed: required item is not currently owned by this address"
        );
    }

    // -------------------------------------------------------------------------
    // 5. Verify that this is the current server challenge
    // -------------------------------------------------------------------------

    let mut challenge_file: ChallengeFile =
        load_json_or_default(&config.server.challenge_file)?;

    if !challenge_file
        .challenge
        .eq_ignore_ascii_case(challenge_hex)
    {
        bail!("challenge is not the current server challenge");
    }

    // -------------------------------------------------------------------------
    // 6. Prevent replay
    // -------------------------------------------------------------------------

    if challenge_file.used {
        bail!("challenge has already been used");
    }

    challenge_file.used = true;

    save_json(
        &config.server.challenge_file,
        &challenge_file,
    )?;

    println!("authenticated user.");
    println!("Address: {}", user.address);

    Ok(())
}


// -----------------------------------------------------------------------------
// Lineage chain-state ownership
// -----------------------------------------------------------------------------

async fn owns_item(
    mempool: &str,
    address: &str,
    required_genesis: &str,
) -> Result<bool> {
    let url = format!(
        "{}/v1/balances/query",
        mempool.trim_end_matches('/')
    );

    let body = serde_json::json!({
        "addresses": [address]
    });

    let response = reqwest::Client::new()
        .post(&url)
        .json(&body)
        .send()
        .await
        .with_context(|| {
            format!("failed to contact {url}")
        })?;

    let status = response.status();
    let text = response.text().await?;

    if !status.is_success() {
        bail!(
            "Lineage API returned {status}: {text}"
        );
    }

    let value: serde_json::Value =
        serde_json::from_str(&text)
            .context("invalid Lineage JSON")?;

    // Current Lineage /v1/balances/query response places the balance
    // information under the top-level "balance" field.
    //
    // Keeping the fallback to the root makes this tolerant of the older
    // response shape as well.
    let root = value
        .get("balance")
        .unwrap_or(&value);

    let list = root
        .get("address_list")
        .and_then(|v| v.get(address));

    let Some(entries) = list.and_then(|v| v.as_array()) else {
        return Ok(false);
    };

    for entry in entries {
        let Some(item) = entry
            .get("value")
            .and_then(|v| v.get("Item"))
        else {
            continue;
        };

        let genesis = item
            .get("genesis_hash")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        let amount = item
            .get("amount")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        if amount > 0
            && genesis.eq_ignore_ascii_case(required_genesis)
        {
            return Ok(true);
        }
    }

    Ok(false)
}


// -----------------------------------------------------------------------------
// Tiny Wallet address selection
// -----------------------------------------------------------------------------

fn select_wallet_address(
    wallet: &WalletFile,
    requested_index: Option<u32>,
) -> Result<WalletAddress> {
    if wallet.addresses.is_empty() {
        bail!(
            "wallet contains no addresses; create an address with Tiny Wallet first"
        );
    }

    if let Some(index) = requested_index {
        return wallet
            .addresses
            .iter()
            .find(|a| a.index == index)
            .cloned()
            .with_context(|| {
                format!(
                    "wallet does not contain address index {}",
                    index
                )
            });
    }

    // Tiny Wallet creates monotonically increasing address indices.
    // Use the highest registered index as the default.
    wallet
        .addresses
        .iter()
        .max_by_key(|a| a.index)
        .cloned()
        .context("wallet contains no addresses")
}


// -----------------------------------------------------------------------------
// Key derivation
// -----------------------------------------------------------------------------

struct DerivedKey {
    address: String,
    public_key: [u8; 32],
    signing_key: SigningKey,
}

fn derive_keypair(
    mnemonic: &Mnemonic,
    passphrase: &str,
    index: u32,
) -> Result<DerivedKey> {
    // This deliberately mirrors Tiny Wallet's current derivation scheme:
    //
    // BIP39 mnemonic + BIP39 passphrase
    //        ↓
    // BIP32 master
    //        ↓
    // hardened child at address index
    //        ↓
    // child xpriv string
    //        ↓
    // first 32 ASCII bytes
    //        ↓
    // Ed25519 seed
    //        ↓
    // public key
    //        ↓
    // SHA3-256(public key)
    //        ↓
    // Lineage address

    let seed = mnemonic.to_seed(passphrase);

    let master = Xpriv::new_master(
        Network::Bitcoin,
        &seed,
    )
    .context("failed to construct BIP32 master key")?;

    let child = master
        .derive_priv(
            &bitcoin::secp256k1::Secp256k1::new(),
            &[ChildNumber::from_hardened_idx(index)?],
        )
        .context("failed to derive Lineage child key")?;

    let xpriv_string = child.to_string();
    let xpriv_bytes = xpriv_string.as_bytes();

    if xpriv_bytes.len() < 32 {
        bail!("unexpectedly short xpriv string");
    }

    let mut ed_seed = [0u8; 32];

    ed_seed.copy_from_slice(&xpriv_bytes[..32]);

    let signing_key = SigningKey::from_bytes(&ed_seed);

    let public_key =
        signing_key.verifying_key().to_bytes();

    let address =
        address_from_public_key(&public_key);

    Ok(DerivedKey {
        address,
        public_key,
        signing_key,
    })
}


// -----------------------------------------------------------------------------
// Lineage address
// -----------------------------------------------------------------------------

fn address_from_public_key(
    public_key: &[u8; 32],
) -> String {
    let mut hasher = Sha3_256::new();

    hasher.update(public_key);

    hex_encode(&hasher.finalize())
}


// -----------------------------------------------------------------------------
// Challenge parsing
// -----------------------------------------------------------------------------

fn parse_challenge(hex: &str) -> Result<Vec<u8>> {
    let bytes = hex_decode(hex)?;

    if bytes.len() != 13 {
        bail!("challenge must be exactly 13 bytes");
    }

    if bytes[0] != CHALLENGE_PREFIX {
        bail!("challenge must start with 0x6a");
    }

    if bytes[9..13] != CHALLENGE_SUFFIX {
        bail!("challenge must end with 0xF9BEB4D9");
    }

    Ok(bytes)
}


// -----------------------------------------------------------------------------
// Config / wallet / JSON
// -----------------------------------------------------------------------------

fn load_config(path: &Path) -> Result<GameConfig> {
    let data = fs::read_to_string(path)
        .with_context(|| {
            format!(
                "failed to read {}",
                path.display()
            )
        })?;

    toml::from_str(&data)
        .with_context(|| {
            format!(
                "invalid Game.toml: {}",
                path.display()
            )
        })
}

fn load_wallet(path: &Path) -> Result<WalletFile> {
    let data = fs::read_to_string(path)
        .with_context(|| {
            format!(
                "failed to read {}",
                path.display()
            )
        })?;

    let wallet: WalletFile =
        serde_json::from_str(&data)
            .with_context(|| {
                format!(
                    "invalid Tiny Wallet file {}",
                    path.display()
                )
            })?;

    if wallet.addresses.is_empty() {
        bail!(
            "wallet.json contains no addresses; \
             this chain_react version expects the new Tiny Wallet format"
        );
    }

    Ok(wallet)
}

fn load_json_or_default<T>(
    path: &str,
) -> Result<T>
where
    T: serde::de::DeserializeOwned + Default,
{
    if !Path::new(path).exists() {
        return Ok(T::default());
    }

    let data = fs::read_to_string(path)
        .with_context(|| {
            format!("failed to read {path}")
        })?;

    serde_json::from_str(&data)
        .with_context(|| {
            format!("invalid JSON file {path}")
        })
}

fn save_json<T: Serialize>(
    path: &str,
    value: &T,
) -> Result<()> {
    fs::write(
        path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(value)?
        ),
    )
    .with_context(|| {
        format!("failed to write {path}")
    })
}


// -----------------------------------------------------------------------------
// Miscellaneous
// -----------------------------------------------------------------------------

fn now_utc() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] =
        b"0123456789abcdef";

    let mut out =
        String::with_capacity(bytes.len() * 2);

    for &b in bytes {
        out.push(
            HEX[(b >> 4) as usize] as char
        );

        out.push(
            HEX[(b & 0x0f) as usize] as char
        );
    }

    out
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        bail!("hex string must have even length");
    }

    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(
                &s[i..i + 2],
                16,
            )
            .context("invalid hex")
        })
        .collect()
}


// Keep the unit visible in the project so token accounting
// cannot accidentally drift into decimal/floating-point
// arithmetic if this project grows later.
#[allow(dead_code)]
const _LNGX_FRACTION: u64 = TOKEN_FRACTION;