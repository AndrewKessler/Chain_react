# chain_react

Minimal Lineage chain-state authentication demo for games and other
applications.

`chain_react` demonstrates a simple entitlement-gated authentication
flow:

1.  A wallet address/public key is registered by the server.
2.  The server generates a one-time challenge.
3.  The client signs the challenge with the private key for the selected
    Lineage address.
4.  The server verifies the Ed25519 signature.
5.  The server derives the Lineage address from the supplied public key
    and checks it against the registered identity.
6.  The server queries the current Lineage chain state.
7.  Authentication succeeds only if the required Item is currently owned
    by that address.
8.  The challenge is consumed so it cannot be replayed.

The project is intentionally separate from `Tiny_wallet`. Tiny Wallet
manages keys, addresses, balances and assets; `chain_react` demonstrates
application-level authentication based on cryptographic identity plus
current on-chain entitlement.

## Requirements

-   Rust / Cargo
-   A Lineage `wallet.json` produced by Tiny Wallet
-   A `Game.toml` configuration file
-   Network access to the Lineage mempool API when blockchain
    authentication is enabled

The default Lineage mempool endpoint is:

`https://mempool.lineage.to`

## Wallet format

`chain_react` uses the current multi-address Tiny Wallet format.

Example:

``` json
{
  "network": "lineage-testnet",
  "seed_phrase": "...",
  "bip39_passphrase": "...",
  "addresses": [
    {
      "index": 0,
      "address": "bc18377aace9a2bdc6052ad7c5a8172f52a3eb30bdf1b1dd1d6d25dbacbc6803",
      "public_key_hex": "8b1d609337e8e9e1c80ab9c9fb96fdc1f0b656a9d8dd63e624da8d4cae749b73"
    },
    {
      "index": 1,
      "address": "...",
      "public_key_hex": "..."
    }
  ]
}
```

The wallet can contain any number of registered addresses.

`chain_react` does not create or modify wallet addresses. It reads the
wallet and derives the private key for the selected address when signing
a challenge.

## Address selection

Commands that operate on a wallet can select an address with:

``` bash
--address-index 0
```

If `--address-index` is omitted when registering, `chain_react` uses the
highest registered address index.

For `validate`, if no address index is supplied, the program searches
the wallet for the address whose public key matches the supplied public
key.

This allows multiple Lineage addresses to coexist in one Tiny Wallet
while still allowing each address to act as a separate game identity.

## Configuration

Create `Game.toml`:

``` toml
use_blockchain_auth = 1
required_item = "YOUR_ITEM_GENESIS_HASH"

[mempool]
url = "https://mempool.lineage.to"

[server]
registry_file = "registry.json"
challenge_file = "challenge.json"
```

### `use_blockchain_auth`

Set:

``` toml
use_blockchain_auth = 1
```

to require real blockchain authentication.

Set:

``` toml
use_blockchain_auth = 0
```

to bypass authentication for local development.

The bypass should not be used for a production game server.

### `required_item`

This is the Lineage Item genesis hash that represents the entitlement
required to authenticate.

For example, a game could mint a unique Item representing:

-   ownership of the game
-   ownership of an episode
-   a DLC entitlement
-   a founder pass
-   a server membership
-   another application-specific right

`chain_react` treats the metadata of the Item as opaque. It only checks
the Item's genesis hash and that its current amount is greater than
zero.

## Commands

### Register an address

Register the highest address in the Tiny Wallet:

``` bash
cargo run -- register
```

Register a specific address:

``` bash
cargo run -- register --address-index 0
```

or:

``` bash
cargo run -- register --address-index 1
```

The server registry is stored in the file specified by:

``` toml
[server]
registry_file = "registry.json"
```

A registry entry contains:

``` json
{
  "address": "...",
  "public_key": "...",
  "address_index": 1,
  "registered_at_utc": 1750000000
}
```

The `address_index` is informational. The cryptographic identity remains
the Lineage address/public-key pair.

### Create a challenge

Run:

``` bash
cargo run -- challenge
```

The command prints a challenge such as:

``` text
6a........................f9beb4d9
```

and stores it in `challenge.json`.

The challenge contains:

-   a fixed prefix
-   an 8-byte cryptographically random nonce
-   a fixed suffix

The random nonce is what provides freshness. The challenge is also
marked as used after successful authentication.

### Sign a challenge

Given a registered public key:

``` bash
cargo run -- validate <PUBLIC_KEY> <CHALLENGE>
```

Example:

``` bash
cargo run -- validate \
  8b1d609337e8e9e1c80ab9c9fb96fdc1f0b656a9d8dd63e624da8d4cae749b73 \
  6a1234567890abcdeff9beb4d9
```

The client prints:

``` text
public_key=...
address_index=0
address=...
signature=...
challenge=...
```

A specific address can also be selected:

``` bash
cargo run -- validate <PUBLIC_KEY> <CHALLENGE> --address-index 0
```

When an address index is supplied, `chain_react` verifies that the
supplied public key belongs to that address.

When no index is supplied, it searches the wallet for the matching
public key.

### Authenticate

The server receives:

``` bash
cargo run -- authenticate <PUBLIC_KEY> <CHALLENGE> <SIGNATURE>
```

For example:

``` bash
cargo run -- authenticate \
  8b1d609337e8e9e1c80ab9c9fb96fdc1f0b656a9d8dd63e624da8d4cae749b73 \
  6a1234567890abcdeff9beb4d9 \
  <SIGNATURE>
```

Successful authentication prints:

``` text
authenticated user.
Address: ...
```

## Authentication flow

The complete flow is:

``` text
                     ┌──────────────────┐
                     │   Game Server    │
                     └────────┬─────────┘
                              │
                        create challenge
                              │
                              ▼
                     ┌──────────────────┐
                     │    Challenge     │
                     │ random nonce     │
                     └────────┬─────────┘
                              │
                              ▼
                     ┌──────────────────┐
                     │  Game / Client   │
                     │                  │
                     │ Tiny Wallet      │
                     │ derives key      │
                     │ signs challenge  │
                     └────────┬─────────┘
                              │
                     public key +
                     signature +
                     challenge
                              │
                              ▼
                     ┌──────────────────┐
                     │   Game Server    │
                     └────────┬─────────┘
                              │
              ┌───────────────┼────────────────┐
              │               │                │
              ▼               ▼                ▼
        Registry check   Ed25519 verify   Derive address
                                              from public key
              │               │                │
              └───────────────┼────────────────┘
                              │
                              ▼
                    Check current Lineage
                         chain state
                              │
                              ▼
                   Required Item owned?
                         /        \
                       YES         NO
                        │           │
                        ▼           ▼
                  authenticate    reject
                        │
                        ▼
                  consume challenge
```

## Why the chain-state check matters

Registration does not permanently grant the entitlement.

The server checks the current Lineage state at authentication time.

For example:

``` text
Day 1:
User owns game Item
        ↓
Authentication succeeds

Day 2:
User transfers Item away
        ↓
Authentication fails
```

This means the Item acts as a live, transferable entitlement.

The server does not need to maintain a separate database saying that the
user owns the game. It can ask the Lineage network whether the address
currently owns the required Item.

## Current Lineage balance response

The current balance endpoint is:

``` text
POST /v1/balances/query
```

`chain_react` looks under:

``` text
balance
└── address_list
    └── <address>
        └── value
            └── Item
                ├── amount
                ├── genesis_hash
                └── metadata
```

An Item satisfies the entitlement check when:

``` text
amount > 0
```

and:

``` text
genesis_hash == required_item
```

The comparison is case-insensitive.

The Item metadata is not interpreted by `chain_react`.

## Key derivation

The key derivation intentionally mirrors the current Tiny Wallet
derivation.

The process is:

``` text
BIP39 mnemonic
      +
BIP39 passphrase
      │
      ▼
BIP39 seed
      │
      ▼
BIP32 master key
      │
      ▼
hardened child at address index
      │
      ▼
child xpriv string
      │
      ▼
first 32 ASCII bytes
      │
      ▼
Ed25519 seed
      │
      ▼
Ed25519 public key
      │
      ▼
SHA3-256(public key)
      │
      ▼
Lineage address
```

`chain_react` verifies the derived public key and address against the
corresponding entries in `wallet.json` before signing.

This is important because it prevents a corrupted or mismatched wallet
registry entry from silently producing a different identity.

## Server registry

The server maintains a local registry such as:

``` json
[
  {
    "address": "bc18377aace9a2bdc6052ad7c5a8172f52a3eb30bdf1b1dd1d6d25dbacbc6803",
    "public_key": "8b1d609337e8e9e1c80ab9c9fb96fdc1f0b656a9d8dd63e624da8d4cae749b73",
    "address_index": 0,
    "registered_at_utc": 1750000000
  }
]
```

The registry is deliberately separate from `wallet.json`.

The server needs to know which public keys/addresses it is willing to
recognize. It does not need the user's mnemonic or private key.

## Security model

The authentication proof has three distinct components.

### 1. Registered identity

The public key must already exist in the server registry.

### 2. Proof of private-key possession

The client signs the fresh challenge with Ed25519.

The server verifies:

``` text
Verify(public_key, challenge, signature)
```

Possession of the public key alone is therefore insufficient.

### 3. Current blockchain entitlement

The address derived from the public key must currently own the required
Item.

The three conditions together are:

``` text
registered identity
        AND
private-key possession
        AND
current Item ownership
        =
authenticated
```

## Replay protection

A challenge is generated by:

``` bash
cargo run -- challenge
```

The challenge is stored in `challenge.json`.

After successful authentication:

``` text
used = true
```

A second authentication attempt using the same challenge is rejected.

A challenge also has to equal the current server challenge.

Therefore an old challenge cannot simply be replayed after a new
challenge has been issued.

## Important current limitations

This is a deliberately small authentication demonstration rather than a
production authentication service.

### Global challenge

There is currently one active challenge in `challenge.json`.

That means the design is appropriate for a simple prototype or
single-client demonstration, but a production multiplayer server would
normally create challenges per connection/session.

### Local registry

The registry is a local JSON file.

A production service could replace this with a database or another
durable identity registry.

### Development bypass

`use_blockchain_auth = 0` disables authentication.

This is useful while developing the game, but should be disabled in
production.

### Ed25519

The current authentication proof uses Ed25519.

It is not a post-quantum authentication scheme.

Post-quantum authentication can be considered separately without
changing the basic architecture of:

``` text
challenge
    +
proof of key possession
    +
current chain-state entitlement
```

## Relationship with Tiny Wallet

The intended division is:

``` text
Tiny Wallet
│
├── mnemonic
├── BIP39 passphrase
├── address derivation
├── multiple addresses
├── balances
├── LNGX
└── Item minting
        │
        │ wallet.json
        ▼
chain_react
│
├── select identity
├── sign challenge
├── server registry
├── verify signature
├── derive address
├── query Lineage state
└── authenticate
```

`chain_react` should not grow into another wallet implementation.

Tiny Wallet remains the small wallet utility; `chain_react` remains the
application authentication experiment.

## Typical development test

A simple local test sequence is:

### 1. Make sure the wallet has an address

``` bash
cargo run -- address
```

### 2. Check its balance

``` bash
cargo run -- balance
```

### 3. Register the desired address with chain_react

``` bash
cargo run -- register --address-index 0
```

### 4. Create a challenge

``` bash
cargo run -- challenge
```

Copy the printed challenge.

### 5. Sign the challenge

``` bash
cargo run -- validate <PUBLIC_KEY> <CHALLENGE>
```

Copy the signature.

### 6. Authenticate

``` bash
cargo run -- authenticate <PUBLIC_KEY> <CHALLENGE> <SIGNATURE>
```

If the public key is registered, the signature is valid, the derived
address matches the registry, the challenge is current and unused, and
the required Item is currently owned, authentication succeeds.

### 7. Try the same challenge again

Run the authentication command again.

It should fail with:

``` text
challenge has already been used
```

### 8. Transfer the entitlement Item

If the required Item is transferred away from the registered address,
repeat the authentication flow with a new challenge.

Authentication should fail because the Item is no longer currently
owned.

## Files

Typical project files:

``` text
chain_react/
├── Cargo.toml
├── Game.toml
├── src/
│   └── main.rs
├── registry.json
└── challenge.json
```

`wallet.json` normally comes from Tiny Wallet and should not be
committed to source control.

## Do not commit wallet secrets

Never commit:

``` text
wallet.json
```

to Git.

The wallet contains the mnemonic and BIP39 passphrase.

A suitable `.gitignore` entry is:

``` gitignore
/wallet.json
/target/
```

`registry.json` and `challenge.json` do not contain the wallet's private
key material, but whether they should be committed depends on how the
server is deployed.

## Design principle

The central idea of `chain_react` is that authentication does not have
to mean:

``` text
username + password
```

It can instead mean:

``` text
"I control this cryptographic identity"
            +
"This identity currently possesses this on-chain entitlement"
```

That makes the blockchain Item a live authorization primitive rather
than merely a record of ownership.
