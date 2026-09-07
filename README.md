# chain_react

Minimal Rust demo of authentication that **reacts to current Lineage chain state**.

The purchased game item is the entitlement. A user authenticates by signing a fresh server challenge with the key corresponding to their registered Lineage address. The server then checks that the address **currently owns the required item**.

If the item is transferred away, authentication fails.

## Configuration

`Game.toml`:

```toml
use_blockchain_auth = 1
required_item = "ge862a974002715c4f45859a5bd6b489"
```

Set `use_blockchain_auth = 0` to bypass the blockchain ownership check for local game development.

## Demo flow

This project expects the `wallet.json` produced by Tiny_wallet for the first test.

Register the wallet with the local demo server registry:

```bash
cargo run -- register
```

Generate a fresh server challenge:

```bash
cargo run -- challenge
```

Sign it with the wallet:

```bash
cargo run -- validate <PUBLIC_KEY> <CHALLENGE>
```

Then authenticate using the returned signature:

```bash
cargo run -- authenticate <PUBLIC_KEY> <CHALLENGE> <SIGNATURE>
```

Successful authentication prints:

```text
authenticated user.
```

The challenge is single-use.

## Challenge format

Exactly 13 bytes:

```text
0x6a + 8-byte random nonce + 0xF9BEB4D9
```

The nonce is generated with the operating system CSPRNG. The exact bytes are signed; no hashing is performed by `chain_react` before Ed25519 signing.

## Chain reaction

Authentication queries:

`POST https://mempool.lineage.to/v1/balances/query`

It looks for an `Item` UTXO with the configured `required_item` genesis hash and a positive amount at the registered address.

Therefore:

```text
owns item -> authentication succeeds
transfers item away -> authentication fails
```

## Security note

This is a local proof-of-concept. `wallet.json` contains plaintext recovery material inherited from the Tiny_wallet demo. Do not use it with meaningful funds.

The separate post-quantum authentication-key design is intentionally left for the next phase.
