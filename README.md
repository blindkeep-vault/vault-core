# vault-core

Zero-knowledge cryptographic primitives for [BlindKeep](https://blindkeep.com) Vault.

All encryption and key management happens client-side. The server never sees plaintext data or master keys.

## Primitives

| Function | Algorithm | Purpose |
|---|---|---|
| `derive_master_key` | Argon2id (64 MiB, 3 iter) | Password to master key |
| `derive_subkey` | HKDF-SHA256 | Master key to purpose-specific subkeys |
| `encrypt_item` / `decrypt_item` | XChaCha20-Poly1305 | Authenticated encryption with 24-byte nonces |
| `wrap_key_for_recipient` / `unwrap_key` | X25519 + HKDF + XChaCha20-Poly1305 | Asymmetric key wrapping for grant sharing |

## Policy Engine

The `Policy` struct controls access to shared grants:

- Absolute expiry (`expires_at`)
- TTL from first access (`ttl_seconds`)
- View count limits (`max_views`)
- Operation allowlists (`allowed_ops`)
- IP allowlists with CIDR support (`ip_allowlist`)

## Build

```bash
cargo build
cargo test
```

Requires Rust 1.70+.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
vault-core = { git = "ssh://git@github.com/blindkeep-vault/vault-core.git" }
```

```rust
use vault_core::crypto::{derive_master_key, encrypt_item, decrypt_item};

// Derive a master key from a password
let master = derive_master_key(b"password", b"salt-at-least-16b").unwrap();

// Encrypt
let payload = encrypt_item(master.as_bytes(), b"secret data").unwrap();

// Decrypt
let plaintext = decrypt_item(master.as_bytes(), &payload.ciphertext, &payload.nonce).unwrap();
assert_eq!(plaintext, b"secret data");
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT), at your option.

## Acknowledgments

- **Maarten Boone** — Cryptographic review
