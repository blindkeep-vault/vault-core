# vault-core

Zero-knowledge cryptographic primitives for the [BlindKeep](https://blindkeep.com) vault ecosystem. This crate provides all client-side encryption, key derivation, and protocol logic shared across vault-cli, vault-wasm, vault-mobile, and vault-api.

## Cryptographic primitives

| Primitive | Usage |
|-----------|-------|
| **XChaCha20-Poly1305** | AEAD encryption for items and files |
| **Argon2id** | Password-based key derivation (64 MiB, 3 iterations) |
| **HKDF-SHA256** | Subkey derivation (encryption, wrapping, grants) |
| **X25519** | Ephemeral key exchange for grant sharing |
| **Ed25519** | Notarization signatures (strict verification) |
| **PBKDF2-HMAC-SHA512** | Drop wrapping key derivation (600k iterations) |
| **BIP39** | Mnemonic generation for drops |

## Modules

- **`crypto`** -- Master key derivation, item encryption/decryption (V0/V1 with AAD), key wrapping for recipients and grants, X25519 keypair generation, Ed25519 signing
- **`envelope`** -- SecretBlob serialization, inline envelope decryption, version-aware blob handling
- **`unlock`** -- API key parsing (`vk_PREFIX_SECRET`), master key unwrapping from encrypted storage (V0/V1 auto-detection)
- **`drops`** -- BIP39 mnemonic generation, drop lookup key derivation, wrapping key derivation, drop key wrap/unwrap
- **`padding`** -- Random-padded bucket sizing to prevent length-based traffic analysis
- **`policy`** -- Grant access policies (TTL, max views, allowed operations, IP allowlists)
- **`storage`** -- S3-compatible storage abstraction
- **`types`** -- Shared domain types (User, Item, Grant, AuditEntry)

### Feature flags

| Feature | Enables |
|---------|---------|
| `drops` | BIP39 mnemonic, PBKDF2 drop key derivation |
| `server` | JWT auth (`auth` module), Argon2 hash verification (`hashing` module), HTTP network helpers |

## Security properties

- All key-returning functions use `Zeroizing<[u8; 32]>` wrappers to clear key material from memory on drop
- `MasterKey` implements `Zeroize` with `#[zeroize(drop)]`
- `OsRng` used exclusively for all randomness (no `thread_rng`)
- Low-order X25519 point rejection (all-zero shared secret check)
- JWT algorithm pinned to HS256 to prevent confusion attacks
- V1 ciphertext format binds AAD (user ID, context) to prevent ciphertext relocation

## Usage

```toml
[dependencies]
vault-core = { git = "ssh://git@github.com/blindkeep-vault/vault-core.git" }

# With drops support
vault-core = { git = "ssh://git@github.com/blindkeep-vault/vault-core.git", features = ["drops"] }
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT), at your option.
