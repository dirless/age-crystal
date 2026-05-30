# age-crystal

Pure Crystal implementation of the [age encryption format](https://age-encryption.org/v1). No Go toolchain, no CGo — built directly on OpenSSL primitives via Crystal's stdlib.

## What it does

Encrypts and decrypts data using the age format (X25519 key exchange + ChaCha20-Poly1305 + Bech32 key encoding). Keys and ciphertext are interoperable with the `age` CLI and other conforming implementations.

## Language / stack

- Crystal >= 1.20.0
- No external shard dependencies (uses Crystal's OpenSSL bindings)

## Key entry points

| File | Purpose |
|------|---------|
| `src/age/age.cr` | Public API: `Age.keygen`, `Age.encrypt`, `Age.decrypt`, `Age.decrypt_string` |
| `src/age/keys.cr` | `Age::PublicKey`, `Age::SecretKey`, `Age::Keypair` types with Bech32 validation |
| `src/age/x25519.cr` | X25519 key exchange |
| `src/age/chacha20poly1305.cr` | Symmetric encryption |
| `src/age/hkdf.cr` | Key derivation |
| `src/age/format.cr` | age binary format encoding/decoding |
| `src/age/stream.cr` | Streaming encryption chunks |
| `src/age/bech32.cr` | Bech32 encoding for `age1…` and `AGE-SECRET-KEY-1…` keys |

## Build & test

```sh
shards install
crystal spec
```

## Error handling

All public API functions raise `Age::Error` on failure (bad key format, wrong key, corrupt ciphertext).

## Used by

`dirless-cli` — generates age keypairs during node enrollment and stores the secret key at `/etc/dirless/age.key`.
