# age-crystal

Pure Crystal implementation of the [age encryption format](https://age-encryption.org/v1)
using OpenSSL (already a Crystal stdlib dependency — no extra native libraries required).

## Why

age is a simple, modern file encryption format. This shard implements it directly in
Crystal over OpenSSL primitives — no Go toolchain, no CGo, no shared library to manage.

The format is interoperable: keys and ciphertext produced by this shard work with the
`age` CLI and any other conforming age implementation.

## Requirements

- Crystal >= 1.20.0
- OpenSSL (already linked by Crystal — no extra setup)

## Installation

Add to your `shard.yml`:

```yaml
dependencies:
  age-crystal:
    github: dirless/age-crystal
```

Run `shards install`. That's it — no native library to build or copy.

## Usage

```crystal
require "age-crystal"

# Generate a keypair
keypair = Age.keygen
puts keypair.public_key  # age1...
puts keypair.secret_key  # AGE-SECRET-KEY-1...

# Encrypt
ciphertext = Age.encrypt("hello world", keypair.public_key)

# Decrypt
plaintext = Age.decrypt_string(ciphertext, keypair.secret_key)
```

Keys are compatible with the `age` CLI and any other age implementation:

```sh
# Encrypt in Crystal, decrypt with age CLI
echo "AGE-SECRET-KEY-1..." > key.txt
age --decrypt -i key.txt ciphertext.age
```

## API

### `Age.keygen`

Returns a fresh `Age::Keypair` with a random X25519 keypair.

### `Age.encrypt`

```crystal
Age.encrypt(data : Bytes | String, recipient : PublicKey) : Bytes
```

Encrypts `data` for `recipient`. Each call produces a different ciphertext
(ephemeral key per encryption).

### `Age.decrypt`

```crystal
Age.decrypt(ciphertext : Bytes, identity : SecretKey) : Bytes
Age.decrypt_string(ciphertext : Bytes, identity : SecretKey) : String
```

## Key types

- `Age::PublicKey` — wraps `age1...` strings
- `Age::SecretKey` — wraps `AGE-SECRET-KEY-1...` strings
- `Age::Keypair`   — holds both, returned by `Age.keygen`

All three validate their format on construction and raise `Age::Error` if invalid.

## Error handling

All functions raise `Age::Error` on failure (bad key format, decryption mismatch, etc.).

## Testing

```sh
crystal spec
```

## License

MIT
