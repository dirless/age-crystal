# age-crystal

Pure Crystal implementation of the [age encryption format](https://age-encryption.org/v1).

## Why

age is a simple, modern file encryption format. This shard implements it directly in
Crystal with pure Crystal cryptographic primitives — no OpenSSL, no external C libraries.

The format is interoperable: keys and ciphertext produced by this shard work with the
`age` CLI and any other conforming age implementation.

## Requirements

- Crystal >= 1.20.0

## Installation

Add to your `shard.yml`:

```yaml
dependencies:
  age-crystal:
    github: dirless/age-crystal
```

Run `shards install`.

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

### `Age.keypair_from_secret`

```crystal
Age.keypair_from_secret(secret_key : String) : Keypair
```

Reconstructs the full keypair from an existing secret key string. Use this when you
need the corresponding public key without generating a new keypair (e.g. re-enrollment
with an existing key).

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

Apache-2.0
