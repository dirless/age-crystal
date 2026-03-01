# age-crystal

Crystal bindings to [filippo.io/age](https://github.com/FiloSottile/age) via a Go shared library.

## Why

`filippo.io/age` is the reference implementation of the age encryption format — battle tested,
audited, and maintained by the spec author. Rather than reimplement the cryptography in Crystal,
we wrap the real thing via FFI.

## Requirements

- Crystal >= 1.9.0
- `libage.so` — prebuilt and shipped with releases (see below)

## Installation

Add to your `shard.yml`:

```yaml
dependencies:
  age-crystal:
    github: dirless/age-crystal
```

Copy `libage.so` to a location on your library path (e.g. `/usr/lib/`) or alongside your binary.

### Building `libage.so` from source

For local development (requires Go >= 1.21 on PATH):

```sh
make build
# → libage.so
```

For a production-compatible build matching the RPM target (requires Docker):

```sh
make docker-build
# → dist/libage.so (built inside Amazon Linux 2023)
```

Use `dist/libage.so` for anything going into an RPM.

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

Keys are compatible with the age CLI and any other age implementation:

```sh
# Encrypt in Crystal, decrypt with age CLI
echo "AGE-SECRET-KEY-1..." > key.txt
age --decrypt -i key.txt ciphertext.age
```

## Key Types

- `Age::PublicKey` — wraps `age1...` strings
- `Age::SecretKey` — wraps `AGE-SECRET-KEY-1...` strings
- `Age::Keypair`   — holds both, returned by `Age.keygen`

## Error Handling

All functions raise `Age::Error` on failure.

## License

MIT
