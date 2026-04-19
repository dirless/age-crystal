# age-crystal

Crystal bindings to [filippo.io/age](https://github.com/FiloSottile/age) via a Go shared library.

## Why

`filippo.io/age` is the reference implementation of the age encryption format — battle tested,
audited, and maintained by the spec author. Rather than reimplement the cryptography in Crystal,
we wrap the real thing via FFI.

## Requirements

- Crystal >= 1.9.0
- `libage.so` (dynamic) or `libage.a` (static) — prebuilt and shipped with releases (see below)

## Installation

Add to your `shard.yml`:

```yaml
dependencies:
  age-crystal:
    github: dirless/age-crystal
```

### Dynamic linking (default)

Copy `libage.so` to a location on your library path (e.g. `/usr/lib/`) or alongside your binary.

### Static linking

Download `libage-linux-amd64.tar.gz` from the [latest release](https://github.com/dirless/age-crystal/releases/latest),
extract it, and pass the archive to the Crystal compiler:

```sh
tar -xzf libage-linux-amd64.tar.gz  # → libage.a, libage.h
crystal build src/your_app.cr --link-flags "/path/to/libage.a"
```

This produces a fully self-contained binary with no runtime `.so` dependency.

### Building from source

For local development (requires Go >= 1.21 on PATH):

```sh
make build
# → libage.so
```

For a dynamic build compatible with Amazon Linux 2023 (requires Docker):

```sh
make docker-build
# → dist/libage.so
```

For a static build (Alpine/musl, requires Docker):

```sh
make docker-build-static
# → dist/libage.a + dist/libage.h
```

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
