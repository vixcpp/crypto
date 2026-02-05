# vix::crypto

Modern cryptography primitives for Vix.

This module provides **explicit, auditable, dependency-light** cryptographic building blocks
designed for secure runtimes, offline-first systems, and peer-to-peer protocols.

No hidden magic. No implicit control flow. No exceptions in public APIs.

---

## Design principles

- **Explicit errors**
  All operations return `Result<T>` or `Result<void>`. Failure is visible at call sites.

- **Composable primitives**
  Small building blocks that can be combined safely in higher-level systems.

- **Provider-agnostic**
  Interfaces are stable. Providers (OpenSSL, OS RNG) are behind clear boundaries.

- **Predictable behavior**
  No global state. No hidden initialization. No surprising allocations.

---

## Provided primitives

### Randomness

- `random_bytes(span<uint8_t>)`
- `random_uint(max)`

Backed by:
- OpenSSL CSPRNG (when enabled)
- Linux `getrandom()` syscall

---

### Hashing

- `sha256(...)`
- Generic `hash(HashAlg, ...)`

Used for:
- content identifiers
- integrity checks
- signatures
- WAL and sync engines

---

### HMAC

- `hmac_sha256(...)`
- Generic `hmac(HmacAlg, ...)`

Provides message authentication with shared secrets.

---

### Key derivation

- `hkdf_sha256(...)`
- Generic `kdf(KdfAlg, ...)`

RFC 5869 compliant.

---

### Secret keys

- `SecretKey` (owning, zeroized on destruction)
- `generate_secret_key(size)`

Designed for in-memory safety and explicit lifetimes.

---

### Authenticated encryption (AEAD)

- `aes_256_gcm` via `aead_encrypt` / `aead_decrypt`

Provides:
- confidentiality
- integrity
- authenticity

Nonce and tag handling is explicit and strict.

---

### Signatures

- `ed25519`
  - key generation
  - signing
  - verification

Deterministic, fast, and widely deployed.

---

## Error handling

All APIs return explicit errors:

```cpp
auto r = sha256(data, out);
if (!r.ok())
{
  // inspect r.error().code and r.error().message
}
```

No exceptions are thrown by public APIs.

---

## Build and integration

### As part of the Vix umbrella

The crypto module is designed to be added via:

```
modules/crypto
```

Dependencies are managed by the umbrella build.

---

### Standalone build

```bash
cmake -S . -B build
cmake --build build
```

OpenSSL is used automatically when available.

---

## Examples

See the `examples/` directory:

- `hash_sha256.cpp`
- `aead_roundtrip.cpp`
- `sign_verify.cpp`

Each example is small, self-contained, and demonstrates correct usage.

---

## Tests

The `tests/` directory contains a minimal smoke test validating:

- randomness
- hashing
- HMAC
- KDF
- AEAD
- signatures

These tests ensure wiring and providers work as expected.

---

## Scope

This module intentionally does **not** provide:

- TLS
- certificate handling
- key storage
- protocol-level logic

Those belong in higher-level modules (`p2p`, `net`, `sync`).

---

## License

MIT. See `LICENSE`.

---

> Cryptography does not create trust.
> It makes systems **work without having to trust**.
