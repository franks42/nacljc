# Changelog

## 0.3.1 (2026-09-25)

### Changed

- **The stack is wiped after every operation that reads a secret**, on
  success and on error: `sodium_stackzero` over 16 KiB below the caller,
  as recommended in libsodium's "Securing memory allocations" docs. C code
  copies secret values into registers and stack frames while it runs.
  About 0.2 µs per operation; operations on byte arrays skip it. No API
  change.

## 0.3.0 (2026-09-25)

For signet 0.9.0's sessions, whose chaining key and transport keys stay in
guarded memory.

### Added

- **`secret-split`:** new secrets holding consecutive parts of a secret,
  e.g. `(secret-split s64 [32 32])`. The lengths must be positive and add
  up to the secret's size. The bytes are copied inside guarded memory
  (`sodium_memzero`, then `sodium_add` onto the zeroed part, since
  libsodium has no memcpy and `ffi/copy` goes through a JS buffer on nbb).
  The source is unchanged. If a part cannot be allocated, the parts
  already made are freed.

### Changed

- **`hkdf-sha-256` accepts a secret salt.** The result is a secret if the
  ikm or the salt is one (before, only a secret ikm gave a secret). Byte
  inputs behave exactly as in 0.2.0.

## 0.2.0 (2026-09-24)

### Added

- **Secrets in guarded memory.**
  - `secret-random`, `secret-import!` (copies, then wipes the caller's
    array), `secret-export` (requires `{:i-understand :exposes-secret}`),
    `secret-destroy!`, `with-secret`, `secret?`, `secret-length`,
    `secret-destroyed?`.
  - A secret lives in `sodium_malloc` memory (guard pages, canaries,
    `mlock`). It is no-access except during a call using it, then
    read-only. It is safe to share between threads. It prints as
    `#nacljc/secret{:bytes n}` and is not a map.
  - Every function that takes key material accepts a secret. Secret-key
    results of secret inputs are secrets: the X25519 shared secret,
    `ed25519->x25519-secret-key`, HKDF output.
- **AEGIS-256** (RFC 10032): `aegis256-encrypt` and `aegis256-decrypt`,
  with a 32-byte nonce and a 32-byte tag. Checked against the RFC's test
  vectors natively and in libsodium.js (WASM on Node, headless Chrome).
- **X-Wing** (ML-KEM-768 + X25519, libsodium 1.0.22+): `xwing-public-key`,
  `xwing-encapsulate`, `xwing-decapsulate`. Shared secrets are always
  secrets. Checked against the X-Wing test vectors. On an older libsodium
  only these functions fail, with `::unsupported-by-libsodium`.
- `bb test:secrets`: in child processes on bb, the JVM and nbb, reading a
  secret's memory outside a call or after destroy faults.
- A clj-kondo config export, so `na/with-secret` lints as `let`.

### Unchanged

- Every 0.1.0 function keeps its behaviour for byte-array inputs.

## 0.1.0 (2026-09-23)

First release. Before this, nacljc was a research repo named `sodium.cljc`.

- **API**, all in `nacljc.core`, each name saying its algorithm:
  - Ed25519: `ed25519-public-key`, `ed25519-sign`, `ed25519-verify?`.
  - Ed25519 to X25519: `ed25519->x25519-public-key`,
    `ed25519->x25519-secret-key`.
  - X25519: `x25519`, `x25519-public-key`.
  - AEAD: `chacha20-poly1305-encrypt`, `chacha20-poly1305-decrypt`.
  - Hashing and key derivation: `hkdf-sha-256`, `hmac-sha-256`,
    `sha-256`.
  - Utilities: `random-bytes`, `memzero!`, `constant-time-equal?`,
    `libsodium-version`, `minimum-libsodium-version`.
- **Ed25519 secret keys are 32-byte seeds.** libsodium's 64-byte secret
  key exists only in native memory, so its public-key half can never be
  mismatched. A mismatched half leaks the private scalar.
- **Hardened C boundary.**
  - Every input is type- and size-checked before any native memory is
    allocated, raising `::bad-input` or `::bad-length`. Error data never
    includes contents.
  - Every native buffer is wiped with `sodium_memzero` before release, on
    success and on error.
  - Every libsodium return code is checked and typed: `::auth-failed`,
    `::low-order-point`, `::invalid-public-key`, `::call-failed`.
  - The raw C bindings are private.
- **Loading.**
  - `NACLJC_LIBSODIUM`, or on the JVM and bb the `-Dnacljc.libsodium`
    property, selects exactly one library.
  - Defaults: Homebrew and MacPorts on macOS; `libsodium.so.26`, `.23` and
    `.so` on Linux.
  - Load-time errors: `::library-not-found` (listing the paths tried),
    `::not-libsodium`, `::libsodium-too-old` (below 1.0.19).
- **Runtimes:** the JVM (JDK 25+, `org.babashka/ffi`), babashka
  1.13.220+ (the dynamically linked build on Linux), and nbb 1.6.213+ on
  Node 26+. On nbb, `Int8Array` and `Uint8Array` inputs are accepted.
