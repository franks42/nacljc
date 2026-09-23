# Changelog

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
