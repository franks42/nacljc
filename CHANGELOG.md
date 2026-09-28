# Changelog

## 0.6.0 (unreleased)

### Added

- **`nacljc.tty`: read a password straight into guarded memory.**
  `(read-password "Password: ")` opens `/dev/tty`, switches off echo and
  signals (so ^C is a byte, not a kill with echo left off), and reads the
  line with `read(2)` directly into `sodium_malloc` memory; the newline
  and ^C are found there with `memchr`, so the password never exists as a
  String, a byte array, or a byte in a Clojure value. Returns a secret of
  the exact length. `{:confirm "Again: "}` reads twice and compares in
  constant time. `read-password-fd` does the same for a pipe or file
  (stdin, systemd credentials). Typeahead before the prompt is discarded,
  as `readpassphrase(3)` does. Typed errors: `::no-tty`,
  `::interrupted`, `::empty`, `::too-long`, `::mismatch`. macOS and
  Linux, on the JVM, bb and nbb. Checked by `bb test:tty` (a
  pseudo-terminal via `script(1)`: no echo, settings restored,
  backspace, UTF-8, ^C, confirmation), in CI.

## 0.5.0 (2026-09-27)

### Added

- **Key wrapping inside guarded memory:** `wrap-secret` and
  `unwrap-secret`. `(wrap-secret k nonce s aad)` encrypts secret `s`'s
  bytes with ChaCha20-Poly1305, reading them in place, and returns the
  ciphertext as bytes; `(unwrap-secret k nonce ct aad)` decrypts straight
  into a new secret. So a secret can be saved to disk and loaded again
  without its bytes ever existing on the Clojure heap. For signet's vault
  persistence (signet docs/10). Checked against RFC 8439's vector; a
  failed authentication (wrong key, nonce, aad, or a changed ciphertext)
  throws `::auth-failed` and leaves no secret behind; the stack is wiped
  after both, also when the key is a byte array.

## 0.4.0 (2026-09-27)

### Added

- **`constant-time-equal?` compares secrets in place.** Either argument may
  be a secret (or both): it is read inside its guarded memory, so two
  secrets are compared without exporting either, and the stack is wiped
  afterwards. Byte arrays behave as before.
- **Argon2id: `argon2id` and `argon2id-limits`** (libsodium's
  `crypto_pwhash`, Argon2id v1.3). `(argon2id password salt len limits)`
  derives len bytes from a password and a 16-byte salt at the cost in
  `{:opslimit n :memlimit bytes}`; `argon2id-limits` returns libsodium's
  `:interactive`, `:moderate` and `:sensitive` presets. A secret password
  gives a secret key, straight into guarded memory (the base for signet's
  password unlocking). Checked against libsodium's own test vectors,
  natively and in libsodium.js (WASM on Node, headless Chrome). Argon2's
  working memory (memlimit bytes) is mapped for the call and unmapped
  afterwards, outside guarded memory.
- **`nacljc.process`: opt-in process hardening.** `harden-process!` with
  `{:core-dumps false :dumpable false :heap-dump-on-oom false}` (any
  subset) disables core dumps (`setrlimit`), makes the process
  non-dumpable (`prctl`, Linux) and switches off heap dumps on
  OutOfMemoryError (HotSpot); `process-status` reports the settings.
  **Nothing happens by default**: it is a deployment choice (README,
  "Deployment hardening"). A separate namespace: `nacljc.core` still binds
  libsodium only. Tested in child processes on bb, the JVM and nbb
  (`bb test:process`, in CI on macOS and Linux).

## 0.3.2 (2026-09-26)

From the review `docs/review-2026-09-26.md`. No API change.

### Fixed

- **X-Wing wipes a deeper stack.** ML-KEM-768 decapsulation needs close to
  16 KiB of stack (libsodium's `indcpa_enc` alone has about 12 KB of
  locals), so X-Wing operations now wipe 64 KiB (about 0.6 µs); the others
  keep 16 KiB.
- **Encapsulation wipes the stack too.** `xwing-encapsulate` opens no
  secret but produces one, and 0.3.1 wiped only after operations that
  opened a secret. So did `xwing-decapsulate` with a byte-array seed. Both
  now always wipe.
- **Cleanup no longer hides the real error.** `with-secret`: when the body
  throws and destroying the secret fails too (a call on another thread
  still uses it), the body's exception is rethrown, with the destroy error
  attached as suppressed on the JVM. Internally, a failed close no longer
  leaves the other secrets open or skips the stack wipe.
- `release-check` requires a dated heading, `## X.Y.Z (YYYY-MM-DD)`;
  before, `## X.Y.Z (unreleased)` passed.

### Changed

- **Every function states its purity and errors** in fixed wording, public
  and private: `Pure.`, `Impure: <what it reads or writes>`, and
  `Throws ex-info {:type ::x} when …` listing every `:type`. Functions that
  take a key in a byte array or a secret say: pure for byte arrays; with a
  secret, impure: reads it.
- `need-xwing!` (private) is now `check-xwing` and returns the function:
  it writes nothing, so it has no `!`.
- `bb test:signet` now runs signet's own suite in `../signet` (JVM, parity,
  bb) with nacljc replaced by this checkout. The shim that stood in for
  signet's backend (`integration/`) is gone: it implemented signet's old
  16-function contract, and signet has had its own libsodium backend since
  0.7.0.

### Documentation

- Reading a secret after `secret-destroy!` crashes the JVM (a use after
  free, SIGSEGV), unlike a read outside a call (`InternalError` on macOS);
  README, `secret-destroy!` and `test:secrets` said otherwise.
  `test:secrets` writes the JVM's crash logs to `target/`.
- The `Secret` fields are internal (a comment on the deftype).
- README: Windows is not supported or tested; the signet section and its
  numbers are current.

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
