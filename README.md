# nacljc

**libsodium as one crypto engine for Clojure on every runtime**, with one
binding source file, hardened at the C boundary (see "Memory and type
safety").

- **JVM Clojure, babashka and nbb** call native libsodium through
  [`babashka.ffi`](https://github.com/babashka/ffi). The same
  `src/nacljc/core.cljc` runs unchanged on all three.
- **Browsers (Scittle)** use [libsodium.js](https://github.com/jedisct1/libsodium.js),
  libsodium compiled to WebAssembly.

Every engine produces byte-identical results. They reproduce the RFC test
vectors, and they reproduce the outputs of signet's current JCA backend, so
moving signet onto libsodium would change no signature, key or ciphertext.

**signet runs on it unchanged.** A drop-in `signet.impl.jvm` built on
`nacljc.core` (`integration/signet-shim`) passes signet's own, unmodified
suite:

- JVM: 105 tests / 500 assertions, identical to signet's JCA backend.
- babashka: 95 / 476, which is every test except secp256k1 (Bouncy Castle
  cannot load on bb). With its own JCA backend, signet gets 16 errors on bb.

signet itself now ships this backend as `signet.impl.sodium`.

## The name

**nacljc** is NaCl (sodium chloride, and Bernstein, Lange and Schwabe's
Networking and Cryptography library) plus cljc. It is **not a binding to
the original NaCl C library.** It binds [libsodium](https://libsodium.org),
NaCl's maintained successor. It is aligned with NaCl's design: a few
well-chosen primitives, hard to misuse, and the same Curve25519, Ed25519
and Poly1305 lineage. But it also exposes libsodium primitives that NaCl
never had, such as HKDF-SHA-256 and IETF ChaCha20-Poly1305. The repo was
called `sodium.cljc` until 2026-09-23. It was renamed because Clojars'
`com.degel/sodium` already ships a `sodium.core` namespace.

Status: **0.2.0 released** on Clojars (2026-09-24; see [CHANGELOG.md](CHANGELOG.md)). signet uses it as its libsodium backend.
[`docs/feasibility.md`](docs/feasibility.md) has the research findings and
the evidence.

## Installation

nacljc needs **libsodium >= 1.0.19** installed natively (`brew install
libsodium`; on Linux see "Requirements", since Debian and Ubuntu ship
1.0.18).

```clojure
;; deps.edn (JVM, JDK 25+)
{:deps    {com.github.franks42/nacljc {:mvn/version "0.2.0"}}
 :aliases {:run {:jvm-opts ["--enable-native-access=ALL-UNNAMED"]}}}

;; bb.edn (babashka 1.13.220+; bb ignores the org.babashka/ffi
;; dependency and uses its built-in babashka.ffi)
{:deps {com.github.franks42/nacljc {:mvn/version "0.2.0"}}}

;; nbb.edn (nbb 1.6.213+ on Node 26+; nbb resolves :deps through bb,
;; so bb must be installed)
{:deps {com.github.franks42/nacljc {:mvn/version "0.2.0"}}}
```

```clojure
(require '[nacljc.core :as na])
(let [seed (na/random-bytes 32)
      pk   (na/ed25519-public-key seed)
      msg  (.getBytes "hello" "UTF-8")]
  (na/ed25519-verify? pk msg (na/ed25519-sign seed msg)))   ;=> true
```

## API

Everything is in `nacljc.core`. Byte arrays in and out: `byte[]` on the JVM
and bb. On nbb, `Int8Array` or `Uint8Array` in, and `Int8Array` out.

| Function | Inputs, sizes in bytes | Returns |
|---|---|---|
| `(ed25519-public-key seed)` | seed 32 | public key 32 |
| `(ed25519-sign seed msg)` | seed 32, msg any | signature 64, deterministic |
| `(ed25519-verify? pk msg sig)` | pk 32, msg any, sig 64 | boolean; **never throws** for a bad `pk` or `sig` (untrusted input) |
| `(ed25519->x25519-public-key pk)` | Ed25519 public key 32 | X25519 public key 32 |
| `(ed25519->x25519-secret-key seed)` | Ed25519 seed 32 | X25519 secret key 32 |
| `(x25519 sk pk)` | our secret key 32, their public key 32 | shared secret 32 |
| `(x25519-public-key sk)` | secret key 32 | public key 32 |
| `(chacha20-poly1305-encrypt k nonce pt aad)` | key 32, nonce 12, plaintext, aad (nil = none) | ciphertext ‖ 16-byte tag |
| `(chacha20-poly1305-decrypt k nonce ct aad)` | key 32, nonce 12, ciphertext ≥ 16, aad | plaintext |
| `(hkdf-sha-256 ikm salt info len)` | salt and info may be nil (empty); len 1..8160 | `len` bytes (RFC 5869) |
| `(hmac-sha-256 k data)` | key of any length | 32 |
| `(sha-256 data)` | | 32 |
| `(random-bytes n)` | n ≥ 0 | n bytes from libsodium's CSPRNG |
| `(memzero! bs)` | byte array | nil; overwrites `bs` with zeros |
| `(constant-time-equal? a b)` | two byte arrays | boolean; constant-time for equal lengths |
| `(libsodium-version)`, `minimum-libsodium-version` | | `"1.0.22"`, `[1 0 19]` |
| `(aegis256-encrypt k nonce pt aad)` | key 32, **nonce 32**, plaintext, aad (nil = none) | ciphertext ‖ **32-byte** tag (AEGIS-256, RFC 10032) |
| `(aegis256-decrypt k nonce ct aad)` | key 32, nonce 32, ciphertext ≥ 32, aad | plaintext |
| `(xwing-public-key seed)` | seed 32 (the X-Wing secret key) | public key 1216 (X-Wing: ML-KEM-768 + X25519) |
| `(xwing-encapsulate pk)` | public key 1216 | `{:ciphertext <1120 bytes> :shared-secret <secret>}` |
| `(xwing-decapsulate seed ct)` | seed 32, ciphertext 1120 | shared secret, **always a secret object** |

**Secrets (0.2.0).** Key material can live in libsodium's guarded memory
instead of the Clojure heap:

| Function | Does |
|---|---|
| `(secret-random n)` | a new secret of n random bytes (1..65536), drawn straight into guarded memory |
| `(secret-import! bs)` | a new secret holding a copy of `bs`, **then wipes `bs`** |
| `(secret-export s {:i-understand :exposes-secret})` | the bytes as a new array; throws `::export-not-acknowledged` without that exact map |
| `(secret-destroy! s)` | zeroes and frees it (`sodium_free`); later use throws `::destroyed-secret`; again is a no-op |
| `(with-secret [s (secret-random 32)] …)` | destroys `s` on exit, also when the body throws |
| `(secret? x)`, `(secret-length s)`, `(secret-destroyed? s)` | |

Every function that takes key material (a seed, a secret key, an AEAD, HMAC
or HKDF key) accepts a secret wherever it accepts a byte array. **Secrets
stay secrets:** when a secret-key *input* is a secret, a result that is
itself secret key material comes back as a secret too. That covers the
X25519 shared secret, `ed25519->x25519-secret-key` and HKDF output.
Public results (public keys, signatures, ciphertexts, MAC tags) are byte
arrays. Callers that pass byte arrays get byte arrays, exactly as in 0.1.0.
X-Wing shared secrets are always secrets.

Ed25519 secret keys are **32-byte seeds**. libsodium's 64-byte secret key
(seed ‖ public key) never leaves native memory; take its first 32 bytes
if you have one.

Errors are `ex-info` with a `:type`:

| `:type` | When |
|---|---|
| `:nacljc.core/bad-input` | an input is not a byte array, or a count is not an integer |
| `:nacljc.core/bad-length` | a fixed-size input has the wrong size, or a count is out of range |
| `:nacljc.core/auth-failed` | decryption failed: wrong key, nonce or aad, or tampered ciphertext |
| `:nacljc.core/low-order-point` | `x25519` with a small-order public key (the shared secret would be all zeros) |
| `:nacljc.core/invalid-public-key` | `ed25519->x25519-public-key` with a point that is not on the curve or has small order |
| `:nacljc.core/call-failed` | any other non-zero libsodium return code |
| `:nacljc.core/destroyed-secret` | a secret used after `secret-destroy!` |
| `:nacljc.core/secret-in-use` | `secret-destroy!` while another thread's call is using the secret |
| `:nacljc.core/export-not-acknowledged` | `secret-export` without `{:i-understand :exposes-secret}` |
| `:nacljc.core/unsupported-by-libsodium` | X-Wing on a libsodium older than 1.0.22 |
| `:nacljc.core/library-not-found`, `not-libsodium`, `libsodium-too-old`, `init-failed` | at load time (see below) |

Error data describes types and sizes, **never contents**, since they may be
secret.

## Memory and type safety

`nacljc.core` is the line between Clojure, where a wrong value gives an
exception, and C, where it reads or writes the wrong memory. C trusts every
pointer and length, so everything is settled on the Clojure side first.

- **Types are checked** before any native memory is touched. A string, a
  vector, an `int[]`, or on nbb a plain JS array or `Int16Array`, is
  `::bad-input`, never a pointer to the wrong bytes.
- **Sizes are checked.** Every fixed-size input is checked, and every
  length passed to C is taken from the array itself, never from the caller.
- **Rejected input never reaches C.** The tests assert that each rejected
  call allocates no native memory at all. A missing guard whose C call
  still happens to return the right answer, such as `verify?` over-reading
  a short signature, is caught this way.
- **Every native buffer is wiped.** Each call copies its inputs into a
  fresh confined arena, calls C, and copies the results out. Every buffer
  in the arena is then zeroed with `sodium_memzero` before the arena is
  released, on success and on error. The tests audit every allocation,
  wipe and close, and check that the wipe really zeroes memory.
- **Nothing escapes and nothing is shared.** No pointer outlives its call.
  Results are fresh arrays, and inputs are never written to.
- **Ed25519 signing takes the seed.** A 64-byte secret key whose
  public-key half does not match its seed makes Ed25519 leak the private
  scalar: libsodium hashes that half into the signature without checking
  it. nacljc derives the full key from the seed inside native memory for
  each signature, so the mismatch cannot happen.
- **Every return code is checked**, and each failure has its own type.
- **The raw C bindings are private**, and a test pins the public API to
  exactly the table above.

Each of these checks was shown to bite by removing it and watching the
tests fail. Without the count check, `(random-bytes -1)` does not throw at
all: it aborts the whole process inside libsodium.

What stays with the caller:

- **Secrets live in guarded memory** (0.2.0). A secret's bytes are in
  `sodium_malloc` memory: guard pages around it, canaries checked when it
  is freed, and locked so it is never swapped out. It is **no-access
  except during a call that uses it**, when it is read-only. C reads it in
  place, so the bytes never reach the Clojure heap unless you call
  `secret-export`. Several threads can use one secret at once: a counter
  under a lock opens the read-only window on the first use and closes it
  after the last. `bb test:secrets` proves the protection in child
  processes: reading a secret's memory outside a call, or after
  destroying it, **faults** (bb and nbb crash; the JVM raises
  `InternalError` on macOS and aborts on Linux), while the same read inside a call works. Removing the
  counter as an experiment crashed the JVM with SIGBUS when threads shared
  a secret.
- **Clojure-side arrays are yours.** Arrays you pass in and get back live
  on the Clojure heap. Prefer secrets for long-lived keys. They are not locked in memory, and the JVM's moving
  garbage collector may already have copied them. Call `memzero!` on
  secrets when you are done.
- **Raw bytes carry no key type.** An Ed25519 public key and an X25519
  public key are both 32 bytes, so no length check can tell them apart. A
  typed layer above nacljc must keep them apart; signet's key records do.
- **Nonces are your responsibility.** `chacha20-poly1305-encrypt` takes a
  caller-chosen nonce. Never reuse one with the same key. Higher-level
  APIs such as signet's box hide nonces entirely.
- **Scratch buffers are not `mlock`ed.** Byte-array inputs are copied into
  a per-call scratch arena (wiped before release), which could reach swap
  during the microseconds of a call. Secrets are locked.
- **Destroy your secrets.** Guarded memory is not garbage-collected: a
  secret that is dropped without `secret-destroy!` (or `with-secret`)
  stays allocated and locked until the process exits.

## Loading libsodium

libsodium loads when `nacljc.core` loads. Without configuration it is
looked for in these places:

- **macOS:** Homebrew on Apple silicon and Intel, then MacPorts.
- **Linux:** `libsodium.so.26`, then `.so.23`, then `.so`, through the
  system search path.

To use exactly one library, set a path:

```bash
NACLJC_LIBSODIUM=/opt/libsodium/lib/libsodium.so.26 bb …        # any runtime
clojure -J-Dnacljc.libsodium=/opt/libsodium/lib/libsodium.dylib …  # JVM (bb: -Dnacljc.libsodium=…)
```

- The system property wins over the environment variable. An empty value
  counts as unset.
- A configured path is the only one tried; there is no fallback.
- These cases fail at load, loudly:
  - A missing library: `::library-not-found`, listing the paths tried.
  - A library that isn't libsodium: `::not-libsodium`.
  - A libsodium older than 1.0.19: `::libsodium-too-old`.

## Requirements

All of these are needed to run everything. Each runtime also works on its
own.

| Component | Minimum | Tested | Notes |
|---|---|---|---|
| libsodium (native) | **1.0.19** (X-Wing: **1.0.22**) | 1.0.22 (Homebrew) | 1.0.19 added HKDF and AEGIS-256; X-Wing arrived in 1.0.22, and on an older libsodium only the X-Wing functions fail, with `::unsupported-by-libsodium`; `nacljc.core` checks the version at load and throws `::libsodium-too-old` for anything older. macOS: `brew install libsodium`. On Linux, check your distribution's version with `pkg-config --modversion libsodium`, since some ship an older one. |
| JDK (JVM Clojure) | **25** | 25.0.3 (Temurin) | `org.babashka/ffi` needs JDK 25+. On 21.0.11 it fails with `ClassNotFoundException: java.lang.classfile.ClassBuilder`. Run with `--enable-native-access=ALL-UNNAMED` (the `:test` alias sets it). Without it, JDK 25 warns that native calls "will be blocked in a future release". |
| `org.babashka/ffi` (JVM only) | 0.1.2 | 0.1.2 | Built into bb and nbb. Experimental. |
| Clojure CLI | — | 1.12.6 | |
| babashka | **1.13.220** | 1.13.223, 1.13.224 | `babashka.ffi` was added in 1.13.220. **On Linux use the dynamically linked build** (`babashka-<v>-linux-amd64.tar.gz`). The static build (`…-static`), which `DeLaGuardo/setup-clojure` installs on Linux, cannot load shared libraries at all: `cannot load library`, even by absolute path. |
| nbb | **1.6.213** | 1.6.213 | `babashka.ffi` built in. |
| Node.js (nbb) | **26.1** | 26.9.0 | nbb's FFI uses Node's built-in `node:ffi`. It is experimental and prints an `ExperimentalWarning`. |
| libsodium.js (WASM) | 0.8.4 **sumo** | 0.8.4 | The *standard* 0.8.4 build has no HMAC, SHA-256 or HKDF. 0.8.4 does not export HKDF, so the tests implement it on HMAC (see the docs). |
| Scittle (browser) | — | 0.8.33 | libsodium.js loads through a plain `<script>` tag, with no bundler. Only headless Chromium has been tested. |
| Playwright (browser test only) | — | 1.58.2 | `npm install && npx playwright install chromium` in `test/browser`. |
| clj-kondo, cljfmt | — | current | For `bb lint` and `bb fmt`. |

## Running the tests

```bash
bb test:bb        # vector tests on babashka
bb test:jvm       # vector tests on JVM Clojure (JDK 25+)
bb test:nbb       # vector tests on nbb (Node 26+)
bb test:loading   # library loading in fresh processes, on bb, nbb and the JVM
bb test:secrets   # secret memory faults outside calls and after destroy (child processes, all runtimes)
bb test:wasm      # libsodium.js on Node        (first: cd test/wasm && npm install)
bb test:browser   # Scittle + libsodium.js in headless Chromium
                  # (first: cd test/browser && npm install; optional arg = a libsodium.js build URL or path)
bb test:jca       # random-input cross-check against signet's JCA backend (needs ../signet)
bb test:signet    # signet's own test suite: JCA oracle (JVM), libsodium (JVM), libsodium (bb)
                  #   (needs ../signet; also test:signet-jca / test:signet-jvm / test:signet-bb)
bb test:all       # everything except test:jca and test:signet, plus library loading, lint and format
bb install        # install the jar (build.clj's version) into ~/.m2
bb test:jar       # the suite against the installed jar, from a scratch project: JVM, bb, nbb
bb test:clojars V # the same against release V fetched from Clojars
```

`bb install` builds a jar containing only `src/` (its pom depends on
`org.babashka/ffi 0.1.2`) and installs it locally. Re-run it after every
change, or consumers such as signet keep using the old jar. `bb test:jar`
runs the whole suite against that jar from a scratch project with no
`src/`, on the JVM, bb and nbb. On babashka, the jar's `org.babashka/ffi`
dependency is ignored; bb always uses its built-in `babashka.ffi`
(verified).

Releases: push a `vX.Y.Z` tag. The release workflow checks the version
(`bb release-check`) and runs the tests. It then deploys to Clojars, runs
the suite again against the jar fetched back from Clojars (`bb test:clojars
X.Y.Z`), and creates the GitHub release from the CHANGELOG section.

`test:wasm` and `test:browser` need the network: npm, and jsdelivr for
Scittle and libsodium.js.

## Layout

```
src/nacljc/core.cljc          the binding (API above): checks, scratch arenas, wiping
test/nacljc/vectors.edn       RFC vectors + cross-platform vectors
test/nacljc/core_test.cljc    known answers, typed errors, hygiene audit (JVM, bb, nbb)
test/loading/run.clj          library-loading checks, driving test/loading/child.cljc
test/nacljc/jca_crosscheck.clj  libsodium vs signet's JCA on random inputs
test/wasm/check.cljs          libsodium.js on Node against the same vectors
test/browser/index.html       Scittle page doing the same in a browser
test/browser/run.mjs          Playwright runner for that page
integration/signet-shim/signet/impl/jvm.clj
                              drop-in libsodium backend for signet (same ns, 16 fns)
integration/nacljc/signet_suite.clj
                              runs signet's unmodified tests; asserts which backend loaded
docs/feasibility.md           findings and recommendation
```

## License

Copyright (c) Frank Siebenlist. Distributed under the [Eclipse Public License v2.0](LICENSE).
