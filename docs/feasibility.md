# libsodium as a common crypto engine — feasibility

Research date: 2026-09-23. Motivation: signet (`../signet`), which uses
canonical-edn and uuidv7, runs only on the JVM and on babashka, and its JCA
backend has gaps on bb. The question was whether libsodium could be one
engine under JVM Clojure, bb, nbb and the browser. A second question was
whether it would also give us a secure random generator for free.

Every claim below is marked. **[verified]** means it was run here.
**[source]** means it comes from the cited documentation.
**[inference]** is our own reasoning.

## Verdict

**Go, as a prototype.** One binding file covers JVM Clojure, bb and nbb.
libsodium.js covers the browser. Every engine reproduces the RFC vectors
and signet's current output byte for byte. signet's own test suite passes
unchanged on a libsodium backend, on the JVM and, for the first time in
full, on babashka. The main risks are that the tooling is very new and
that libsodium becomes a native dependency.

## What was tested

| Runtime | Engine | How it is called | Result |
|---|---|---|---|
| babashka 1.13.223 | libsodium 1.0.22 (Homebrew) | built-in `babashka.ffi` | **[verified]** 12 tests / 38 assertions pass. The JCA cross-check passes 13/13. |
| JVM, JDK 25.0.3 | same | `org.babashka/ffi 0.1.2` | **[verified]** Same `core.cljc`. 12/38 and 13/13 pass. |
| nbb 1.6.213, Node 26.9.0 | same | built-in `babashka.ffi` over `node:ffi` | **[verified]** 12/38 pass. |
| Node 26.9.0 | libsodium.js 0.8.4 sumo (WASM) | npm `libsodium-wrappers-sumo` | **[verified]** all vector checks pass |
| Headless Chromium | libsodium.js 0.8.4 sumo, `browsers-sumo/sodium.js` | Scittle 0.8.33, plain `<script>` tags | **[verified]** 12 checks pass |
| Headless Chromium | libsodium.js at master (unreleased, local clone), sumo build | same | **[verified]** Passes. The native HKDF export works too. |
| JVM, JDK 21.0.11 | — | `org.babashka/ffi 0.1.2` | **[verified]** Fails: `ClassNotFoundException: java.lang.classfile.ClassBuilder` |

The operations covered: seed → Ed25519 keypair, Ed25519 sign and verify,
Ed25519 → X25519 key conversion, X25519 Diffie-Hellman and base-point
multiplication, SHA-256, HMAC-SHA-256 (any key length), ChaCha20-Poly1305
IETF encryption, HKDF-SHA-256 and `randombytes_buf`. Wrong-size inputs are
also tested. The known answers come from RFC 8032 §7.1 test 1, RFC 7748
§5.2 and §6.1, RFC 8439 §2.8.2, RFC 5869 A.1, RFC 4231 cases 1 and 6, and
FIPS 180-2 ("abc"). Each vector was checked against libsodium before it was
added to the file. For the RFC 8439 vector, the ciphertext prefix and the
tag both match the RFC.

### Agreement with signet's JCA backend [verified]

`test/sodium/jca_crosscheck.clj` feeds random inputs to libsodium and to
`signet.impl.jvm`. The results are byte-identical for the seed-derived
public key, the Ed25519 signature, the X25519 keys derived from Ed25519
keys, the DH secret, ChaCha20-Poly1305 and HKDF. This holds on bb and on
the JVM. **Switching engines therefore needs no migration.**

In particular, libsodium's `crypto_sign_seed_keypair` derives a public key
from a seed on bb. signet cannot do that today: its `proxy [SecureRandom]`
trick fails on bb 1.13.223 with `No matching clause`.

## signet on libsodium [verified]

`integration/signet-shim/signet/impl/jvm.clj` is a drop-in replacement for
signet's JCA backend. It has the same namespace and the same 16 functions,
implemented on `sodium.core`. When it comes first on the classpath, signet
uses libsodium without any change to signet's repo.
`integration/sodium/signet_suite.clj` runs signet's own test namespaces and
checks a `backend` marker var. If the wrong backend loaded it exits 2; this
was checked by running the JCA configuration while expecting libsodium.

| Run (`bb test:signet-…`) | Runtime | Backend | Result |
|---|---|---|---|
| `jca` (oracle) | JVM 25.0.3 | signet's JCA | 102 tests / 436 assertions, 0 failures |
| `jvm` | JVM 25.0.3 | libsodium | **102 / 436, 0 failures**: identical to the oracle |
| `bb` | bb 1.13.223 | libsodium | **93 / 415, 0 failures** (all but the 9 secp256k1 tests) |
| (for comparison) | bb 1.13.223 | signet's JCA | 93 / 377, **16 errors** |

All 16 JCA-on-bb errors have one cause:
`No matching clause: ["java.security.SecureRandom" #{}]`. That is signet's
`proxy [SecureRandom]` seed → key trick, which bb cannot run. It breaks key
construction from seeds, the Ed25519 → X25519 conversions, kid round
trips, the key store and verification of open chains. libsodium's
`crypto_sign_seed_keypair` removes the trick, so signet runs in full on bb
for the first time. signet's own `bb smoke` covers 9 tests.

The signet runs use signet's own pinned dependencies through
`:local/root`, so the backend is the only thing that changes. The results
held at the original pins (cedn 1.2.0, uuidv7 0.5.0, Bouncy Castle 1.78.1)
and still hold after the bump on signet's branch (cedn 1.5.2, uuidv7 0.7.1,
Bouncy Castle 1.86). `test:signet-bb` mirrors signet's bb pins.

### Memory safety: length-check every fixed-size input [verified]

libsodium's C functions read fixed-size inputs (32-byte keys and seeds,
64-byte secret keys and signatures, 12-byte nonces) without knowing the
size of the buffer. The first version of the binding passed arrays through
unchecked. Given a 32-byte array where the 64-byte secret key belongs, it
returned a "signature" without error; given a 16-byte X25519 public key, it
returned a "shared secret". Both were computed from memory past the end of
the allocation. `sodium.core` now checks every fixed-size input and throws
`::bad-length`. `verify?` returns false for a wrong-size signature or key,
because both are untrusted input. `length-checks` in `core_test.cljc`
covers this. Any future binding needs the same discipline.

## babashka.ffi [source + verified]

- Added in bb **1.13.220** (2026-08-31). The CHANGELOG entry reads
  "experimental babashka.ffi: call C functions in shared libraries straight
  from babashka and JVM Clojure".
  <https://github.com/babashka/babashka/blob/master/CHANGELOG.md>
- The library lives at <https://github.com/babashka/ffi>, Maven coordinate
  `org.babashka/ffi 0.1.2`. Its README says "Status: experimental".
- **JVM:** uses the FFM API (Panama) and needs JDK 25+.
  **[verified]** JDK 21 fails.
  `--enable-native-access=ALL-UNNAMED` silences JEP 472's warning, which
  announces that such calls will be blocked in a future release.
  **[verified]** The warning appears without the flag.
- **bb native image:** known call signatures are compiled ahead of time
  (about 30 ns per call). Any other signature goes through libffi (about
  1 µs). The static musl bb binary has no libffi, so structs passed by
  value and variadic functions fail there. [source: the guide]
  **[inference]** Our signatures take no structs and no varargs.
- **nbb:** built in since nbb **1.6.213**, on Node **26.1+**'s built-in
  `node:ffi`. It prints an `ExperimentalWarning` **[verified]**. It does not
  support structs by value or variadic functions [source].
- **Portability details [verified]:**
  - `read-array :char` returns a `byte[]` on the JVM and bb, and an
    `Int8Array` on nbb. `alength` works on both.
  - nbb has no `with-open`. `core.cljc` uses a small `with-arena` macro,
    which closes the arena in a `finally`.
- clj-kondo config ships inside the jar (`clj-kondo.exports/babashka/ffi`).
  Import it with
  `clj-kondo --lint "$(clojure -Spath)" --dependencies --copy-configs --skip-lint`.

### Linux CI findings (2026-09-23) [verified]

These surfaced when signet's CI first ran the libsodium backend on Linux:

- **Ubuntu 24.04 and 25.10 ship libsodium 1.0.18**, which has no HKDF.
  CI builds 1.0.22 from source (SHA-256 pinned; byte-identical from
  download.libsodium.org and the GitHub release). `sodium.core` now
  refuses anything older than 1.0.19 at load, with a clear error.
- **The statically linked bb cannot load native libraries.**
  `babashka.ffi/load-library` fails with `cannot load library`, even for
  `/usr/local/lib/libsodium.so.26` by absolute path. `DeLaGuardo/setup-clojure`
  installs that static build on Linux. The dynamically linked build
  (`babashka-<v>-linux-amd64.tar.gz`) works. The JVM, being dynamically
  linked itself, was never affected.
- **Fresh machines need `clojure -P` before `clojure -T:build install`:**
  tools.build's basis did not download `org.babashka/ffi` itself.

## libsodium.js (browser, and Node without native libsodium)

- libsodium.js 0.8.4 (released 2026-04-19) bundles libsodium 1.0.22
  **[verified]**.
- The single-file browser builds (`dist/browsers*/sodium.js`) load from a
  plain `<script>` tag using the `window.sodium = {onload: …}` hook. They
  are not in the npm packages, but jsdelivr serves them from the GitHub
  tag, e.g.
  <https://cdn.jsdelivr.net/gh/jedisct1/libsodium.js@0.8.4/dist/browsers-sumo/sodium.js>.
  **[verified]** This works under Scittle 0.8.33.
- **Build choice [verified]:**
  - Standard 0.8.4 has X25519, Ed25519 and AEAD, but **no HMAC, SHA-256
    or HKDF**.
  - Use **sumo**: it has HMAC-SHA-256, but still no exported HKDF in
    0.8.4.
- **HKDF:** see the next section.
- **Upstream bug at master [verified]:** in the unreleased *standard*
  browser build, `crypto_scalarmult` throws
  `g._crypto_scalarmult_curve25519_bytes is not a function`. The wrapper
  calls a function that the standard core does not export: the symbol
  occurs 0 times in `dist/modules/libsodium.js` and once in the sumo core.
  Released 0.8.4 standard is fine. *Candidate for an upstream issue.*

## HKDF in libsodium and libsodium.js

### libsodium has HKDF; the WASM gap is only in the JS wrappers

- **libsodium (C) has had HKDF since 1.0.19 [verified].** The ChangeLog
  entry under "Version 1.0.19" reads: "The HKDF key derivation mechanism,
  required by many standard protocols, is now available in the
  `crypto_kdf_hkdf_*()` namespace. It is implemented for the SHA-256 and
  SHA-512 hash functions." The source is in
  `src/libsodium/crypto_kdf/hkdf/`. `core.cljc` calls
  `crypto_kdf_hkdf_sha256_extract`/`_expand` natively and reproduces
  RFC 5869 A.1.
- **libsodium.js has two layers.** The first is the C library compiled to
  WASM, whose raw exports include `_crypto_kdf_hkdf_sha256_extract` /
  `_expand` in sumo 0.8.4 [source: research agent's inspection of the npm
  package]. The second is hand-written JS wrappers, which turn raw exports
  into `Uint8Array` calls; each function needs its own wrapper
  definition, and 0.8.4 has none for HKDF [verified].
- **The wrappers exist on master but are unreleased [verified].** Commit
  `c0f9f85` (2026-07-10, "implement JS wrapper definitions for
  crypto_kdf_hkdf") added them, and 59 commits have landed since the 0.8.4
  tag (2026-04-19). A browser build from master exports HKDF: the
  `test:browser` run against `../libsodium.js/dist/browsers-sumo/sodium.js`
  reports "native export yes" and matches the vectors.

### Building HKDF from HMAC-SHA-256 [verified]

RFC 5869 is two HMAC steps. Extract: `PRK = HMAC(salt, IKM)`, where an
empty salt means 32 zero bytes. Expand:
`T(i) = HMAC(PRK, T(i-1) ‖ info ‖ byte(i))`, concatenated and truncated
to the requested length. The shim in `test/browser/index.html` and
`test/wasm/check.cljs` (about 12 lines) matches native HKDF, including
RFC 5869 A.1. Two traps:

- libsodium.js's one-shot `crypto_auth_hmacsha256` accepts only 32-byte
  keys ("invalid key length"). The A.1 salt is 13 bytes, so the shim uses
  the streaming `crypto_auth_hmacsha256_init/update/final`, which takes any
  key length.
- Output is capped at 255 × 32 = 8,160 bytes. The shim does not enforce
  this yet (signet only derives 32). TODO before production use.
- The standard (non-sumo) 0.8.4 build has no HMAC at all, so there the shim
  is impossible. Another reason to use sumo.

### The upcoming export takes `info` as a string — consequences [verified]

The master wrapper types HKDF's `info` (`ctx`) as a JavaScript string
(`unsized_string`). The conversion is in
`wrapper/macros/input_unsized_string.js`: `from_string(ctx + "\0")`,
passing the byte length minus the NUL, so an embedded NUL is not
truncated. `from_string` (`wrapper/wrap-esm-template.js`) is
`new TextEncoder().encode(str)`, i.e. UTF-8. When `TextEncoder` is missing
it falls back to `unescape(encodeURIComponent(str))`.

1. **Non-UTF-8 byte sequences are inexpressible.** RFC 5869 defines `info`
   as arbitrary bytes. Its own vector A.1 (`f0 f1 … f9`) is not valid UTF-8,
   so no JavaScript string yields those bytes. The native export cannot
   reproduce the RFC's own vector.
2. **Lone surrogates are silently replaced, so distinct labels collide.** A
   JS string is UTF-16 and may hold an unpaired surrogate, which has no
   UTF-8 encoding. `TextEncoder` maps it to U+FFFD with no error. Measured
   on Node 26.9:
   `TextEncoder("\uD800")` → `ef bf bd`, the same bytes as for `"�"`.
   So two different `info` strings give the same derived key, which is the
   collision `info` exists to prevent. Only the no-`TextEncoder` fallback
   throws (`URIError: URI malformed`), and every current browser and Node
   has `TextEncoder`.
3. **The JVM encodes the same string differently.** Java's
   `(.getBytes "\uD800" "UTF-8")` → `3f` (`?`). The same label therefore
   derives different keys on the JVM and in the browser, and each side sees
   only a decryption failure. This is the class of bug canonical-edn fixed
   in 1.4.0 (decision 10: lone surrogates became `?` on the JVM and U+FFFD
   in JS; cedn now rejects them).

signet is unaffected today: `"signet/box/v1"` is ASCII, which encodes
identically everywhere.

### Design rules for the cljc engine facade [inference]

- **Take `info` (and every KDF or AEAD context) as bytes**, never strings,
  at the facade's API. Callers encode on purpose: a constant byte array, or
  canonical-edn bytes, which reject lone surrogates.
- **In the browser, avoid the string-typed export.** Use the byte-based
  HMAC shim, or call the raw WASM export `_crypto_kdf_hkdf_sha256_expand`
  with a byte buffer, so every runtime feeds libsodium identical bytes.
- **If a string convenience API exists, reject lone surrogates** instead of
  replacing them. The same applies to anything that is hashed, signed or
  used as a key label.

### Upstream issue (draft, not filed)

libsodium.js master, `crypto_kdf_hkdf_sha256_expand` /
`crypto_kdf_hkdf_sha512_expand`: `ctx` is typed as a string and
UTF-8-encoded with `TextEncoder`. This means:

- binary `info` (RFC 5869 A.1) cannot be passed;
- lone surrogates are replaced with U+FFFD, so distinct labels derive the
  same key;
- the same label derives different keys than Java's UTF-8 encoder.

Suggestion: accept a `Uint8Array` for `ctx` (optionally also a string), as
the other buffer inputs do. Since the wrapper is unreleased, changing it
breaks nobody.

## Randomness

- Native libsodium's `randombytes_buf` uses the operating system's secure
  generator [source: libsodium docs].
- In the WASM build, randomness comes from `crypto.getRandomValues` in
  browsers or `crypto.randomBytes` on Node. When neither is available it
  fails closed: libsodium calls `sodium_misuse()` (an abort), and the older
  code threw `'No secure random number generator found'`. There is no
  `Math.random` fallback. **[verified]** read in `../libsodium`, commit
  `c960b3b0` (2026-09-22), "Emscripten: simplify randomness extraction".
- So for signet, secure randomness does come free with libsodium.
- **uuidv7 still needs its own fix [verified].** ClojureScript's
  `random-uuid` is built on `Math.random`, and uuidv7 uses it on CLJS, nbb
  and Scittle. With `Math.random` pinned, the "random" bits become
  identical. uuidv7 should stay dependency-free, so it needs a small
  `random-bytes` of its own (`SecureRandom` / `crypto.getRandomValues`,
  chunked at 65,536 bytes, fail closed) rather than a dependency on
  libsodium.

## Costs and risks

1. **Maturity.** `babashka.ffi` is under four weeks old and `node:ffi` is
   experimental. Both APIs could still change.
2. **Native dependency.** clj, bb and nbb users must install libsodium ≥
   1.0.19. Today signet on the JVM needs nothing beyond the JDK. Windows is
   untested. Linux distributions vary: check `pkg-config --modversion
   libsodium`.
3. **Version floors.** JDK 25+ and Node 26+ (not yet an LTS line). The
   native-access flag is needed on the JVM.
4. **Two binding layers.** The FFI binding and libsodium.js have different
   APIs. libsodium.js initialises asynchronously (`await sodium.ready`) and
   works on `Uint8Array`, where the FFI binding uses `byte[]`/`Int8Array`.
   A signet engine needs a cljc facade over both.
5. **Not in libsodium:** secp256k1. Options: keep Bouncy Castle on the JVM,
   or bind bitcoin-core's libsecp256k1 through the same FFI (untested).
6. **Secret hygiene.** `core.cljc` copies secrets into confined arenas and
   closes them, but does not zero them first. A production version should
   call `sodium_memzero` before closing (TODO). Every fixed-size input *is*
   length-checked (see "Memory safety").

## Suggested next steps

1. ~~Build a libsodium backend behind signet's `signet.impl.jvm` functions
   and run signet's suite against it~~ **Done:** passes on the JVM (102/436)
   and on bb (93/415). **Also done:** it now lives in signet itself (PR #1,
   merged to main 2026-09-23, build 0.7.0-SNAPSHOT) as `signet.impl.sodium`, behind a
   `signet.impl` facade that selects the backend once at load
   (`-Dsignet.backend` / `SIGNET_BACKEND`, default `jca`, loud failure
   instead of silent fallback). signet's own `test/signet/backend_parity.clj`
   compares both backends in one JVM (54 checks, byte-identical). The shim
   here stays as the no-changes-to-signet integration test.
2. Design the cljc engine facade: FFI for clj/bb/nbb, libsodium.js for
   Scittle. Decide how to handle async initialisation in the browser.
   Follow the byte-only rules in "Design rules for the cljc engine facade".
3. File the two libsodium.js observations upstream: string-typed HKDF
   `info` (draft above), and `crypto_scalarmult` in the master standard
   build.
4. Decide on secp256k1, and on how users get libsodium installed
   (documentation, or bundling per-platform binaries).
