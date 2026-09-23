# nacljc — project guide

Research repo, created 2026-09-23. It tests whether **libsodium** can be the
single crypto engine for Clojure on JVM, babashka, nbb and the browser.
Public repo: https://github.com/franks42/nacljc (created 2026-09-23;
no CI yet, and no release, since it is research code and not a published
library).

Renamed from `sodium.cljc` on 2026-09-23 (namespaces `sodium.*` → `nacljc.*`,
coordinates `com.github.franks42/sodium` → `com.github.franks42/nacljc`),
because Clojars' `com.degel/sodium` already ships `sodium.core`. It binds
libsodium, not the original NaCl: aligned with NaCl's design, but not the
same library (README "The name").

Read `docs/feasibility.md` first: findings, evidence, risks, next steps.
`README.md` has the requirements table (minimum and tested versions).

## Context

- The consumer is **signet** (`../signet`): Ed25519/X25519 signing and
  encryption. It runs on JVM and bb only (every `:cljs` branch throws), and
  its JCA seed→public-key trick fails on bb.
- It is built on **canonical-edn** (`../canonical-edn`) and **uuidv7**
  (`../uuidv7.cljc`).
- signet's 2026-09 review findings (trust model, key-store growth,
  ephemeral key retention, nonce reuse on stale session state) are in the
  Claude memory `signet-review-2026-09` for the canonical-edn project.
- The user has local clones of `../libsodium` and `../libsodium.js`, used to
  read randomness code and wrapper definitions.

## Rules of the road

- **Use Homebrew's libsodium** (`brew install libsodium`; tested 1.0.22).
  `core.cljc` looks in `/opt/homebrew/opt/libsodium/lib` first.
- **Document requirements.** Any new tool or version dependency goes into
  the README table, with a minimum and the version actually tested.
- **Test every runtime, the browser (Scittle) included:**
  `bb test:all` covers bb, JVM, nbb, WASM on Node, Scittle in headless
  Chromium, lint and fmt. `bb test:jca` needs `../signet`.
- **Lint and format every file.** A user-level Claude Code hook
  (`~/.claude/hooks/clj-lint.sh`) runs cljfmt and clj-kondo after edits.
  `bb lint` and `bb fmt` cover `src`, `test`, `bb.edn` and `deps.edn`.
- **Failing-first.** New tests must be shown to fail on bad input (e.g. a
  corrupted vector) before they count.
- Mark claims in the docs as **[verified]**, **[source]** or
  **[inference]**.

## Gotchas found so far

- `babashka.ffi` returns `byte[]` on JVM/bb and `Int8Array` on nbb.
- nbb has no `with-open`. `core.cljc` uses its `with-scratch` macro, which
  also wipes every native buffer (sodium_memzero) before closing the arena.
- The JVM needs JDK 25+ (JDK 21 fails) and `--enable-native-access=ALL-UNNAMED`
  (set in the `:test` alias).
- A bb task that calls `(System/exit 0)` ends a whole `bb test:all` run.
  Exit only on failure.
- Scittle has no `cljs.reader`. Use `clojure.edn`.
- libsodium.js 0.8.4: use **sumo** (standard has no HMAC/SHA-256/HKDF). HKDF
  is not exported (shim in the tests). The upcoming export types `info` as a
  UTF-8 string, so lone surrogates collide with U+FFFD and differ from the
  JVM's `?`. **Facade rule: KDF/AEAD contexts are bytes, never strings.**
  See "HKDF in libsodium and libsodium.js" in docs/feasibility.md.
- libsodium reads fixed-size inputs blindly: every input is type- and
  length-checked before the FFI call (`need-bytes!`, `need-count!`), or a
  short array makes it read past the allocation. `ed25519-verify?` returns
  false on bad sizes (untrusted input). Tests assert rejected input
  allocates **no** native memory: a missing guard whose C call still
  answers correctly (an over-read) is otherwise invisible.
- **Hardening rules for any new binding** (README "Memory and type
  safety"): check types and sizes first; allocate only through `alloc!`/`in!`
  inside `with-scratch`; copy results out with `read!`; check the return
  code; add the function to the public-API test, the bad-input table, the
  hygiene audit, and prove each guard by removing it.
- Without the count check, `(random-bytes -1)` aborts the process inside
  libsodium (`size <= SSIZE_MAX`). Never pass an unchecked count to C.
- Ed25519 takes 32-byte seeds only: libsodium's `crypto_sign_detached`
  hashes the secret key's public-key half unchecked, and a mismatched half
  leaks the scalar.
- On nbb, `babashka.ffi/write-array :char` accepts only `Int8Array`;
  `as-int8` makes a zero-copy view of a `Uint8Array`. `read-array` copies
  on both runtimes (verified), so wiping native memory is safe.
- clj-kondo: the `defcfn` hooks are imported into `.clj-kondo/imports`.
  `with-scratch` lints as `fn`, and promesa's `p/let` as `let`.

## Next steps (from the feasibility doc)

1. ~~libsodium backend behind signet's `signet.impl.jvm` functions~~ Done:
   `integration/signet-shim` passes signet's unmodified suite on the JVM
   (102/436, same as JCA) and on bb (93/415; JCA on bb: 16 errors).
   `bb test:signet`. Also moved into signet as `signet.impl.sodium` + the
   `signet.impl` facade, merged into signet's main (PR #1, 0.7.0-SNAPSHOT).
2. A cljc facade over FFI (clj/bb/nbb) and libsodium.js (Scittle).
3. File the two libsodium.js observations upstream.
4. Decide on secp256k1 (not in libsodium) and on distribution.
