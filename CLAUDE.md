# nacljc — project guide

libsodium for Clojure on the JVM, babashka and nbb (babashka.ffi), with
libsodium.js (WASM) tested for the browser. Public repo:
https://github.com/franks42/nacljc. Namespaces: `nacljc.core` (the
libsodium binding: the C boundary), `nacljc.process` (opt-in process
hardening, libc), `nacljc.tty` (terminal password input into guarded
memory, libc).

## Current state (2026-09-28)

**Released: 0.6.0 (2026-09-28). main is 0.7.0-SNAPSHOT** (CHANGELOG has an
empty `## 0.7.0 (unreleased)`). CI green (lint, macOS, Linux). signet
0.10.0 depends on nacljc 0.6.0.

Releases (details in CHANGELOG.md):
- **0.6.0:** `nacljc.tty`: `read-password` (/dev/tty, ECHO and ISIG off,
  canonical mode, `read(2)` into sodium_malloc memory, newline and ^C
  found with `memchr`; `{:confirm …}`), `read-password-fd`. `bb test:tty`
  drives a pseudo-terminal with script(1) on bb, the JVM and nbb (12
  checks each; verified on macOS and Linux CI). termios c_lflag is read as
  a 32-bit :int at offset 24 (macOS) / 12 (Linux), little-endian.
- **0.5.0:** `wrap-secret` / `unwrap-secret` (key wrapping in guarded
  memory; signet's vault files).
- **0.4.0:** `constant-time-equal?` over secrets, `nacljc.process`
  (opt-in hardening), Argon2id (`argon2id`, `argon2id-limits`).
- **0.3.x:** `secret-split`, secret HKDF salt (0.3.0); `sodium_stackzero`
  after every secret operation (0.3.1); review fixes and purity/throws
  docstrings everywhere (0.3.2).
- **0.2.0:** secrets in guarded memory (`secret-*`), AEGIS-256, X-Wing.
- **0.1.0:** first Clojars release.

### Possible next steps (none chosen; ask the user)

- Whatever signet needs next (signet's CLAUDE.md lists its candidates).
  Candidates here: pinentry support (a GUI prompt answering over a pipe,
  read into a secret like `read-password-fd`), peer-credential checks
  (`SO_PEERCRED` / `getpeereid`) for signet's agent (docs/12 in signet;
  the agent is on the back burner).
- **Back burner:** CI for libsodium < 1.0.19 (Ubuntu/Debian 1.0.18).

### Workflow

- Commit and push only when asked. Bugs: failing-first test; every guard
  injection-checked.
- Release: set build.clj's version and `## X.Y.Z (YYYY-MM-DD)` in the
  CHANGELOG; `bb release-check`, `bb test:jar`; commit "Release X.Y.Z",
  push, wait for CI; tag `vX.Y.Z` (release.yml: tests, deploy, `bb
  test:clojars X.Y.Z`, GitHub release); then bump build.clj to the next
  -SNAPSHOT and add an unreleased CHANGELOG heading. `bb
  check-not-released` (in test:jar) refuses a released version.
- No Docker locally: Linux-only behavior is verified in CI.

### Decisions (2026-09-27)

- **Old libsodium (Ubuntu/Debian 1.0.18): back burner.** No CI job for it
  for now; the load-time version check still refuses a too-old libsodium
  loudly (`::libsodium-too-old`).
- **Process hardening is opt-in, never automatic** (`nacljc.process`,
  its own namespace). Loading nacljc or signet changes no process
  settings; the README documents each option and its trade-off. A
  deployment choice.

### Rules

- **Docstrings:** every function, public and private, states its purity in
  its first paragraph: `Pure.`, or `Impure: <what it reads or writes>`, or
  for key-taking functions "Pure for byte-array keys; with a secret,
  impure: reads it". Then `Throws ex-info {:type ::x} when …` with every
  `:type` (or `Never throws`). Scratch native memory allocated and wiped
  within a call does not count as state.
- **Hard rule: this ns is the C boundary.** Read the README's "Memory and
  type safety" section and follow the hardening rules below for any change.

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
  length-checked before the FFI call (`check-bytes`, `check-count`), or a
  short array makes it read past the allocation. `ed25519-verify?` returns
  false on bad sizes (untrusted input). Tests assert rejected input
  allocates **no** native memory: a missing guard whose C call still
  answers correctly (an over-read) is otherwise invisible.
- **Hardening rules for any new binding** (README "Memory and type
  safety"): check types and sizes first; allocate only through `alloc!`/`in!`
  inside `with-scratch`; copy results out with `read-bytes`; check the return
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

## Earlier roadmap (from the feasibility doc; items 2–4 still open)

1. ~~libsodium backend behind signet's `signet.impl.jvm` functions~~ Done,
   and moved into signet as `signet.impl.sodium` + the `signet.impl`
   facade (0.7.0). The early shim (`integration/`) was removed in 0.3.2;
   `bb test:signet` now runs signet's own suite on this checkout (JVM
   183/1000 + parity 54, bb 173/974 with signet 0.9.2).
2. A cljc facade over FFI (clj/bb/nbb) and libsodium.js (Scittle).
3. File the two libsodium.js observations upstream.
4. Decide on secp256k1 (not in libsodium) and on distribution.

## Naming: purity, `!` and exceptions

The same convention holds in canonical-edn, uuidv7, nacljc and signet
(decided 2026-09-23).

- **`!` means the call writes state that outlives it.** That covers
  atoms, volatiles and transients, global registries (such as signet's key
  store), the contents of an argument (wiping a buffer, consuming a
  session state), native memory the caller owns, files, databases and
  network sends. This is clojure.core's line (`reset!`, `swap!`, `conj!`),
  extended to external writes, as in the Clojure style guide's `save-user!`.
- **Reads get no `!`, even impure ones:** the clock, the random
  generator (drawing is not a write), the environment, system properties
  and file reads. Printing and logging are diagnostic and get no `!`
  either. The docstring says what the function reads.
- **`!` never means "may throw".** That is the Elixir and Rails meaning,
  and it is not used here. An exception signals abnormal execution, and
  Clojure never forces a caller to catch one, so throwing is documented,
  not encoded in the name.
- **Docstrings** state these facts in their first paragraph, in fixed
  wording:
  - `Impure: <what it reads or writes>.` for every impure function.
  - `Throws ex-info {:type ::x} when …`, listing every `:type`. The
    ex-data `:type` is the contract; callers dispatch on it, never on the
    message.
  - `Never throws: …` for functions that promise it, such as verifiers
    returning `{:valid? false …}`.
- **Validators** that return their argument or throw are named `check-…`
  (for example `check-bytes`). Helpers whose only job is to throw are named
  `throw-…`.
- **Prefer a pure core with a thin `!` shell** (functional core, imperative
  shell). When a function both computes and writes, offer the pure one and
  make the write a separate, explicit `!` call, rather than only renaming.

Existing names that break this rule were inventoried on 2026-09-23 and
have not been renamed yet.
