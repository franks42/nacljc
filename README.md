# sodium.cljc

Proof of concept: **libsodium as one crypto engine for Clojure on every
runtime**, with one binding source file.

- **JVM Clojure, babashka and nbb** call native libsodium through
  [`babashka.ffi`](https://github.com/babashka/ffi). The same
  `src/sodium/core.cljc` runs unchanged on all three.
- **Browsers (Scittle)** use [libsodium.js](https://github.com/jedisct1/libsodium.js),
  libsodium compiled to WebAssembly.

Every engine produces byte-identical results. They reproduce the RFC test
vectors, and they reproduce the outputs of signet's current JCA backend, so
moving signet onto libsodium would change no signature, key or ciphertext.

**signet runs on it unchanged.** A drop-in `signet.impl.jvm` built on
`sodium.core` (`integration/signet-shim`) passes signet's own, unmodified
suite:

- JVM: 102 tests / 436 assertions, identical to signet's JCA backend.
- babashka: 93 / 415, which is every test except secp256k1 (Bouncy Castle
  cannot load on bb). With its own JCA backend, signet gets 16 errors on bb.

Status: **experimental research code**, not a library yet.
[`docs/feasibility.md`](docs/feasibility.md) has the findings, the evidence
and the open questions.

## Requirements

All of these are needed to run everything. Each runtime also works on its
own.

| Component | Minimum | Tested | Notes |
|---|---|---|---|
| libsodium (native) | **1.0.19** | 1.0.22 (Homebrew) | 1.0.19 added HKDF; `sodium.core` checks the version at load and throws `::libsodium-too-old` for anything older. macOS: `brew install libsodium`. On Linux, check your distribution's version with `pkg-config --modversion libsodium`, since some ship an older one. |
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
bb test:wasm      # libsodium.js on Node        (first: cd test/wasm && npm install)
bb test:browser   # Scittle + libsodium.js in headless Chromium
                  # (first: cd test/browser && npm install; optional arg = a libsodium.js build URL or path)
bb test:jca       # random-input cross-check against signet's JCA backend (needs ../signet)
bb test:signet    # signet's own test suite: JCA oracle (JVM), libsodium (JVM), libsodium (bb)
                  #   (needs ../signet; also test:signet-jca / test:signet-jvm / test:signet-bb)
bb test:all       # everything except test:jca and test:signet, plus lint and format
bb install        # install com.github.franks42/sodium 0.1.0-SNAPSHOT into ~/.m2 (local only)
```

`bb install` builds a jar containing only `src/` (its pom depends on
`org.babashka/ffi 0.1.2`) and installs it locally, so consumers such as
signet can test the packaged artifact. Re-run it after every change, or
consumers keep using the old jar. There is deliberately no deploy task:
nothing is published to Clojars. On babashka, the jar's `org.babashka/ffi`
dependency is ignored; bb always uses its built-in `babashka.ffi`
(verified).

`test:wasm` and `test:browser` need the network: npm, and jsdelivr for
Scittle and libsodium.js.

## Layout

```
src/sodium/core.cljc          the binding (Ed25519, Ed25519->X25519, X25519, SHA-256,
                              HMAC-SHA-256, ChaCha20-Poly1305 IETF, HKDF-SHA-256,
                              randombytes); fixed-size inputs are length-checked
test/sodium/vectors.edn       RFC vectors + cross-platform vectors
test/sodium/core_test.cljc    known-answer tests for JVM, bb and nbb
test/sodium/jca_crosscheck.clj  libsodium vs signet's JCA on random inputs
test/wasm/check.cljs          libsodium.js on Node against the same vectors
test/browser/index.html       Scittle page doing the same in a browser
test/browser/run.mjs          Playwright runner for that page
integration/signet-shim/signet/impl/jvm.clj
                              drop-in libsodium backend for signet (same ns, 16 fns)
integration/sodium/signet_suite.clj
                              runs signet's unmodified tests; asserts which backend loaded
docs/feasibility.md           findings and recommendation
```

## License

Copyright (c) Frank Siebenlist. Distributed under the [Eclipse Public License v2.0](LICENSE).
