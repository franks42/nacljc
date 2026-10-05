# Ed25519 and message size: signing a digest for HSMs, KMS and smart cards

Written 2026-10-05, from a design discussion about letting signet keep
long-term keys in a YubiKey, AWS KMS or a YubiHSM next to nacljc's guarded
memory. Claims are marked as in `feasibility.md`: **[verified]** was
checked in code or run, **[source]** comes from the cited documentation,
**[inference]** is our own reasoning.

## The problem

signet signs the canonical EDN bytes of the whole envelope
(`{:message … :signer … :request-id … :expires …}`) with pure Ed25519
**[verified: `signet.sign/sign-edn`]**. The payload is inside the signed
bytes. The SHA-256 values `verify-edn` returns (`:digest`,
`:message-digest`) are computed after verification as identifiers; they are
not what is signed **[verified]**.

That is fine in process: nacljc signs any length in guarded memory. It
stops being fine when the key lives somewhere the message has to be sent:

| Signer | What it receives for Ed25519 | Limit |
|---|---|---|
| nacljc / libsodium (`crypto_sign_detached`) | the full message | none in practice |
| AWS KMS, raw message type | the full message | 4096 bytes **[source: Cosmos KMS docs]** |
| YubiKey 5 PIV (fw ≥ 5.7, alg `0xE0`) | the full message, unhashed, sent as chained 255-byte APDUs **[verified: `yubikit/piv.py`, `_pad_message` returns the message as-is for Ed25519]** | undocumented; bounded by the card's RAM buffer **[inference]**. Certificate bodies (≈1 KB) work. Measure before relying on more. |
| YubiHSM 2 | the full message | device command size **[inference]** |

## Why Ed25519 cannot be "digested" by the host

Pure Ed25519 (RFC 8032) hashes internally, but twice, and both passes need
every byte of the message:

1. nonce `r = SHA-512(prefix ‖ M)`, where `prefix` is the secret half of
   `SHA-512(seed)`: only the key holder can compute it;
2. challenge `k = SHA-512(R ‖ A ‖ M)`, which can only start after (1).

So the device must hold all of `M` at once. That is why KMS caps the raw
message and a smart card is limited by its RAM, not its CPU. ECDSA is
different: `SHA256withECDSA` hashes once and signs the digest, so
secp256k1 can be sent to KMS or a YubiHSM as a 32-byte digest today.

## Two ways out

### A. Ed25519ph (RFC 8032 pre-hash variant)

`Ed25519ph(M)` signs `SHA-512(M)` with a domain prefix (`dom2` with the
pre-hash flag). libsodium's multi-part API (`crypto_sign_init` /
`_update` / `_final_create`) is Ed25519ph, and its docs say
`Ed25519ph(m)` is intentionally not `Ed25519(SHA512(m))` **[source:
libsodium docs]**. AWS KMS also has a digest message type for Ed25519
keys.

### B. Pure Ed25519 over a framed digest (the minisign / SSHSIG pattern)

Hash the message on the host, wrap the digest in a small frame, and sign
the frame with ordinary pure Ed25519. Every backend then signs about a
hundred bytes.

This is what deployed formats do:

- **minisign** (Frank Denis): `ED` signatures are
  `ed25519(BLAKE2b-512(file))`; the legacy `Ed` format signed the raw file.
  New implementations must use the hashed format. A second "global"
  signature covers `signature ‖ trusted_comment` **[source: minisign
  format docs]**.
- **SSHSIG** (`ssh-keygen -Y sign`): signs
  `"SSHSIG" ‖ namespace ‖ reserved ‖ hash_algorithm ‖ H(message)`, hash
  `sha256` or `sha512`. Hashing is there "to limit the amount of data
  presented to the signature operation, which may be of concern if the
  signing key is held in limited or slow hardware or on a remote
  ssh-agent"; the namespace prevents cross-protocol attacks **[source:
  draft-josefsson-sshsig-format-04]**.
- **OpenPGP EdDSA** feeds the message digest, untruncated, to EdDSA
  **[source: draft-koch-eddsa-for-openpgp-04]**.
- **COSE Hash Envelope** makes the hash the COSE_Sign1 payload, with the
  hash algorithm in the protected header, motivated by remote and HSM
  signing **[source: draft-ietf-cose-hash-envelope-09]**.

libsodium has the parts but not the composition: `crypto_generichash`
(BLAKE2b, 64-byte output) and `crypto_sign_detached`. minisign composes
them itself.

### Comparison

| | Ed25519ph | Pure Ed25519 over a framed digest |
|---|---|---|
| Standardised | RFC 8032 | per format (minisign, SSHSIG, COSE); ours would be our own |
| Signature verifies as pure Ed25519 | no; a separate scheme | yes |
| libsodium | multi-part API | `crypto_generichash` or `crypto_hash_sha512` + `crypto_sign_detached` |
| YubiKey PIV | not supported, as far as we know **[inference]** | yes (it is just a short message) |
| AWS KMS | digest message type | raw message type |
| Byte-identical across our backends | no: only where ph exists | yes, so the JCA/libsodium parity tests extend to hardware |
| Collision resilience | lost (a hash collision gives a forgery) | lost, same trade-off |
| Domain separation | `dom2` prefix built in | must be designed in (the frame) |
| Adoption | little; Sigstore moved Fulcio back to pure Ed25519 **[source: sigstore/sigstore PR #1616]** | minisign, SSHSIG, OpenPGP, COSE |

Choose B. Ed25519ph would add a signature flavour that hardware cannot
reproduce, while B works the same on every signer we care about.

## What B needs to be safe

The pattern is sound, but "the digest becomes the message" alone is not
enough. From the formats above:

1. **A magic value and a namespace in the signed bytes.** signet already
   signs short raw values (the chain seal signs the previous 64-byte
   signature). Without a namespace, a signature over a bare digest in one
   context could be valid in another.
2. **The hash algorithm's identity in the signed bytes**, so it cannot be
   swapped and can be upgraded.
3. **An unambiguous version marker** outside and inside the signature, so
   a verifier never guesses whether a signature is over a frame or over
   raw bytes (minisign's `Ed`/`ED`).
4. **The full 512-bit digest**, untruncated.

The cost is that security now rests on the hash's collision resistance
(SHA-512 or BLAKE2b-512: no practical concern), and that verifiers must
recompute the digest. Existing signet envelopes keep verifying under v1
rules.

## Design direction (implementation placement still open)

Updated 2026-10-05. Where the code lives, nacljc or signet, is still up
for discussion. The behaviour below is the agreed direction.

### Callers never choose between "hashed" and "raw"

An application signs a message and verifies a signature. It does not pick
a mode, pass a digest, or know about frames. The signing path always uses
the framed digest (option B); verification works out which rule applies
from a version carried with the signature.

That requires something to carry the version, so the transparent API
lives where there is an envelope:

- **signet's envelope gets a version inside the signed data**, for
  example `{:v 2 :message … :signer … :request-id …}`, and the frame
  carries its own marker (`:signet/sig 2`, or the binary magic below).
  The version is authenticated, not just a label.
- **`verify-edn` dispatches on it.** v2: recompute the frame from the
  canonical envelope and verify; no version: the v1 rule (pure Ed25519
  over the canonical envelope). The caller sees the same `{:valid? …}`
  either way.
- **No downgrade or cross-verification** **[inference]**. A v2 signature
  covers a frame; a v1 signature covers an envelope map that must contain
  `:message`, `:signer` and `:request-id`. Neither byte string can be the
  other, so relabelling an envelope gets an attacker nothing. A minimum
  version option (`{:min-v 2}`) lets a deployment stop accepting v1 once
  old envelopes have expired.
- **Every signing context gets a namespace**: `:envelope`,
  `:chain-block`, `:chain-seal` (today it signs a raw 64-byte value),
  `:external`. No public path signs unframed bytes.
- **Raw `ed25519-sign` stays as it is.** Its contract is libsodium's
  `crypto_sign_detached`: the RFC 8032 vectors, byte-for-byte parity with
  the JCA backend, and the reference that hardware signatures are checked
  against. A bare 64-byte signature has nowhere to carry a version, so a
  raw signer that silently hashed could not be verified transparently. It
  becomes an internal building block rather than an application API.

### One call: hash, frame and sign together

The signing entry point takes the **message**, not a digest, and computes
the digest, the frame and the signature itself, in one call. Splitting it
into "hash" then "sign" opens a gap: whoever sits between the two calls
can hand the signer a digest that is not the hash of the message that was
shown, logged or checked. With a single call the signer only ever signs
the hash it computed itself.

What this does and does not protect against **[inference]**:

- **It closes digest substitution** by bugs, by misuse, and by any layer
  between hashing and signing, and it means the key can never be used to
  sign an arbitrary caller-supplied digest or frame.
- **It does not stop a caller that controls the whole call.** Code that can
  call `sign` can choose any message. Inside one process the boundary is
  the API, not memory protection.
- **It matters most across a trust boundary.** When the signer is a
  separate component (signet's agent, a vault process, a policy check in
  front of the key), receiving the full message lets that component
  inspect, log or refuse what it actually signs. A digest would make it a
  blind oracle.
- **Guarded memory is for the seed, not the message.** The message, the
  digest and the frame are public; copying the message into
  `sodium_malloc` memory adds no secrecy. What a single native call does
  add is that hashing, framing and signing happen in one place with no
  Clojure-side value in between to tamper with.

For hardware keys the same rule applies one level up. A YubiKey or KMS
cannot hash a large message itself (that is the whole problem), so the
host must build the frame. The boundary is therefore the **vault
provider**: `vault/sign` takes the message; the `:sodium` provider does
hash, frame and sign in one nacljc call; a `:yubikey-piv` or `:aws-kms`
provider hashes and frames inside the provider and sends only the frame to
the device. Nothing above the provider ever handles a digest.

### Building blocks (placement open)

Whichever library ends up owning the policy, these pieces are needed:

```clojure
;; message in, signature out: hash + frame + sign in one native call
(sign-message seed-or-secret msg {:ns :envelope})          ; => signature 64
(verify-message? pk msg sig {:ns :envelope})               ; => boolean, never throws

;; for hardware providers only: the frame a device signs
(message-frame msg {:ns :envelope})                        ; => public bytes, ~100
```

A frame in the SSHSIG style, binary so non-Clojure verifiers can
reproduce it **[inference: proposal]**:

```
"NACLJC-H1"            magic and version
u32 len ‖ namespace    UTF-8, required, non-empty
u8  hash id            1 = BLAKE2b-512 (crypto_generichash, 64-byte output)
64 bytes               H(msg)
```

An EDN frame (`{:signet/sig 2 :ns … :hash :blake2b-512 :digest …}`,
canonical via cedn) is the alternative if the frame lives in signet. The
binary form is easier for other languages; the EDN form keeps signet
EDN-native. Undecided.

Needed in `nacljc.core` either way: a `crypto_generichash` (BLAKE2b)
binding and, optionally, `crypto_hash_sha512`.

Separately, an exact **minisign-compatible** pair
(`ed25519(BLAKE2b-512(file))`, no frame) could sign files for minisign
tools. It has no namespace, so it must not be used for signet's
envelopes.

## Open points

- Measure the YubiKey's real Ed25519 message limit: sign 1, 2, 3 and 4 KB
  with `session.sign(slot, KEY_TYPE.ED25519, msg, None)` on a 5.7+ key and
  verify each with libsodium.
- Confirm that KMS's Ed25519 digest message type is Ed25519ph (we only use
  the raw type in option B).
- secp256k1 needs none of this: it already pre-hashes with SHA-256.
- Where the policy lives: nacljc (frame and one-call signing as
  primitives) or signet (versioned envelopes, vault providers), and
  binary versus EDN frame.

## Sources

- [minisign signature format](https://jedisct1.github.io/minisign/)
- [draft-josefsson-sshsig-format-04](https://www.ietf.org/archive/id/draft-josefsson-sshsig-format-04.html)
- [draft-ietf-cose-hash-envelope-09](https://www.ietf.org/archive/id/draft-ietf-cose-hash-envelope-09.html)
- [draft-koch-eddsa-for-openpgp-04](https://potaroo.net/ietf/all-ids/draft-koch-eddsa-for-openpgp-04.html)
- [libsodium: public-key signatures](https://doc.libsodium.org/public-key_cryptography/public-key_signatures)
- [Cosmos SDK KMS backends (KMS 4096-byte raw cap)](https://docs.cosmos.network/sdk/latest/kms/configure-backend)
- [Yubico/yubikey-manager, `yubikit/piv.py`](https://github.com/Yubico/yubikey-manager)
- [sigstore/sigstore PR #1616](https://github.com/sigstore/sigstore/pull/1616)
