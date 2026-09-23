(ns sodium.core
  "Thin libsodium binding over babashka.ffi. One source file for JVM
   Clojure (org.babashka/ffi, JDK 25+), babashka (built in) and nbb
   (built in, Node 26+ node:ffi).

   Byte arrays in and out: byte[] on the JVM and bb, Int8Array on nbb.
   Covers the primitives signet uses: Ed25519, Ed25519->X25519
   conversion, X25519, ChaCha20-Poly1305 IETF, HKDF-SHA-256 and
   randombytes. Status: proof of concept — see docs/feasibility.md."
  (:require [babashka.ffi :as ffi]))

(def lib
  "The loaded libsodium. HKDF needs libsodium >= 1.0.19."
  (ffi/load-library {:mac   ["/opt/homebrew/opt/libsodium/lib/libsodium.dylib"
                             "/usr/local/opt/libsodium/lib/libsodium.dylib"]
                     :linux ["libsodium.so.26" "libsodium.so.23" "libsodium.so"]}))

(ffi/defcfn -sodium-init {:library lib} "sodium_init" [] :int)
(ffi/defcfn version-string {:library lib} "sodium_version_string" [] :string)
(ffi/defcfn -randombytes-buf {:library lib} "randombytes_buf" [:pointer :size_t] :void)
(ffi/defcfn -sign-seed-keypair {:library lib} "crypto_sign_seed_keypair"
  [:pointer :pointer :pointer] :int)
(ffi/defcfn -sign-detached {:library lib} "crypto_sign_detached"
  [:pointer :pointer :pointer :ulong :pointer] :int)
(ffi/defcfn -sign-verify-detached {:library lib} "crypto_sign_verify_detached"
  [:pointer :pointer :ulong :pointer] :int)
(ffi/defcfn -pk-to-curve25519 {:library lib} "crypto_sign_ed25519_pk_to_curve25519"
  [:pointer :pointer] :int)
(ffi/defcfn -sk-to-curve25519 {:library lib} "crypto_sign_ed25519_sk_to_curve25519"
  [:pointer :pointer] :int)
(ffi/defcfn -scalarmult {:library lib} "crypto_scalarmult_curve25519"
  [:pointer :pointer :pointer] :int)
(ffi/defcfn -scalarmult-base {:library lib} "crypto_scalarmult_curve25519_base"
  [:pointer :pointer] :int)
(ffi/defcfn -hash-sha256 {:library lib} "crypto_hash_sha256"
  [:pointer :pointer :ulong] :int)
(ffi/defcfn -hmacsha256-statebytes {:library lib} "crypto_auth_hmacsha256_statebytes" [] :size_t)
(ffi/defcfn -hmacsha256-init {:library lib} "crypto_auth_hmacsha256_init"
  [:pointer :pointer :size_t] :int)
(ffi/defcfn -hmacsha256-update {:library lib} "crypto_auth_hmacsha256_update"
  [:pointer :pointer :ulong] :int)
(ffi/defcfn -hmacsha256-final {:library lib} "crypto_auth_hmacsha256_final"
  [:pointer :pointer] :int)
(ffi/defcfn -aead-encrypt {:library lib} "crypto_aead_chacha20poly1305_ietf_encrypt"
  [:pointer :pointer :pointer :ulong :pointer :ulong :pointer :pointer :pointer] :int)
(ffi/defcfn -aead-decrypt {:library lib} "crypto_aead_chacha20poly1305_ietf_decrypt"
  [:pointer :pointer :pointer :pointer :ulong :pointer :ulong :pointer :pointer] :int)
(ffi/defcfn -hkdf-extract {:library lib} "crypto_kdf_hkdf_sha256_extract"
  [:pointer :pointer :size_t :pointer :size_t] :int)
(ffi/defcfn -hkdf-expand {:library lib} "crypto_kdf_hkdf_sha256_expand"
  [:pointer :size_t :pointer :size_t :pointer] :int)

(when (neg? (-sodium-init))
  (throw (ex-info "sodium_init failed" {})))

(defmacro ^:private with-arena
  "Like with-open over a confined arena; nbb has no with-open."
  [[a] & body]
  `(let [~a (ffi/confined-arena)]
     (try ~@body (finally (.close ~a)))))

(defn- in [arena bs]
  (let [p (ffi/alloc arena (max 1 (alength bs)))]
    (ffi/write-array p :char bs)
    p))

(defn- out [arena n] (ffi/alloc arena n))

(defn- bytes-of [p n] (ffi/read-array p :char n))

(defn- check! [rc what]
  (when-not (zero? rc)
    (throw (ex-info (str what " failed") {:rc rc}))))

(defn- check-len!
  "libsodium reads fixed-size inputs (keys, seeds, signatures, nonces)
   without knowing the buffer size. A shorter array would make it read past
   the allocation, so every fixed-size input is checked before the call."
  [bs n what]
  (when-not (and (some? bs) (= n (alength bs)))
    (throw (ex-info (str what " must be " n " bytes")
                    {:type ::bad-length :what what :expected n
                     :actual (when (some? bs) (alength bs))}))))

(defn- bytes-or-empty [bs]
  (or bs #?(:clj (byte-array 0) :cljs (js/Int8Array. 0))))

(defn random-bytes
  "n bytes from libsodium's CSPRNG (the OS generator natively)."
  [n]
  (with-arena [a]
    (let [p (out a n)]
      (-randombytes-buf p n)
      (bytes-of p n))))

(defn seed->keypair
  "Ed25519: 32-byte seed -> [public-key(32) secret-key(64)]."
  [seed]
  (check-len! seed 32 "Ed25519 seed")
  (with-arena [a]
    (let [pk (out a 32) sk (out a 64)]
      (check! (-sign-seed-keypair pk sk (in a seed)) "crypto_sign_seed_keypair")
      [(bytes-of pk 32) (bytes-of sk 64)])))

(defn sign
  "Ed25519 detached signature (64 bytes) of msg with a 64-byte secret key."
  [sk msg]
  (check-len! sk 64 "Ed25519 secret key")
  (with-arena [a]
    (let [sig (out a 64)]
      (check! (-sign-detached sig ffi/null (in a msg) (alength msg) (in a sk))
              "crypto_sign_detached")
      (bytes-of sig 64))))

(defn verify?
  "True if sig is a valid Ed25519 signature of msg under pk. Returns false
   (never throws) for a signature or key of the wrong size: both are
   untrusted input."
  [pk msg sig]
  (and (some? pk) (= 32 (alength pk))
       (some? sig) (= 64 (alength sig))
       (with-arena [a]
         (zero? (-sign-verify-detached (in a sig) (in a msg) (alength msg) (in a pk))))))

(defn ed-pk->x-pk
  "Ed25519 public key -> X25519 public key."
  [ed-pk]
  (check-len! ed-pk 32 "Ed25519 public key")
  (with-arena [a]
    (let [o (out a 32)]
      (check! (-pk-to-curve25519 o (in a ed-pk)) "crypto_sign_ed25519_pk_to_curve25519")
      (bytes-of o 32))))

(defn ed-sk->x-sk
  "Ed25519 64-byte secret key -> X25519 secret key."
  [ed-sk]
  (check-len! ed-sk 64 "Ed25519 secret key")
  (with-arena [a]
    (let [o (out a 32)]
      (check! (-sk-to-curve25519 o (in a ed-sk)) "crypto_sign_ed25519_sk_to_curve25519")
      (bytes-of o 32))))

(defn x25519
  "X25519 shared secret. Throws for low-order points (libsodium returns -1)."
  [our-sk their-pk]
  (check-len! our-sk 32 "X25519 secret key")
  (check-len! their-pk 32 "X25519 public key")
  (with-arena [a]
    (let [o (out a 32)]
      (check! (-scalarmult o (in a our-sk) (in a their-pk)) "crypto_scalarmult_curve25519")
      (bytes-of o 32))))

(defn aead-encrypt
  "ChaCha20-Poly1305 IETF: key(32) nonce(12) plaintext ad -> ciphertext||tag(16).
   ad may be nil."
  [k nonce pt ad]
  (check-len! k 32 "AEAD key")
  (check-len! nonce 12 "AEAD nonce")
  (let [ad (bytes-or-empty ad)]
    (with-arena [a]
      (let [n (+ (alength pt) 16)
            c (out a n)]
        (check! (-aead-encrypt c ffi/null (in a pt) (alength pt) (in a ad) (alength ad)
                               ffi/null (in a nonce) (in a k))
                "crypto_aead_chacha20poly1305_ietf_encrypt")
        (bytes-of c n)))))

(defn aead-decrypt
  "Inverse of aead-encrypt. Throws ex-info on authentication failure or a
   ciphertext shorter than the 16-byte tag. ad may be nil."
  [k nonce ct ad]
  (check-len! k 32 "AEAD key")
  (check-len! nonce 12 "AEAD nonce")
  (when-not (and (some? ct) (<= 16 (alength ct)))
    (throw (ex-info "AEAD ciphertext shorter than the 16-byte tag"
                    {:type ::bad-length :what "AEAD ciphertext"})))
  (let [ad (bytes-or-empty ad)]
    (with-arena [a]
      (let [n (- (alength ct) 16)
            m (out a (max 1 n))]
        (when-not (zero? (-aead-decrypt m ffi/null ffi/null (in a ct) (alength ct)
                                        (in a ad) (alength ad) (in a nonce) (in a k)))
          (throw (ex-info "AEAD authentication failed" {})))
        (bytes-of m n)))))

(defn hkdf-sha256
  "RFC 5869 HKDF-SHA-256 extract-then-expand; len bytes (max 8160)."
  [ikm salt info len]
  (with-arena [a]
    (let [prk (out a 32)
          o   (out a len)]
      (check! (-hkdf-extract prk (in a salt) (alength salt) (in a ikm) (alength ikm))
              "crypto_kdf_hkdf_sha256_extract")
      (check! (-hkdf-expand o len (in a info) (alength info) prk)
              "crypto_kdf_hkdf_sha256_expand")
      (bytes-of o len))))

(defn x25519-base
  "X25519 public key for a 32-byte secret key (scalar times the base point)."
  [sk]
  (check-len! sk 32 "X25519 secret key")
  (with-arena [a]
    (let [o (out a 32)]
      (check! (-scalarmult-base o (in a sk)) "crypto_scalarmult_curve25519_base")
      (bytes-of o 32))))

(defn sha-256
  "SHA-256 digest (32 bytes)."
  [data]
  (with-arena [a]
    (let [o (out a 32)]
      (check! (-hash-sha256 o (in a data) (alength data)) "crypto_hash_sha256")
      (bytes-of o 32))))

(defn hmac-sha256
  "HMAC-SHA-256 (32 bytes) with a key of any length (streaming API)."
  [k data]
  (with-arena [a]
    (let [st (out a (-hmacsha256-statebytes))
          o  (out a 32)]
      (check! (-hmacsha256-init st (in a k) (alength k)) "crypto_auth_hmacsha256_init")
      (check! (-hmacsha256-update st (in a data) (alength data)) "crypto_auth_hmacsha256_update")
      (check! (-hmacsha256-final st o) "crypto_auth_hmacsha256_final")
      (bytes-of o 32))))
