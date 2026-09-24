(ns nacljc.core
  "libsodium for Clojure: one source file for JVM Clojure (org.babashka/ffi,
   JDK 25+), babashka (built in) and nbb (built in, Node 26+ node:ffi).

   This namespace is the boundary between Clojure and C. C trusts every
   pointer and length it is given, so everything is checked here, before
   C sees it:

   - Types: every byte input must be a byte array: byte[] on the JVM and
     bb; Int8Array or Uint8Array on nbb. Anything else throws ::bad-input.
     Counts must be integers. Error data names types and sizes, never
     contents.
   - Sizes: fixed-size inputs (keys, seeds, nonces, signatures) are
     length-checked (::bad-length). Variable lengths passed to C are always
     taken from the array itself, never from the caller.
   - Native memory: each call copies its inputs into a fresh confined arena,
     calls C, and copies the results out. Before the arena is released,
     every buffer in it is wiped with sodium_memzero, on success and on
     error. No pointer escapes a call; results are fresh arrays; inputs are
     never written to.
   - Ed25519 secrets are 32-byte seeds. The 64-byte libsodium secret key
     (seed || public key) exists only in native memory, inside one call, so
     a mismatched public-key half cannot leak the private scalar.
   - Every libsodium return code is checked. Failures are typed:
     ::auth-failed, ::low-order-point, ::invalid-public-key, ::call-failed.
   - The raw C bindings are private.

   What the caller still owns: the byte arrays passed in and returned live
   on the Clojure heap. They are not locked in memory, and the JVM's moving
   garbage collector may have copied them. Wipe secrets you no longer need
   with memzero!. Raw bytes also cannot tell an Ed25519 public key from an
   X25519 public key (both 32 bytes): a typed layer above this one (such as
   signet's key records) must keep them apart.

   Loading: libsodium >= 1.0.19 is loaded when this namespace loads. Set
   NACLJC_LIBSODIUM (or, on the JVM and bb, the system property
   nacljc.libsodium) to a library path to use exactly that library."
  (:require [babashka.ffi :as ffi]
            [clojure.string :as str]))

;; ---------------------------------------------------------------------------
;; Loading libsodium
;; ---------------------------------------------------------------------------

(def ^:private default-locations
  "Where libsodium is looked for when no location is configured, per OS."
  {:mac   ["/opt/homebrew/opt/libsodium/lib/libsodium.dylib" ; Homebrew, Apple silicon
           "/usr/local/opt/libsodium/lib/libsodium.dylib"    ; Homebrew, Intel
           "/opt/local/lib/libsodium.dylib"]                 ; MacPorts
   ;; .so.23 is libsodium 1.0.18: found so that the version check below can
   ;; say "too old" rather than "not found".
   :linux ["libsodium.so.26" "libsodium.so.23" "libsodium.so"]})

(defn- os []
  (let [s (str #?(:clj (System/getProperty "os.name") :cljs js/process.platform))]
    (cond (re-find #"(?i)mac|darwin" s) :mac
          (re-find #"(?i)linux" s)      :linux
          :else                         (keyword (str/lower-case s)))))

(defn- configured-location
  "The explicitly configured library path and where it came from, or nil.
   An empty value counts as not set."
  []
  (let [prop #?(:clj (System/getProperty "nacljc.libsodium") :cljs nil)
        env  #?(:clj (System/getenv "NACLJC_LIBSODIUM") :cljs (.-NACLJC_LIBSODIUM js/process.env))]
    (cond (seq prop) {:path prop :source "system property nacljc.libsodium"}
          (seq env)  {:path env :source "environment variable NACLJC_LIBSODIUM"})))

(def ^:private lib
  (let [{:keys [path source]} (configured-location)
        os    (os)
        tried (if path [path] (get default-locations os))
        hint  "Install libsodium >= 1.0.19, or set NACLJC_LIBSODIUM to its path."]
    (when (empty? tried)
      (throw (ex-info (str "nacljc: no default libsodium location for OS " (name os) ". " hint)
                      {:type ::library-not-found :os os :tried []})))
    (let [l (try
              (ffi/load-library tried)
              (catch #?(:clj Exception :cljs :default) e
                (throw (ex-info (str "nacljc: cannot load libsodium from "
                                     (if source (str path " (" source ")") (str/join ", " tried))
                                     ". " hint)
                                {:type ::library-not-found :os os :tried tried :source (or source :defaults)}
                                e))))]
      ;; A path that loads but is some other library would otherwise fail
      ;; later with a bare "symbol not found".
      (when-not (ffi/find-symbol l "sodium_init")
        (throw (ex-info (str "nacljc: " (:path l) " loaded, but it is not libsodium (no sodium_init). " hint)
                        {:type ::not-libsodium :path (:path l) :source (or source :defaults)})))
      l)))

;; ---------------------------------------------------------------------------
;; Raw C bindings: private. They take pointers and trust every length.
;; ---------------------------------------------------------------------------

(ffi/defcfn ^:private -sodium-init {:library lib} "sodium_init" [] :int)
(ffi/defcfn ^:private -version-string {:library lib} "sodium_version_string" [] :string)
(ffi/defcfn ^:private -memzero {:library lib} "sodium_memzero" [:pointer :size_t] :void)
(ffi/defcfn ^:private -memcmp {:library lib} "sodium_memcmp" [:pointer :pointer :size_t] :int)
(ffi/defcfn ^:private -randombytes-buf {:library lib} "randombytes_buf" [:pointer :size_t] :void)
(ffi/defcfn ^:private -sign-seed-keypair {:library lib} "crypto_sign_seed_keypair"
  [:pointer :pointer :pointer] :int)
(ffi/defcfn ^:private -sign-detached {:library lib} "crypto_sign_detached"
  [:pointer :pointer :pointer :ulong :pointer] :int)
(ffi/defcfn ^:private -sign-verify-detached {:library lib} "crypto_sign_verify_detached"
  [:pointer :pointer :ulong :pointer] :int)
(ffi/defcfn ^:private -pk-to-curve25519 {:library lib} "crypto_sign_ed25519_pk_to_curve25519"
  [:pointer :pointer] :int)
(ffi/defcfn ^:private -sk-to-curve25519 {:library lib} "crypto_sign_ed25519_sk_to_curve25519"
  [:pointer :pointer] :int)
(ffi/defcfn ^:private -scalarmult {:library lib} "crypto_scalarmult_curve25519"
  [:pointer :pointer :pointer] :int)
(ffi/defcfn ^:private -scalarmult-base {:library lib} "crypto_scalarmult_curve25519_base"
  [:pointer :pointer] :int)
(ffi/defcfn ^:private -hash-sha256 {:library lib} "crypto_hash_sha256"
  [:pointer :pointer :ulong] :int)
(ffi/defcfn ^:private -hmacsha256-statebytes {:library lib} "crypto_auth_hmacsha256_statebytes" [] :size_t)
(ffi/defcfn ^:private -hmacsha256-init {:library lib} "crypto_auth_hmacsha256_init"
  [:pointer :pointer :size_t] :int)
(ffi/defcfn ^:private -hmacsha256-update {:library lib} "crypto_auth_hmacsha256_update"
  [:pointer :pointer :ulong] :int)
(ffi/defcfn ^:private -hmacsha256-final {:library lib} "crypto_auth_hmacsha256_final"
  [:pointer :pointer] :int)
(ffi/defcfn ^:private -aead-encrypt {:library lib} "crypto_aead_chacha20poly1305_ietf_encrypt"
  [:pointer :pointer :pointer :ulong :pointer :ulong :pointer :pointer :pointer] :int)
(ffi/defcfn ^:private -aead-decrypt {:library lib} "crypto_aead_chacha20poly1305_ietf_decrypt"
  [:pointer :pointer :pointer :pointer :ulong :pointer :ulong :pointer :pointer] :int)
(ffi/defcfn ^:private -hkdf-extract {:library lib} "crypto_kdf_hkdf_sha256_extract"
  [:pointer :pointer :size_t :pointer :size_t] :int)
(ffi/defcfn ^:private -hkdf-expand {:library lib} "crypto_kdf_hkdf_sha256_expand"
  [:pointer :size_t :pointer :size_t :pointer] :int)

(when (neg? (-sodium-init))
  (throw (ex-info "nacljc: sodium_init failed" {:type ::init-failed})))

;; ---------------------------------------------------------------------------
;; Version
;; ---------------------------------------------------------------------------

(def minimum-libsodium-version
  "Oldest libsodium release nacljc supports: 1.0.19 added HKDF
   (crypto_kdf_hkdf_sha256_*)."
  [1 0 19])

(defn- version>=?
  "Is release version string s (e.g. \"1.0.22\") at least min, a vector
   such as [1 0 19]? Numeric, not lexicographic (1.0.9 < 1.0.19). Pure;
   false for anything unparseable."
  [s min]
  (if-let [[_ a b c] (and (string? s) (re-matches #"(\d+)\.(\d+)\.(\d+).*" s))]
    (not (neg? (compare [(parse-long a) (parse-long b) (parse-long c)] min)))
    false))

(defn libsodium-version
  "The loaded libsodium's version string, e.g. \"1.0.22\"."
  []
  (-version-string))

;; Fail at load, clearly, rather than at the first HKDF call with an obscure
;; missing-symbol error. Ubuntu 24.04 / 25.10 ship 1.0.18.
(let [v (libsodium-version)]
  (when-not (version>=? v minimum-libsodium-version)
    (throw (ex-info (str "nacljc: libsodium " v " is too old: nacljc needs >= "
                         (str/join "." minimum-libsodium-version)
                         " (HKDF). Debian/Ubuntu packages are 1.0.18; install a newer"
                         " libsodium (e.g. Homebrew, or build from download.libsodium.org).")
                    {:type ::libsodium-too-old :found v :minimum minimum-libsodium-version}))))

;; ---------------------------------------------------------------------------
;; Input checks. They run before any native memory is allocated.
;; ---------------------------------------------------------------------------

(defn- byte-array? [x]
  #?(:clj  (bytes? x)
     :cljs (or (instance? js/Int8Array x) (instance? js/Uint8Array x))))

(defn- type-name
  "The name of x's type, for error messages: never x's contents, which may
   be secret."
  [x]
  (if (nil? x)
    "nil"
    #?(:clj  (.getName (class x))
       :cljs (or (some-> x .-constructor .-name) "unknown"))))

(defn- empty-bytes [] #?(:clj (byte-array 0) :cljs (js/Int8Array. 0)))

(defn- as-int8
  "The platform byte array babashka.ffi writes: byte[] as is; on nbb an
   Int8Array view (not a copy) of a Uint8Array."
  [bs]
  #?(:clj  bs
     :cljs (if (instance? js/Int8Array bs)
             bs
             (js/Int8Array. (.-buffer bs) (.-byteOffset bs) (.-length bs)))))

(defn- throw-bad-input [what expected x]
  (throw (ex-info (str "nacljc: " what " must be " expected ", got " (type-name x))
                  {:type ::bad-input :what what :expected expected :got (type-name x)})))

(defn- throw-bad-length [what expected actual]
  (throw (ex-info (str "nacljc: " what " must be " expected " bytes, got " actual)
                  {:type ::bad-length :what what :expected expected :actual actual})))

(defn- check-bytes
  "x, checked to be a byte array (of exactly n bytes, if n is given), as
   the platform byte array. Throws ::bad-input or ::bad-length."
  ([x what]
   (when-not (byte-array? x) (throw-bad-input what "a byte array" x))
   (as-int8 x))
  ([x n what]
   (let [bs (check-bytes x what)]
     (when-not (= n (alength bs)) (throw-bad-length what n (alength bs)))
     bs)))

(defn- check-optional-bytes
  "Like check-bytes, but nil means empty."
  [x what]
  (if (nil? x) (empty-bytes) (check-bytes x what)))

(defn- check-count
  "n, checked to be an integer in lo..hi. Throws ::bad-input or ::bad-length."
  [n lo hi what]
  (when-not (integer? n) (throw-bad-input what "an integer" n))
  (when-not (<= lo n hi) (throw-bad-length what (str lo ".." hi) n))
  #?(:clj (long n) :cljs n))

;; ---------------------------------------------------------------------------
;; Scratch memory: one confined arena per call, wiped before release.
;; ---------------------------------------------------------------------------

(def ^:private ^:dynamic *audit*
  "Tests bind this to an atom to record [:alloc addr n], [:wipe addr n] and
   [:close]. Addresses and sizes only, never contents."
  nil)

(defn- audit! [event]
  (when-let [a *audit*] (swap! a conj event)))

(defn- wipe-native!
  "Zero n bytes of native memory at p with sodium_memzero, which the C
   compiler may not optimise away."
  [p n]
  (-memzero p n)
  (audit! [:wipe (str (ffi/address p)) n]))

(defn- open-scratch []
  {:arena (ffi/confined-arena) :live (volatile! [])})

(defn- alloc!
  "n bytes (at least 1) of zeroed native memory in the scratch arena,
   registered to be wiped."
  [scratch n]
  (let [size (max 1 n)
        p    (ffi/alloc (:arena scratch) size)]
    (vswap! (:live scratch) conj [p size])
    (audit! [:alloc (str (ffi/address p)) size])
    p))

(defn- release!
  "Wipe every buffer in the scratch arena, then close it, even if a wipe
   throws."
  [{:keys [arena live]}]
  (try
    (doseq [[p size] @live]
      (wipe-native! p size))
    (finally
      (.close arena)
      (audit! [:close]))))

(defmacro ^:private with-scratch
  "Evaluate body with s bound to a fresh scratch arena. Every buffer in it
   is wiped and the arena released when body returns or throws. Nothing
   allocated in it may escape: copy results out with read-bytes."
  [[s] & body]
  `(let [~s (open-scratch)]
     (try ~@body (finally (release! ~s)))))

(defn- in!
  "Copy platform byte array bs (already checked) into scratch memory."
  [scratch bs]
  (let [p (alloc! scratch (alength bs))]
    (when (pos? (alength bs)) (ffi/write-array p :char bs))
    p))

(defn- read-bytes
  "Copy n bytes out of native memory into a new platform byte array."
  [p n]
  (if (zero? n) (empty-bytes) (ffi/read-array p :char n)))

(defn- check-rc
  "Throw ::call-failed unless the libsodium call returned 0."
  [rc c-fn]
  (when-not (zero? rc)
    (throw (ex-info (str "nacljc: " c-fn " failed") {:type ::call-failed :fn c-fn :rc rc}))))

(defn- seed-keypair!
  "Ed25519 public key and 64-byte secret key for seed, in scratch memory."
  [scratch seed]
  (let [pk (alloc! scratch 32) sk (alloc! scratch 64)]
    (check-rc (-sign-seed-keypair pk sk (in! scratch seed)) "crypto_sign_seed_keypair")
    [pk sk]))

;; ---------------------------------------------------------------------------
;; Public API
;; ---------------------------------------------------------------------------

(def ^:private max-count 2147483647)

(defn random-bytes
  "n bytes (n >= 0) from libsodium's CSPRNG (the OS generator natively)."
  [n]
  (let [n (check-count n 0 max-count "random-bytes n")]
    (if (zero? n)
      (empty-bytes)
      (with-scratch [s]
        (let [p (alloc! s n)]
          (-randombytes-buf p n)
          (read-bytes p n))))))

(defn memzero!
  "Overwrite byte array bs with zeros, in place. Returns nil. Use it for
   secrets you no longer need. The JVM's garbage collector may already have
   copied the array elsewhere; this clears only the array you hold."
  [bs]
  (let [bs (check-bytes bs "memzero! argument")]
    #?(:clj  (java.util.Arrays/fill ^bytes bs (byte 0))
       :cljs (.fill bs 0))
    nil))

(defn constant-time-equal?
  "Do byte arrays a and b hold the same bytes? For equal lengths the time
   taken does not depend on the contents (sodium_memcmp). Different lengths
   return false at once: lengths are not treated as secret."
  [a b]
  (let [a (check-bytes a "constant-time-equal? a")
        b (check-bytes b "constant-time-equal? b")
        n (alength a)]
    (cond
      (not= n (alength b)) false
      (zero? n)            true
      :else                (with-scratch [s]
                             (zero? (-memcmp (in! s a) (in! s b) n))))))

(defn ed25519-public-key
  "Ed25519 public key (32 bytes) for a 32-byte seed."
  [seed]
  (let [seed (check-bytes seed 32 "Ed25519 seed")]
    (with-scratch [s]
      (let [[pk _] (seed-keypair! s seed)]
        (read-bytes pk 32)))))

(defn ed25519-sign
  "Ed25519 signature (64 bytes) of msg with the key for a 32-byte seed.
   Deterministic. The full secret key is derived from the seed inside
   native memory for each signature, so it never exists on the Clojure
   heap and its public-key half cannot be mismatched."
  [seed msg]
  (let [seed (check-bytes seed 32 "Ed25519 seed")
        msg  (check-bytes msg "message")]
    (with-scratch [s]
      (let [[_ sk] (seed-keypair! s seed)
            sig    (alloc! s 64)]
        (check-rc (-sign-detached sig ffi/null (in! s msg) (alength msg) sk) "crypto_sign_detached")
        (read-bytes sig 64)))))

(defn ed25519-verify?
  "True if sig is a valid Ed25519 signature of msg under public key pk.
   pk and sig are untrusted input: anything that is not a 32-byte and a
   64-byte array gives false, never an exception. msg must be a byte array
   (::bad-input otherwise)."
  [pk msg sig]
  (let [msg (check-bytes msg "message")]
    (boolean
     (and (byte-array? pk) (= 32 (alength pk))
          (byte-array? sig) (= 64 (alength sig))
          (with-scratch [s]
            (zero? (-sign-verify-detached (in! s (as-int8 sig)) (in! s msg) (alength msg)
                                          (in! s (as-int8 pk)))))))))

(defn ed25519->x25519-public-key
  "X25519 public key for an Ed25519 public key (the birational map). Throws
   ::invalid-public-key for a point that is not on the curve or has small
   order."
  [pk]
  (let [pk (check-bytes pk 32 "Ed25519 public key")]
    (with-scratch [s]
      (let [o (alloc! s 32)]
        (when-not (zero? (-pk-to-curve25519 o (in! s pk)))
          (throw (ex-info "nacljc: not a valid Ed25519 public key"
                          {:type ::invalid-public-key :fn "crypto_sign_ed25519_pk_to_curve25519"})))
        (read-bytes o 32)))))

(defn ed25519->x25519-secret-key
  "X25519 secret key for the Ed25519 key with this 32-byte seed."
  [seed]
  (let [seed (check-bytes seed 32 "Ed25519 seed")]
    (with-scratch [s]
      (let [[_ sk] (seed-keypair! s seed)
            o      (alloc! s 32)]
        (check-rc (-sk-to-curve25519 o sk) "crypto_sign_ed25519_sk_to_curve25519")
        (read-bytes o 32)))))

(defn x25519
  "X25519 shared secret (32 bytes) of our secret key and their public key.
   Throws ::low-order-point when the result is all zeros (their key has
   small order); libsodium returns -1 for it."
  [sk pk]
  (let [sk (check-bytes sk 32 "X25519 secret key")
        pk (check-bytes pk 32 "X25519 public key")]
    (with-scratch [s]
      (let [o (alloc! s 32)]
        (when-not (zero? (-scalarmult o (in! s sk) (in! s pk)))
          (throw (ex-info "nacljc: X25519 with a low-order public key"
                          {:type ::low-order-point :fn "crypto_scalarmult_curve25519"})))
        (read-bytes o 32)))))

(defn x25519-public-key
  "X25519 public key (32 bytes) for a 32-byte secret key."
  [sk]
  (let [sk (check-bytes sk 32 "X25519 secret key")]
    (with-scratch [s]
      (let [o (alloc! s 32)]
        (check-rc (-scalarmult-base o (in! s sk)) "crypto_scalarmult_curve25519_base")
        (read-bytes o 32)))))

(defn chacha20-poly1305-encrypt
  "ChaCha20-Poly1305 (IETF, RFC 8439): 32-byte key, 12-byte nonce,
   plaintext and associated data aad (nil means none). Returns ciphertext
   || 16-byte tag. Never reuse a nonce with the same key."
  [k nonce pt aad]
  (let [k     (check-bytes k 32 "ChaCha20-Poly1305 key")
        nonce (check-bytes nonce 12 "ChaCha20-Poly1305 nonce")
        pt    (check-bytes pt "plaintext")
        aad   (check-optional-bytes aad "associated data")
        n     (+ (alength pt) 16)]
    (with-scratch [s]
      (let [c (alloc! s n)]
        (check-rc (-aead-encrypt c ffi/null (in! s pt) (alength pt) (in! s aad) (alength aad)
                                 ffi/null (in! s nonce) (in! s k))
                  "crypto_aead_chacha20poly1305_ietf_encrypt")
        (read-bytes c n)))))

(defn chacha20-poly1305-decrypt
  "Inverse of chacha20-poly1305-encrypt. Throws ::auth-failed when the
   ciphertext, nonce, key or aad do not match; ::bad-length when the
   ciphertext is shorter than the 16-byte tag."
  [k nonce ct aad]
  (let [k     (check-bytes k 32 "ChaCha20-Poly1305 key")
        nonce (check-bytes nonce 12 "ChaCha20-Poly1305 nonce")
        ct    (check-bytes ct "ciphertext")
        aad   (check-optional-bytes aad "associated data")]
    (when (< (alength ct) 16) (throw-bad-length "ciphertext" ">= 16" (alength ct)))
    (let [n (- (alength ct) 16)]
      (with-scratch [s]
        (let [m (alloc! s n)]
          (when-not (zero? (-aead-decrypt m ffi/null ffi/null (in! s ct) (alength ct)
                                          (in! s aad) (alength aad) (in! s nonce) (in! s k)))
            (throw (ex-info "nacljc: ChaCha20-Poly1305 authentication failed" {:type ::auth-failed})))
          (read-bytes m n))))))

(defn hkdf-sha-256
  "HKDF-SHA-256 (RFC 5869), extract then expand: len bytes (1..8160) from
   input keying material ikm, with salt and info (nil means empty; an empty
   salt equals the RFC's default of 32 zero bytes)."
  [ikm salt info len]
  (let [ikm  (check-bytes ikm "HKDF ikm")
        salt (check-optional-bytes salt "HKDF salt")
        info (check-optional-bytes info "HKDF info")
        len  (check-count len 1 8160 "HKDF output length")]
    (with-scratch [s]
      (let [prk (alloc! s 32)
            o   (alloc! s len)]
        (check-rc (-hkdf-extract prk (in! s salt) (alength salt) (in! s ikm) (alength ikm))
                  "crypto_kdf_hkdf_sha256_extract")
        (check-rc (-hkdf-expand o len (in! s info) (alength info) prk)
                  "crypto_kdf_hkdf_sha256_expand")
        (read-bytes o len)))))

(defn sha-256
  "SHA-256 digest (32 bytes) of data."
  [data]
  (let [data (check-bytes data "SHA-256 input")]
    (with-scratch [s]
      (let [o (alloc! s 32)]
        (check-rc (-hash-sha256 o (in! s data) (alength data)) "crypto_hash_sha256")
        (read-bytes o 32)))))

(defn hmac-sha-256
  "HMAC-SHA-256 (32 bytes) of data under key k, which may have any length."
  [k data]
  (let [k    (check-bytes k "HMAC key")
        data (check-bytes data "HMAC input")]
    (with-scratch [s]
      (let [st (alloc! s (-hmacsha256-statebytes))
            o  (alloc! s 32)]
        (check-rc (-hmacsha256-init st (in! s k) (alength k)) "crypto_auth_hmacsha256_init")
        (check-rc (-hmacsha256-update st (in! s data) (alength data)) "crypto_auth_hmacsha256_update")
        (check-rc (-hmacsha256-final st o) "crypto_auth_hmacsha256_final")
        (read-bytes o 32)))))
