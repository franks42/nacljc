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
;; 0.2.0: guarded memory (sodium_malloc: guard pages, canaries, mlock)
(ffi/defcfn ^:private -secure-malloc {:library lib} "sodium_malloc" [:size_t] :pointer)
(ffi/defcfn ^:private -secure-free {:library lib} "sodium_free" [:pointer] :void)
(ffi/defcfn ^:private -mprotect-noaccess {:library lib} "sodium_mprotect_noaccess" [:pointer] :int)
(ffi/defcfn ^:private -mprotect-readonly {:library lib} "sodium_mprotect_readonly" [:pointer] :int)
(ffi/defcfn ^:private -mprotect-readwrite {:library lib} "sodium_mprotect_readwrite" [:pointer] :int)
;; 0.2.0: AEGIS-256 (RFC 10032; libsodium >= 1.0.19)
(ffi/defcfn ^:private -aegis256-encrypt {:library lib} "crypto_aead_aegis256_encrypt"
  [:pointer :pointer :pointer :ulong :pointer :ulong :pointer :pointer :pointer] :int)
(ffi/defcfn ^:private -aegis256-decrypt {:library lib} "crypto_aead_aegis256_decrypt"
  [:pointer :pointer :pointer :pointer :ulong :pointer :ulong :pointer :pointer] :int)

;; 0.2.0: X-Wing (ML-KEM-768 + X25519) arrived in libsodium 1.0.22, later
;; than nacljc's minimum. Bound only if present; otherwise the X-Wing
;; functions throw ::unsupported-by-libsodium.
(defn- optional-cfn [c-name argtypes rettype]
  (when (ffi/find-symbol lib c-name)
    (ffi/cfn lib c-name argtypes rettype)))

(def ^:private -xwing-seed-keypair
  (optional-cfn "crypto_kem_xwing_seed_keypair" [:pointer :pointer :pointer] :int))
(def ^:private -xwing-enc
  (optional-cfn "crypto_kem_xwing_enc" [:pointer :pointer :pointer] :int))
(def ^:private -xwing-enc-deterministic
  (optional-cfn "crypto_kem_xwing_enc_deterministic" [:pointer :pointer :pointer :pointer] :int))
(def ^:private -xwing-dec
  (optional-cfn "crypto_kem_xwing_dec" [:pointer :pointer :pointer] :int))

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

;; ---------------------------------------------------------------------------
;; Secrets (0.2.0): key material held in libsodium's guarded memory
;;
;; A secret's bytes live in sodium_malloc memory: guard pages around it,
;; canaries checked on free, locked against swapping. The memory is
;; no-access (reading it crashes the process) except while a call uses it:
;; then it is read-only. Several threads may use one secret at once: a
;; counter under a lock opens the read-only window on the first use and
;; closes it after the last. The bytes are never copied to the Clojure
;; heap; C reads them in place. Only secret-export copies them out.
;; ---------------------------------------------------------------------------

(def ^:private max-secret-bytes 65536)

(deftype Secret [ptr n lock state]
  Object
  (toString [_] (str "#nacljc/secret{:bytes " n "}")))

(alter-meta! #'->Secret assoc :private true)

#?(:clj  (defmethod print-method Secret [s ^java.io.Writer w] (.write w (str s)))
   :cljs (extend-type Secret
           IPrintWithWriter
           (-pr-writer [s w _] (-write w (str s)))))

(defn secret?
  "Is x a nacljc secret (see secret-random, secret-import!)? Pure."
  [x]
  (instance? Secret x))

(defmacro ^:private with-lock
  "Serialise body on lock l (the JVM and bb; nbb is single-threaded)."
  [l & body]
  #?(:clj `(locking ~l ~@body) :cljs `(do ~l ~@body)))

(defn- protect!
  "Set secret memory p to :noaccess, :readonly or :readwrite."
  [p mode]
  (let [rc (case mode
             :noaccess  (-mprotect-noaccess p)
             :readonly  (-mprotect-readonly p)
             :readwrite (-mprotect-readwrite p))]
    (audit! [:protect (str (ffi/address p)) mode])
    (check-rc rc (str "sodium_mprotect_" (name mode)))))

(defn- open-secret!
  "Open (or join) secret s's read-only window; returns its pointer. Every
   open-secret! must be paired with a close-secret!. Throws
   ::destroyed-secret for a destroyed secret."
  [s]
  (with-lock (.-lock s)
    (let [{:keys [uses destroyed]} @(.-state s)]
      (when destroyed
        (throw (ex-info "nacljc: the secret was destroyed" {:type ::destroyed-secret})))
      (when (zero? uses) (protect! (.-ptr s) :readonly))
      (swap! (.-state s) update :uses inc)
      (.-ptr s))))

(defn- close-secret!
  "Leave secret s's read-only window; the last one out makes it no-access."
  [s]
  (with-lock (.-lock s)
    (when (zero? (:uses (swap! (.-state s) update :uses dec)))
      (protect! (.-ptr s) :noaccess))))

#_{:clj-kondo/ignore [:unused-private-var]}
(defn- secret-uses [s] (:uses @(.-state s)))

(defn- open-secrets!
  "Open the window of every secret among xs; returns the opened ones. If one
   fails (destroyed), those already opened are closed again first."
  [xs]
  (reduce (fn [opened x]
            (try (open-secret! x) (conj opened x)
                 (catch #?(:clj Throwable :cljs :default) e
                   (run! close-secret! opened)
                   (throw e))))
          [] (filter secret? xs)))

(defmacro ^:private with-open-secrets
  "Evaluate body with every secret among xs readable; close them after,
   also when body throws."
  [xs & body]
  `(let [opened# (open-secrets! ~xs)]
     (try ~@body (finally (run! close-secret! opened#)))))

(defn- new-secret!
  "A new secret of n bytes. fill! writes them through the pointer it is
   given, while the memory is still read-write; the secret is no-access
   when returned. If fill! throws, the memory is freed."
  [n fill!]
  (let [raw (-secure-malloc n)]
    (when (ffi/null? raw)
      (throw (ex-info "nacljc: sodium_malloc failed" {:type ::call-failed :fn "sodium_malloc"})))
    (let [p (ffi/reinterpret raw n)]
      (audit! [:secret-alloc (str (ffi/address p)) n])
      (try
        (fill! p)
        (protect! p :noaccess)
        (Secret. p n #?(:clj (Object.) :cljs nil) (atom {:uses 0 :destroyed false}))
        (catch #?(:clj Throwable :cljs :default) e
          (-secure-free p)
          (audit! [:free (str (ffi/address p))])
          (throw e))))))

(defn- check-key
  "x as key material: a platform byte array or a secret, of exactly n bytes
   when n is given. Throws ::bad-input or ::bad-length."
  ([x what]
   (if (secret? x) x (check-bytes x what)))
  ([x n what]
   (if (secret? x)
     (do (when-not (= n (.-n x)) (throw-bad-length what n (.-n x))) x)
     (check-bytes x n what))))

(defn- key-length [k] (if (secret? k) (.-n k) (alength k)))

(defn- key-in!
  "A pointer C can read key k through: a secret's own memory (its window
   must be open, see with-open-secrets), or a scratch copy of a byte array."
  [scratch k]
  (if (secret? k) (.-ptr k) (in! scratch k)))

(defn- output!
  "n bytes that C writes through (write! pointer). When as-secret?, they go
   straight into a new secret and never touch the Clojure heap; otherwise
   into scratch memory, returned as a byte array."
  [scratch as-secret? n write!]
  (if as-secret?
    (new-secret! n write!)
    (let [o (alloc! scratch n)]
      (write! o)
      (read-bytes o n))))

(defn- seed-keypair!
  "Ed25519 public key and 64-byte secret key for seed (a byte array, or a
   secret whose window is open), in scratch memory."
  [scratch seed]
  (let [pk (alloc! scratch 32) sk (alloc! scratch 64)]
    (check-rc (-sign-seed-keypair pk sk (key-in! scratch seed)) "crypto_sign_seed_keypair")
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
  "Ed25519 public key (32 bytes) for a 32-byte seed (a byte array or a
   secret)."
  [seed]
  (let [seed (check-key seed 32 "Ed25519 seed")]
    (with-open-secrets [seed]
      (with-scratch [s]
        (let [[pk _] (seed-keypair! s seed)]
          (read-bytes pk 32))))))

(defn ed25519-sign
  "Ed25519 signature (64 bytes) of msg with the key for a 32-byte seed.
   Deterministic. The full secret key is derived from the seed inside
   native memory for each signature, so it never exists on the Clojure
   heap and its public-key half cannot be mismatched."
  [seed msg]
  (let [seed (check-key seed 32 "Ed25519 seed")
        msg  (check-bytes msg "message")]
    (with-open-secrets [seed]
      (with-scratch [s]
        (let [[_ sk] (seed-keypair! s seed)
              sig    (alloc! s 64)]
          (check-rc (-sign-detached sig ffi/null (in! s msg) (alength msg) sk) "crypto_sign_detached")
          (read-bytes sig 64))))))

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
  "X25519 secret key for the Ed25519 key with this 32-byte seed. A secret
   seed gives a secret result; a byte-array seed gives a byte array."
  [seed]
  (let [seed (check-key seed 32 "Ed25519 seed")]
    (with-open-secrets [seed]
      (with-scratch [s]
        (let [[_ sk] (seed-keypair! s seed)]
          (output! s (secret? seed) 32
                   #(check-rc (-sk-to-curve25519 % sk) "crypto_sign_ed25519_sk_to_curve25519")))))))

(defn x25519
  "X25519 shared secret (32 bytes) of our secret key and their public key.
   A secret sk gives a secret result; a byte-array sk gives a byte array.
   Throws ::low-order-point when the result is all zeros (their key has
   small order); libsodium returns -1 for it."
  [sk pk]
  (let [sk (check-key sk 32 "X25519 secret key")
        pk (check-bytes pk 32 "X25519 public key")]
    (with-open-secrets [sk]
      (with-scratch [s]
        (output! s (secret? sk) 32
                 #(when-not (zero? (-scalarmult % (key-in! s sk) (in! s pk)))
                    (throw (ex-info "nacljc: X25519 with a low-order public key"
                                    {:type ::low-order-point :fn "crypto_scalarmult_curve25519"}))))))))

(defn x25519-public-key
  "X25519 public key (32 bytes) for a 32-byte secret key (a byte array or a
   secret)."
  [sk]
  (let [sk (check-key sk 32 "X25519 secret key")]
    (with-open-secrets [sk]
      (with-scratch [s]
        (let [o (alloc! s 32)]
          (check-rc (-scalarmult-base o (key-in! s sk)) "crypto_scalarmult_curve25519_base")
          (read-bytes o 32))))))

(defn chacha20-poly1305-encrypt
  "ChaCha20-Poly1305 (IETF, RFC 8439): 32-byte key, 12-byte nonce,
   plaintext and associated data aad (nil means none). Returns ciphertext
   || 16-byte tag. Never reuse a nonce with the same key."
  [k nonce pt aad]
  (let [k     (check-key k 32 "ChaCha20-Poly1305 key")
        nonce (check-bytes nonce 12 "ChaCha20-Poly1305 nonce")
        pt    (check-bytes pt "plaintext")
        aad   (check-optional-bytes aad "associated data")
        n     (+ (alength pt) 16)]
    (with-open-secrets [k]
      (with-scratch [s]
        (let [c (alloc! s n)]
          (check-rc (-aead-encrypt c ffi/null (in! s pt) (alength pt) (in! s aad) (alength aad)
                                   ffi/null (in! s nonce) (key-in! s k))
                    "crypto_aead_chacha20poly1305_ietf_encrypt")
          (read-bytes c n))))))

(defn chacha20-poly1305-decrypt
  "Inverse of chacha20-poly1305-encrypt. Throws ::auth-failed when the
   ciphertext, nonce, key or aad do not match; ::bad-length when the
   ciphertext is shorter than the 16-byte tag."
  [k nonce ct aad]
  (let [k     (check-key k 32 "ChaCha20-Poly1305 key")
        nonce (check-bytes nonce 12 "ChaCha20-Poly1305 nonce")
        ct    (check-bytes ct "ciphertext")
        aad   (check-optional-bytes aad "associated data")]
    (when (< (alength ct) 16) (throw-bad-length "ciphertext" ">= 16" (alength ct)))
    (let [n (- (alength ct) 16)]
      (with-open-secrets [k]
        (with-scratch [s]
          (let [m (alloc! s n)]
            (when-not (zero? (-aead-decrypt m ffi/null ffi/null (in! s ct) (alength ct)
                                            (in! s aad) (alength aad) (in! s nonce) (key-in! s k)))
              (throw (ex-info "nacljc: ChaCha20-Poly1305 authentication failed" {:type ::auth-failed})))
            (read-bytes m n)))))))

(defn hkdf-sha-256
  "HKDF-SHA-256 (RFC 5869), extract then expand: len bytes (1..8160) from
   input keying material ikm, with salt and info (nil means empty; an empty
   salt equals the RFC's default of 32 zero bytes). A secret ikm gives a
   secret result; a byte-array ikm gives a byte array."
  [ikm salt info len]
  (let [ikm  (check-key ikm "HKDF ikm")
        salt (check-optional-bytes salt "HKDF salt")
        info (check-optional-bytes info "HKDF info")
        len  (check-count len 1 8160 "HKDF output length")]
    (with-open-secrets [ikm]
      (with-scratch [s]
        (let [prk (alloc! s 32)]
          (check-rc (-hkdf-extract prk (in! s salt) (alength salt) (key-in! s ikm) (key-length ikm))
                    "crypto_kdf_hkdf_sha256_extract")
          (output! s (secret? ikm) len
                   #(check-rc (-hkdf-expand % len (in! s info) (alength info) prk)
                              "crypto_kdf_hkdf_sha256_expand")))))))

(defn sha-256
  "SHA-256 digest (32 bytes) of data."
  [data]
  (let [data (check-bytes data "SHA-256 input")]
    (with-scratch [s]
      (let [o (alloc! s 32)]
        (check-rc (-hash-sha256 o (in! s data) (alength data)) "crypto_hash_sha256")
        (read-bytes o 32)))))

(defn hmac-sha-256
  "HMAC-SHA-256 (32 bytes) of data under key k (a byte array or a secret, of
   any length). The tag is a byte array: it is meant to be sent."
  [k data]
  (let [k    (check-key k "HMAC key")
        data (check-bytes data "HMAC input")]
    (with-open-secrets [k]
      (with-scratch [s]
        (let [st (alloc! s (-hmacsha256-statebytes))
              o  (alloc! s 32)]
          (check-rc (-hmacsha256-init st (key-in! s k) (key-length k)) "crypto_auth_hmacsha256_init")
          (check-rc (-hmacsha256-update st (in! s data) (alength data)) "crypto_auth_hmacsha256_update")
          (check-rc (-hmacsha256-final st o) "crypto_auth_hmacsha256_final")
          (read-bytes o 32))))))

;; ---------------------------------------------------------------------------
;; Secrets: public API (0.2.0)
;; ---------------------------------------------------------------------------

(defn secret-random
  "A new secret of n random bytes (1..65536), drawn from libsodium's CSPRNG
   straight into guarded memory: the bytes never exist on the Clojure heap.
   Impure: draws from the CSPRNG and allocates guarded memory, which must be
   released with secret-destroy! (or use with-secret).
   Throws ::bad-input for a non-integer n, ::bad-length outside 1..65536."
  [n]
  (let [n (check-count n 1 max-secret-bytes "secret-random n")]
    (new-secret! n #(-randombytes-buf % n))))

(defn secret-import!
  "A new secret holding a copy of byte array bs (1..65536 bytes). bs itself
   is then overwritten with zeros, so the secret is the only copy nacljc
   knows of (the JVM's garbage collector may have copied bs earlier).
   Impure: writes bs, allocates guarded memory (see secret-destroy!).
   Throws ::bad-input or ::bad-length."
  [bs]
  (let [bs' (check-bytes bs "secret-import! argument")
        n   (alength bs')]
    (when-not (<= 1 n max-secret-bytes) (throw-bad-length "secret-import! argument" "1..65536" n))
    (let [s (new-secret! n #(ffi/write-array % :char bs'))]
      (memzero! bs)
      s)))

(def ^:private export-acknowledgement {:i-understand :exposes-secret})

(defn secret-export
  "The secret's bytes, as a new byte array on the Clojure heap. This is the
   only way bytes leave a secret, so it requires the acknowledgement map
   {:i-understand :exposes-secret}: without it, it throws
   ::export-not-acknowledged. Wipe the result with memzero! when done.
   Impure: reads the secret. Throws ::destroyed-secret for a destroyed one."
  [s ack]
  (when-not (secret? s) (throw-bad-input "secret-export argument" "a secret" s))
  (when-not (= export-acknowledgement ack)
    (throw (ex-info "nacljc: secret-export needs {:i-understand :exposes-secret}"
                    {:type ::export-not-acknowledged})))
  (with-open-secrets [s]
    (read-bytes (.-ptr s) (.-n s))))

(defn secret-destroy!
  "Zero and free the secret's guarded memory (sodium_free, which also checks
   its canaries). Later use throws ::destroyed-secret. Destroying again is a
   no-op. Impure: frees memory. Throws ::secret-in-use while a call on
   another thread is using it."
  [s]
  (when-not (secret? s) (throw-bad-input "secret-destroy! argument" "a secret" s))
  (with-lock (.-lock s)
    (let [{:keys [uses destroyed]} @(.-state s)]
      (cond
        destroyed   nil
        (pos? uses) (throw (ex-info "nacljc: the secret is in use" {:type ::secret-in-use :uses uses}))
        :else       (do (swap! (.-state s) assoc :destroyed true)
                        (-secure-free (.-ptr s))
                        (audit! [:free (str (ffi/address (.-ptr s)))])
                        nil)))))

(defn secret-length
  "The secret's size in bytes. Pure."
  [s]
  (when-not (secret? s) (throw-bad-input "secret-length argument" "a secret" s))
  (.-n s))

(defn secret-destroyed?
  "Has secret-destroy! been called on s? Impure: reads its state."
  [s]
  (when-not (secret? s) (throw-bad-input "secret-destroyed? argument" "a secret" s))
  (boolean (:destroyed @(.-state s))))

(defmacro with-secret
  "(with-secret [s (secret-random 32)] body…): evaluate body with s bound,
   then secret-destroy! it, also when body throws."
  [[sym init] & body]
  `(let [~sym ~init]
     (try ~@body (finally (secret-destroy! ~sym)))))

;; ---------------------------------------------------------------------------
;; AEGIS-256 (0.2.0; RFC 10032, 256-bit tags)
;; ---------------------------------------------------------------------------

(defn aegis256-encrypt
  "AEGIS-256 (RFC 10032): 32-byte key (a byte array or a secret), 32-byte
   nonce, plaintext and associated data aad (nil means none). Returns
   ciphertext || 32-byte tag. A 256-bit nonce may be random with no
   practical limit, but never reuse one with the same key.
   Throws ::bad-input or ::bad-length."
  [k nonce pt aad]
  (let [k     (check-key k 32 "AEGIS-256 key")
        nonce (check-bytes nonce 32 "AEGIS-256 nonce")
        pt    (check-bytes pt "plaintext")
        aad   (check-optional-bytes aad "associated data")
        n     (+ (alength pt) 32)]
    (with-open-secrets [k]
      (with-scratch [s]
        (let [c (alloc! s n)]
          (check-rc (-aegis256-encrypt c ffi/null (in! s pt) (alength pt) (in! s aad) (alength aad)
                                       ffi/null (in! s nonce) (key-in! s k))
                    "crypto_aead_aegis256_encrypt")
          (read-bytes c n))))))

(defn aegis256-decrypt
  "Inverse of aegis256-encrypt. Throws ::auth-failed when the ciphertext,
   nonce, key or aad do not match; ::bad-length when the ciphertext is
   shorter than the 32-byte tag."
  [k nonce ct aad]
  (let [k     (check-key k 32 "AEGIS-256 key")
        nonce (check-bytes nonce 32 "AEGIS-256 nonce")
        ct    (check-bytes ct "ciphertext")
        aad   (check-optional-bytes aad "associated data")]
    (when (< (alength ct) 32) (throw-bad-length "ciphertext" ">= 32" (alength ct)))
    (let [n (- (alength ct) 32)]
      (with-open-secrets [k]
        (with-scratch [s]
          (let [m (alloc! s n)]
            (when-not (zero? (-aegis256-decrypt m ffi/null ffi/null (in! s ct) (alength ct)
                                                (in! s aad) (alength aad) (in! s nonce) (key-in! s k)))
              (throw (ex-info "nacljc: AEGIS-256 authentication failed" {:type ::auth-failed})))
            (read-bytes m n)))))))

;; ---------------------------------------------------------------------------
;; X-Wing KEM (0.2.0; ML-KEM-768 + X25519; libsodium >= 1.0.22)
;; ---------------------------------------------------------------------------

(defn- need-xwing! [f c-name]
  (when-not f
    (throw (ex-info (str "nacljc: X-Wing needs libsodium >= 1.0.22 (" c-name " not found); loaded "
                         (libsodium-version))
                    {:type ::unsupported-by-libsodium :fn c-name :found (libsodium-version)}))))

(defn xwing-public-key
  "X-Wing public key (1216 bytes) for a 32-byte seed (a byte array or a
   secret). The seed is the X-Wing secret key. Throws ::bad-input,
   ::bad-length or ::unsupported-by-libsodium."
  [seed]
  (need-xwing! -xwing-seed-keypair "crypto_kem_xwing_seed_keypair")
  (let [seed (check-key seed 32 "X-Wing seed")]
    (with-open-secrets [seed]
      (with-scratch [s]
        (let [pk (alloc! s 1216) sk (alloc! s 32)]
          (check-rc (-xwing-seed-keypair pk sk (key-in! s seed)) "crypto_kem_xwing_seed_keypair")
          (read-bytes pk 1216))))))

(defn- encapsulate [pk enc!]
  (let [pk (check-bytes pk 1216 "X-Wing public key")]
    (with-scratch [s]
      (let [ct (alloc! s 1120)
            ss (new-secret! 32 #(enc! ct % (in! s pk)))]
        {:ciphertext (read-bytes ct 1120) :shared-secret ss}))))

(defn xwing-encapsulate
  "Encapsulate a fresh shared secret to X-Wing public key pk (1216 bytes).
   Returns {:ciphertext <1120 bytes> :shared-secret <secret>}: the shared
   secret is always a secret object. Impure: draws from the CSPRNG and
   allocates guarded memory. Throws ::bad-input, ::bad-length or
   ::unsupported-by-libsodium."
  [pk]
  (need-xwing! -xwing-enc "crypto_kem_xwing_enc")
  (encapsulate pk (fn [ct ss pkp] (check-rc (-xwing-enc ct ss pkp) "crypto_kem_xwing_enc"))))

#_{:clj-kondo/ignore [:unused-private-var]}
(defn- xwing-encapsulate-deterministic
  "xwing-encapsulate with caller-chosen 64-byte randomness, for known-answer
   tests only. Private on purpose: reusing randomness breaks the KEM."
  [pk randomness]
  (need-xwing! -xwing-enc-deterministic "crypto_kem_xwing_enc_deterministic")
  (let [r (check-bytes randomness 64 "X-Wing randomness")]
    (with-scratch [s]
      (let [rp (in! s r)]
        (encapsulate pk (fn [ct ss pkp]
                          (check-rc (-xwing-enc-deterministic ct ss pkp rp)
                                    "crypto_kem_xwing_enc_deterministic")))))))

(defn xwing-decapsulate
  "The shared secret for X-Wing ciphertext ct (1120 bytes) under the 32-byte
   seed (a byte array or a secret). Always returns a secret object. A
   ciphertext that was not made for this key gives an unrelated secret
   (ML-KEM's implicit rejection), not an error: authenticate what the key
   protects. Throws ::bad-input, ::bad-length or ::unsupported-by-libsodium."
  [seed ct]
  (need-xwing! -xwing-dec "crypto_kem_xwing_dec")
  (let [seed (check-key seed 32 "X-Wing seed")
        ct   (check-bytes ct 1120 "X-Wing ciphertext")]
    (with-open-secrets [seed]
      (with-scratch [s]
        (new-secret! 32 #(check-rc (-xwing-dec % (in! s ct) (key-in! s seed)) "crypto_kem_xwing_dec"))))))

