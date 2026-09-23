(ns nacljc.core-test
  "Tests for nacljc.core on JVM Clojure, bb and nbb.

   Known answers: test/nacljc/vectors.edn holds RFC vectors and
   cross-platform vectors (fixed inputs where native libsodium, signet's JCA
   backend and libsodium.js agree).

   Hygiene: every input is type- and length-checked before C sees it, every
   native buffer is wiped before it is released (on success and on error),
   results never alias inputs or native memory, and the public API is
   exactly the documented one. Run from the repo root."
  (:require [clojure.test :refer [deftest is testing]]
            [babashka.ffi :as ffi]
            [nacljc.core :as na]
            #?(:clj  [clojure.edn :as edn]
               :cljs [cljs.reader :as edn])
            #?(:cljs ["fs" :as fs])))

(def vectors
  (edn/read-string #?(:clj  (slurp "test/nacljc/vectors.edn")
                      :cljs (str (fs/readFileSync "test/nacljc/vectors.edn")))))

;; ---- portable byte helpers: byte[] on the JVM/bb, Int8Array on nbb ----

(defn- bytes-from [xs]
  #?(:clj  (byte-array (map unchecked-byte xs))
     :cljs (js/Int8Array.from (clj->js xs))))

(defn- b
  "n bytes, all equal to x (default 1)."
  ([n] (b n 1))
  ([n x] (bytes-from (repeat n x))))

(defn- unhex [s]
  (bytes-from (map #(#?(:clj Integer/parseInt :cljs js/parseInt) (subs s % (+ % 2)) 16)
                   (range 0 (count s) 2))))

(defn- byte-seq [bs] #?(:clj (seq bs) :cljs (array-seq bs)))

(defn- hex [bs]
  (apply str (map #(let [h #?(:clj  (Integer/toHexString (bit-and % 0xff))
                              :cljs (.toString (bit-and % 0xff) 16))]
                     (if (= 1 (count h)) (str "0" h) h))
                  (byte-seq bs))))

(defn- utf8 [s]
  #?(:clj  (.getBytes ^String s "UTF-8")
     :cljs (js/Int8Array.from (.from js/Buffer s "utf8"))))

(defn- error-type
  "The ::type of the ex-info f throws, :no-throw, or [:not-ex-info msg]."
  [f]
  (try (f) :no-throw
       (catch #?(:clj Throwable :cljs :default) e
         (if-let [d (ex-data e)]
           (:type d)
           [:not-ex-info (ex-message e)]))))

(defn- allocations
  "How many native buffers f allocated (whether or not it threw). Rejected
   input must allocate none: a missing guard whose C call happens to
   return the right answer is still an over-read, and only this shows it."
  [f]
  (let [log (atom [])]
    (binding [na/*audit* log]
      (try (f) (catch #?(:clj Throwable :cljs :default) _ nil)))
    (count (filter #(= :alloc (first %)) @log))))

(defn- rejected
  "[error type, native allocations] for calling f."
  [f]
  [(error-type f) (allocations f)])

;; ---- the public API is exactly this; nothing raw leaks ----

(def api
  '#{libsodium-version minimum-libsodium-version
     random-bytes memzero! constant-time-equal?
     ed25519-public-key ed25519-sign ed25519-verify?
     ed25519->x25519-public-key ed25519->x25519-secret-key
     x25519 x25519-public-key
     chacha20-poly1305-encrypt chacha20-poly1305-decrypt
     sha-256 hmac-sha-256 hkdf-sha-256})

(deftest public-api-is-exactly-the-documented-one
  (is (= api (set (keys (ns-publics 'nacljc.core))))
      "no raw C binding, arena helper or internal var is public"))

;; ---- RFC vectors ----

(deftest rfc8032-ed25519
  (let [{:keys [seed pk msg sig]} (get-in vectors [:rfc :ed25519])]
    (is (= pk (hex (na/ed25519-public-key (unhex seed)))) "seed -> public key")
    (is (= sig (hex (na/ed25519-sign (unhex seed) (utf8 msg)))) "deterministic signature from the seed")
    (is (true? (na/ed25519-verify? (unhex pk) (utf8 msg) (unhex sig))))
    (is (false? (na/ed25519-verify? (unhex pk) (utf8 "x") (unhex sig))) "rejects another message")))

(deftest rfc7748-x25519
  (let [{:keys [scalar u out]} (get-in vectors [:rfc :x25519])]
    (is (= out (hex (na/x25519 (unhex scalar) (unhex u)))))))

(deftest rfc7748-x25519-public-key
  (let [{:keys [sk pk]} (get-in vectors [:rfc :x25519-base])]
    (is (= pk (hex (na/x25519-public-key (unhex sk)))))))

(deftest rfc8439-chacha20-poly1305
  (let [{:keys [key nonce ad pt ct]} (get-in vectors [:rfc :aead])]
    (is (= ct (hex (na/chacha20-poly1305-encrypt (unhex key) (unhex nonce) (utf8 pt) (unhex ad)))))
    (is (= (hex (utf8 pt)) (hex (na/chacha20-poly1305-decrypt (unhex key) (unhex nonce) (unhex ct) (unhex ad)))))))

(deftest rfc5869-hkdf-sha-256
  (let [{:keys [ikm salt info len okm]} (get-in vectors [:rfc :hkdf])]
    (is (= okm (hex (na/hkdf-sha-256 (unhex ikm) (unhex salt) (unhex info) len))))))

(deftest fips180-sha-256
  (let [{:keys [msg digest]} (get-in vectors [:rfc :sha256])]
    (is (= digest (hex (na/sha-256 (utf8 msg)))))))

(deftest rfc4231-hmac-sha-256
  (doseq [{:keys [source key data mac]} (get-in vectors [:rfc :hmac-sha256])]
    (is (= mac (hex (na/hmac-sha-256 (unhex key) (utf8 data)))) source)))

;; ---- cross-platform vectors ----

(deftest xplatform
  (let [v    (:xplatform vectors)
        seed (unhex (:seed v))
        pk   (na/ed25519-public-key seed)]
    (is (= (:pk v) (hex pk)))
    (is (= (:sig v) (hex (na/ed25519-sign seed (utf8 (:msg v))))))
    (is (= (:x-pk v) (hex (na/ed25519->x25519-public-key pk))) "Ed25519 -> X25519 public key")
    (is (= (:x-sk v) (hex (na/ed25519->x25519-secret-key seed))) "Ed25519 seed -> X25519 secret key")
    (is (= (:dh v) (hex (na/x25519 (unhex (:x-sk v)) (unhex (:peer-x-pk v))))))
    (is (= (:ct v) (hex (na/chacha20-poly1305-encrypt (unhex (:key v)) (unhex (:nonce v))
                                                      (utf8 (:pt v)) (utf8 (:ad v))))))
    (is (= (:hkdf v) (hex (na/hkdf-sha-256 (unhex (:key v)) (b 0) (utf8 "signet/box/v1") 32))))))

;; ---- typed errors: wrong types never reach C ----

(def ^:private not-bytes
  "Values that must never be mistaken for a byte array."
  (concat [nil "abc" [1 2 3] 42 :k]
          #?(:clj  [(int-array 32) (object-array 32)]
             :cljs [#js [1 2 3] (js/Int16Array. 32) (js/Float64Array. 32) (js/Uint8ClampedArray. 32)])))

(deftest wrong-types-are-bad-input
  (let [s32 (b 32) s12 (b 12) msg (utf8 "m")
        ct  (na/chacha20-poly1305-encrypt s32 s12 msg nil)
        cases
        {"ed25519-public-key seed"    #(na/ed25519-public-key %)
         "ed25519-sign seed"          #(na/ed25519-sign % msg)
         "ed25519-sign msg"           #(na/ed25519-sign s32 %)
         "ed25519-verify? msg"        #(na/ed25519-verify? s32 % (b 64))
         "->x25519-public-key"        #(na/ed25519->x25519-public-key %)
         "->x25519-secret-key"        #(na/ed25519->x25519-secret-key %)
         "x25519 sk"                  #(na/x25519 % s32)
         "x25519 pk"                  #(na/x25519 s32 %)
         "x25519-public-key"          #(na/x25519-public-key %)
         "encrypt key"                #(na/chacha20-poly1305-encrypt % s12 msg nil)
         "encrypt nonce"              #(na/chacha20-poly1305-encrypt s32 % msg nil)
         "encrypt plaintext"          #(na/chacha20-poly1305-encrypt s32 s12 % nil)
         "decrypt key"                #(na/chacha20-poly1305-decrypt % s12 ct nil)
         "decrypt nonce"              #(na/chacha20-poly1305-decrypt s32 % ct nil)
         "decrypt ciphertext"         #(na/chacha20-poly1305-decrypt s32 s12 % nil)
         "hkdf ikm"                   #(na/hkdf-sha-256 % (b 0) (b 0) 32)
         "sha-256"                    #(na/sha-256 %)
         "hmac key"                   #(na/hmac-sha-256 % msg)
         "hmac data"                  #(na/hmac-sha-256 s32 %)
         "memzero!"                   #(na/memzero! %)
         "constant-time-equal? a"     #(na/constant-time-equal? % s32)
         "constant-time-equal? b"     #(na/constant-time-equal? s32 %)}]
    (doseq [[label f] cases, x not-bytes]
      (is (= [:nacljc.core/bad-input 0] (rejected #(f x)))
          (str label " with " (pr-str x))))
    (testing "optional inputs (AEAD aad, HKDF salt and info) accept nil but no other non-byte value"
      (doseq [[label f] {"encrypt aad" #(na/chacha20-poly1305-encrypt s32 s12 msg %)
                         "decrypt aad" #(na/chacha20-poly1305-decrypt s32 s12 ct %)
                         "hkdf salt"   #(na/hkdf-sha-256 s32 % (b 0) 32)
                         "hkdf info"   #(na/hkdf-sha-256 s32 (b 0) % 32)}
              x (remove nil? not-bytes)]
        (is (= [:nacljc.core/bad-input 0] (rejected #(f x))) (str label " with " (pr-str x))))
      (is (= (hex (na/chacha20-poly1305-encrypt s32 s12 msg nil))
             (hex (na/chacha20-poly1305-encrypt s32 s12 msg (b 0)))) "nil aad = empty aad")
      (is (= (hex (na/hkdf-sha-256 s32 nil nil 32))
             (hex (na/hkdf-sha-256 s32 (b 0) (b 0) 32))) "nil salt and info = empty"))
    (testing "counts must be integers"
      (doseq [x [nil 1.5 "32" :k]]
        (is (= [:nacljc.core/bad-input 0] (rejected #(na/random-bytes x))) (pr-str x))
        (is (= [:nacljc.core/bad-input 0] (rejected #(na/hkdf-sha-256 s32 nil nil x))) (pr-str x))))))

(deftest verify-never-throws-on-untrusted-input
  (let [seed (b 32) pk (na/ed25519-public-key seed) msg (utf8 "m")
        sig  (na/ed25519-sign seed msg)]
    (is (true? (na/ed25519-verify? pk msg sig)))
    (doseq [x (concat not-bytes [(b 31) (b 33) (b 63) (b 65) (b 0)])]
      (is (false? (na/ed25519-verify? x msg sig)) (str "public key " (pr-str x)))
      (is (zero? (allocations #(na/ed25519-verify? x msg sig))) (str "public key never reaches C: " (pr-str x)))
      (is (false? (na/ed25519-verify? pk msg x)) (str "signature " (pr-str x)))
      (is (zero? (allocations #(na/ed25519-verify? pk msg x))) (str "signature never reaches C: " (pr-str x))))
    (is (false? (na/ed25519-verify? (b 32 0) msg sig)) "all-zero (small-order) public key")))

;; ---- sizes: fixed-size inputs and counts are checked before C ----

(deftest wrong-sizes-are-bad-length
  (let [msg (utf8 "m")
        bad-length? #(= [:nacljc.core/bad-length 0] (rejected %))]
    (is (bad-length? #(na/ed25519-public-key (b 31))))
    (is (bad-length? #(na/ed25519-sign (b 64) msg)) "a 64-byte libsodium secret key is not a seed")
    (is (bad-length? #(na/ed25519-sign (b 31) msg)))
    (is (bad-length? #(na/ed25519->x25519-public-key (b 31))))
    (is (bad-length? #(na/ed25519->x25519-secret-key (b 64))))
    (is (bad-length? #(na/x25519 (b 32) (b 31))))
    (is (bad-length? #(na/x25519 (b 33) (b 32))))
    (is (bad-length? #(na/x25519-public-key (b 16))))
    (is (bad-length? #(na/chacha20-poly1305-encrypt (b 31) (b 12) msg nil)))
    (is (bad-length? #(na/chacha20-poly1305-encrypt (b 32) (b 24) msg nil)) "XChaCha-size nonce")
    (is (bad-length? #(na/chacha20-poly1305-decrypt (b 32) (b 12) (b 15) nil)) "shorter than the tag")
    (is (bad-length? #(na/chacha20-poly1305-decrypt (b 32) (b 11) (b 16) nil)))
    (testing "HKDF output length: 1..8160 (255 x 32)"
      (is (bad-length? #(na/hkdf-sha-256 (b 32) nil nil 0)))
      (is (bad-length? #(na/hkdf-sha-256 (b 32) nil nil -1)))
      (is (bad-length? #(na/hkdf-sha-256 (b 32) nil nil 8161)))
      (is (= 8160 (alength (na/hkdf-sha-256 (b 32) nil nil 8160))))
      (is (= 1 (alength (na/hkdf-sha-256 (b 32) nil nil 1)))))
    (testing "random-bytes: n >= 0"
      (is (bad-length? #(na/random-bytes -1)))
      (is (= 0 (alength (na/random-bytes 0)))))))

;; ---- failures that come from C are typed too ----

(deftest c-failures-are-typed
  (let [k (b 32) n (b 12) msg (utf8 "m")
        ct (na/chacha20-poly1305-encrypt k n msg (utf8 "ad"))]
    (is (= :nacljc.core/auth-failed
           (error-type #(na/chacha20-poly1305-decrypt k n ct (utf8 "other ad")))))
    (is (= :nacljc.core/auth-failed
           (error-type #(na/chacha20-poly1305-decrypt (b 32 2) n ct (utf8 "ad")))) "wrong key")
    (is (= :nacljc.core/low-order-point
           (error-type #(na/x25519 (na/random-bytes 32) (b 32 0))))
        "all-zero public key gives an all-zero secret; libsodium returns -1")
    (is (= :nacljc.core/invalid-public-key
           (error-type #(na/ed25519->x25519-public-key (b 32 0))))
        "a small-order Ed25519 point has no safe X25519 counterpart")))

;; ---- native memory hygiene ----

(defn- audited
  "Run f with the arena audit on. Returns [result-or-error-type events]."
  [f]
  (let [log (atom [])]
    (binding [na/*audit* log]
      [(error-type f) @log])))

(defn- arena-hygienic?
  "One arena's events: every allocation was wiped with its full size, no
   allocation came after the first wipe, and the arena was closed last."
  [events]
  (let [allocs (filter #(= :alloc (first %)) events)
        wiped  (set (map rest (filter #(= :wipe (first %)) events)))]
    (boolean
     (and (seq allocs)
          (every? #(contains? wiped (rest %)) allocs)
          (= [:close] (last events))
          (not-any? #(= :alloc (first %)) (drop-while #(not= :wipe (first %)) events))))))

(defn- hygienic?
  "At least one arena was used, and every arena (a run of events ending in
   :close) was hygienic, with nothing left over after the last close."
  [events]
  (let [arenas (loop [es events acc []]
                 (if (empty? es)
                   acc
                   (let [[a more] (split-with #(not= [:close] %) es)]
                     (recur (rest more) (conj acc (concat a (take 1 more)))))))]
    (boolean (and (seq arenas) (every? arena-hygienic? arenas)))))

(deftest every-native-buffer-is-wiped
  (let [seed (b 32 7) pk (na/ed25519-public-key seed) msg (utf8 "m")
        k (b 32) n (b 12) ct (na/chacha20-poly1305-encrypt k n msg nil)]
    (testing "on success"
      (doseq [[label f] {"random-bytes"        #(na/random-bytes 32)
                         "ed25519-public-key"  #(na/ed25519-public-key seed)
                         "ed25519-sign"        #(na/ed25519-sign seed msg)
                         "ed25519-verify?"     #(na/ed25519-verify? pk msg (b 64))
                         "->x25519-public-key" #(na/ed25519->x25519-public-key pk)
                         "->x25519-secret-key" #(na/ed25519->x25519-secret-key seed)
                         "x25519"              #(na/x25519 k (na/x25519-public-key seed))
                         "x25519-public-key"   #(na/x25519-public-key k)
                         "encrypt"             #(na/chacha20-poly1305-encrypt k n msg nil)
                         "decrypt"             #(na/chacha20-poly1305-decrypt k n ct nil)
                         "hkdf"                #(na/hkdf-sha-256 k nil nil 64)
                         "sha-256"             #(na/sha-256 msg)
                         "hmac"                #(na/hmac-sha-256 k msg)
                         "constant-time-equal" #(na/constant-time-equal? k k)}]
        (let [[r events] (audited f)]
          (is (= :no-throw r) (str label " failed: " (pr-str r)))
          (is (hygienic? events) (str label ": " (pr-str events))))))
    (testing "when C reports a failure, the buffers are still wiped"
      (let [[r events] (audited #(na/chacha20-poly1305-decrypt (b 32 9) n ct nil))]
        (is (= :nacljc.core/auth-failed r))
        (is (hygienic? events) (pr-str events)))
      (let [[r events] (audited #(na/x25519 k (b 32 0)))]
        (is (= :nacljc.core/low-order-point r))
        (is (hygienic? events) (pr-str events))))
    (testing "bad input is rejected before any native memory is allocated"
      (let [[r events] (audited #(na/ed25519-sign (b 31) msg))]
        (is (= :nacljc.core/bad-length r))
        (is (empty? events))))))

(deftest the-wipe-really-zeroes
  (let [arena (ffi/confined-arena)]
    (try
      (let [p (ffi/alloc arena 64)]
        (ffi/write-array p :char (b 64 0x55))
        (is (= (repeat 64 0x55) (byte-seq (ffi/read-array p :char 64))) "the buffer held data")
        (#'na/wipe-native! p 64)
        (is (= (repeat 64 0) (byte-seq (ffi/read-array p :char 64))) "sodium_memzero cleared it"))
      (finally (.close arena)))))

(deftest inputs-are-never-mutated-and-outputs-never-alias
  (let [seed (b 32 3) msg (utf8 "message") k (b 32 4) n (b 12 5) aad (utf8 "aad")
        before (mapv hex [seed msg k n aad])
        sig (na/ed25519-sign seed msg)
        ct  (na/chacha20-poly1305-encrypt k n msg aad)
        pt  (na/chacha20-poly1305-decrypt k n ct aad)
        h   (na/sha-256 msg)]
    (na/hkdf-sha-256 k n aad 32)
    (na/hmac-sha-256 k msg)
    (na/x25519 k (na/x25519-public-key seed))
    (is (= before (mapv hex [seed msg k n aad])) "no function writes to its inputs")
    (is (not (identical? pt msg)) "decrypt returns a fresh array")
    (na/memzero! pt)
    (na/memzero! sig)
    (is (= (hex h) (hex (na/sha-256 msg))) "results are independent copies")
    (is (= (hex (utf8 "message")) (hex msg)) "wiping a result leaves the input alone")))

;; ---- memzero! and constant-time-equal? ----

(deftest memzero!-clears-a-byte-array
  (let [bs (b 40 0x7f)]
    (is (nil? (na/memzero! bs)))
    (is (= (repeat 40 0) (byte-seq bs))))
  (is (nil? (na/memzero! (b 0))) "empty is fine"))

(deftest constant-time-equal?-compares-contents
  (is (true? (na/constant-time-equal? (b 32 1) (b 32 1))))
  (is (false? (na/constant-time-equal? (b 32 1) (bytes-from (concat (repeat 31 1) [2])))))
  (is (false? (na/constant-time-equal? (b 32 1) (b 31 1))) "different lengths: false, not an error")
  (is (true? (na/constant-time-equal? (b 0) (b 0)))))

#?(:cljs
   (deftest uint8array-is-accepted-on-nbb
     (let [msg (utf8 "abc")
           u8  (js/Uint8Array.from (array-seq (js/Uint8Array. (.-buffer msg))))]
       (is (= (hex (na/sha-256 msg)) (hex (na/sha-256 u8))) "Uint8Array input, same bytes")
       (is (instance? js/Int8Array (na/sha-256 u8)) "results are Int8Array"))))

;; ---- the loaded libsodium must be new enough ----

(deftest minimum-version-check
  (let [version>=? #'na/version>=?]
    (testing "version>=? compares release versions numerically"
      (is (true? (version>=? "1.0.19" [1 0 19])))
      (is (true? (version>=? "1.0.22" [1 0 19])))
      (is (true? (version>=? "1.1.0" [1 0 19])))
      (is (false? (version>=? "1.0.18" [1 0 19])) "Ubuntu 24.04's libsodium: no HKDF")
      (is (false? (version>=? "1.0.9" [1 0 19])) "numeric, not lexicographic")
      (is (false? (version>=? "garbage" [1 0 19])))
      (is (false? (version>=? nil [1 0 19]))))
    (testing "the loaded library passes"
      (is (re-matches #"\d+\.\d+\.\d+" (na/libsodium-version)))
      (is (version>=? (na/libsodium-version) na/minimum-libsodium-version)))))

;; ---- randomness ----

(deftest random-bytes-are-distinct
  (is (= 32 (alength (na/random-bytes 32))))
  (is (= 1000 (count (set (repeatedly 1000 #(hex (na/random-bytes 16))))))))
