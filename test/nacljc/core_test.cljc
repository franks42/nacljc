(ns nacljc.core-test
  "Known-answer tests for nacljc.core, on JVM Clojure, bb and nbb.
   test/nacljc/vectors.edn holds RFC vectors and cross-platform vectors
   (fixed inputs where native libsodium, signet's JCA backend and
   libsodium.js agree). Run from the repo root."
  (:require [clojure.test :refer [deftest is testing]]
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

(defn- unhex [s]
  (bytes-from (map #(#?(:clj Integer/parseInt :cljs js/parseInt) (subs s % (+ % 2)) 16)
                   (range 0 (count s) 2))))

(defn- hex [bs]
  (apply str (map #(let [h #?(:clj  (Integer/toHexString (bit-and % 0xff))
                              :cljs (.toString (bit-and % 0xff) 16))]
                     (if (= 1 (count h)) (str "0" h) h))
                  #?(:clj (seq bs) :cljs (array-seq bs)))))

(defn- utf8 [s]
  #?(:clj  (.getBytes ^String s "UTF-8")
     :cljs (js/Int8Array.from (.from js/Buffer s "utf8"))))

;; ---- RFC vectors ----

(deftest rfc8032-ed25519
  (let [{:keys [seed pk msg sig]} (get-in vectors [:rfc :ed25519])
        [pk' sk] (na/seed->keypair (unhex seed))]
    (is (= pk (hex pk')) "seed -> public key")
    (is (= sig (hex (na/sign sk (utf8 msg)))) "deterministic signature")
    (is (na/verify? pk' (utf8 msg) (unhex sig)))
    (is (not (na/verify? pk' (utf8 "x") (unhex sig))) "rejects another message")))

(deftest rfc7748-x25519
  (let [{:keys [scalar u out]} (get-in vectors [:rfc :x25519])]
    (is (= out (hex (na/x25519 (unhex scalar) (unhex u)))))))

(deftest rfc8439-chacha20-poly1305
  (let [{:keys [key nonce ad pt ct]} (get-in vectors [:rfc :aead])]
    (is (= ct (hex (na/aead-encrypt (unhex key) (unhex nonce) (utf8 pt) (unhex ad)))))
    (is (= (hex (utf8 pt)) (hex (na/aead-decrypt (unhex key) (unhex nonce) (unhex ct) (unhex ad)))))
    (testing "authentication failures throw"
      (is (thrown-with-msg? #?(:clj clojure.lang.ExceptionInfo :cljs ExceptionInfo)
                            #"authentication failed"
                            (na/aead-decrypt (unhex key) (unhex nonce) (unhex ct) (utf8 "other ad")))))))

(deftest rfc5869-hkdf-sha256
  (let [{:keys [ikm salt info len okm]} (get-in vectors [:rfc :hkdf])]
    (is (= okm (hex (na/hkdf-sha256 (unhex ikm) (unhex salt) (unhex info) len))))))

;; ---- cross-platform vectors ----

(deftest xplatform
  (let [v (:xplatform vectors)
        [pk sk] (na/seed->keypair (unhex (:seed v)))]
    (is (= (:pk v) (hex pk)))
    (is (= (:sig v) (hex (na/sign sk (utf8 (:msg v))))))
    (is (= (:x-pk v) (hex (na/ed-pk->x-pk pk))) "Ed25519 -> X25519 public key")
    (is (= (:x-sk v) (hex (na/ed-sk->x-sk sk))) "Ed25519 -> X25519 secret key")
    (is (= (:dh v) (hex (na/x25519 (unhex (:x-sk v)) (unhex (:peer-x-pk v))))))
    (is (= (:ct v) (hex (na/aead-encrypt (unhex (:key v)) (unhex (:nonce v))
                                         (utf8 (:pt v)) (utf8 (:ad v))))))
    (is (= (:hkdf v) (hex (na/hkdf-sha256 (unhex (:key v)) (bytes-from [])
                                          (utf8 "signet/box/v1") 32))))))

;; ---- safety properties ----

(deftest low-order-point-rejected
  (is (thrown? #?(:clj clojure.lang.ExceptionInfo :cljs ExceptionInfo)
               (na/x25519 (na/random-bytes 32) (bytes-from (repeat 32 0))))
      "all-zero public key gives an all-zero secret; libsodium returns -1"))

(deftest random-bytes
  (is (= 64 (count (hex (na/random-bytes 32)))))
  (is (= 1000 (count (set (repeatedly 1000 #(hex (na/random-bytes 16))))))))

(deftest library-version
  (is (re-matches #"\d+\.\d+\.\d+" (na/version-string))))

;; ---- hashing, HMAC, X25519 base point ----

(deftest fips180-sha256
  (let [{:keys [msg digest]} (get-in vectors [:rfc :sha256])]
    (is (= digest (hex (na/sha-256 (utf8 msg)))))))

(deftest rfc4231-hmac-sha256
  (doseq [{:keys [source key data mac]} (get-in vectors [:rfc :hmac-sha256])]
    (is (= mac (hex (na/hmac-sha256 (unhex key) (utf8 data)))) source)))

(deftest rfc7748-x25519-base
  (let [{:keys [sk pk]} (get-in vectors [:rfc :x25519-base])]
    (is (= pk (hex (na/x25519-base (unhex sk)))))))

;; ---- fixed-size inputs are length-checked before reaching C ----

(defn- bad-length? [f]
  (try (f) false
       (catch #?(:clj clojure.lang.ExceptionInfo :cljs ExceptionInfo) e
         (= :nacljc.core/bad-length (:type (ex-data e))))))

(deftest length-checks
  (let [b #(bytes-from (repeat % 1))
        [pk sk] (na/seed->keypair (b 32))
        msg (utf8 "m")]
    (testing "wrong sizes throw ::bad-length instead of over-reading native memory"
      (is (bad-length? #(na/seed->keypair (b 31))))
      (is (bad-length? #(na/sign (b 32) msg)) "32-byte seed passed where the 64-byte secret key belongs")
      (is (bad-length? #(na/ed-pk->x-pk (b 31))))
      (is (bad-length? #(na/ed-sk->x-sk (b 32))))
      (is (bad-length? #(na/x25519 (b 32) (b 31))))
      (is (bad-length? #(na/x25519-base (b 16))))
      (is (bad-length? #(na/aead-encrypt (b 31) (b 12) msg nil)))
      (is (bad-length? #(na/aead-encrypt (b 32) (b 24) msg nil)) "XChaCha-size nonce rejected")
      (is (bad-length? #(na/aead-decrypt (b 32) (b 12) (b 15) nil)) "ciphertext shorter than the tag"))
    (testing "verify? returns false (never throws) for malformed untrusted input"
      (let [sig (na/sign sk msg)]
        (is (true? (na/verify? pk msg sig)))
        (is (false? (na/verify? pk msg (b 10))) "short signature")
        (is (false? (na/verify? (b 31) msg sig)) "short public key")
        (is (false? (na/verify? pk msg nil)))))
    (testing "nil AD is treated as empty"
      (let [k (b 32) n (b 12)]
        (is (= (hex (na/aead-encrypt k n msg nil))
               (hex (na/aead-encrypt k n msg (bytes-from [])))))))))

;; ---- the loaded libsodium must be new enough ----

(deftest minimum-version-check
  (testing "version>=? compares release versions numerically"
    (is (true? (na/version>=? "1.0.19" [1 0 19])))
    (is (true? (na/version>=? "1.0.22" [1 0 19])))
    (is (true? (na/version>=? "1.1.0" [1 0 19])))
    (is (false? (na/version>=? "1.0.18" [1 0 19])) "Ubuntu 24.04's libsodium: no HKDF")
    (is (false? (na/version>=? "1.0.9" [1 0 19])) "numeric, not lexicographic")
    (is (false? (na/version>=? "garbage" [1 0 19]))))
  (testing "the loaded library passes"
    (is (na/version>=? (na/version-string) na/minimum-version))))
