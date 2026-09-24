(ns check
  "libsodium.js (WASM, libsodium-wrappers-sumo) against test/nacljc/vectors.edn.
   Shows the browser/Node-WASM engine gives the same bytes as native
   libsodium. 0.8.4 does not export HKDF (added upstream 2026-07-10, not yet
   released), so hkdf below is RFC 5869 built on crypto_auth_hmacsha256.
   Run from this directory: npm install && nbb check.cljs"
  (:require ["libsodium-wrappers-sumo$default" :as s]
            ["fs" :as fs]
            [cljs.reader :as reader]
            [promesa.core :as p]))

(def vectors (reader/read-string (str (fs/readFileSync "../nacljc/vectors.edn"))))
(def fails (atom 0))
(defn- check [label ok]
  (when-not ok (swap! fails inc))
  (println (if ok "  ok  " "  FAIL") label))

(defn- concat-u8 [& as]
  (let [o (js/Uint8Array. (reduce + (map #(.-length %) as)))]
    (reduce (fn [off a] (.set o a off) (+ off (.-length a))) 0 as)
    o))

(defn- hkdf-sha256
  "RFC 5869 over HMAC-SHA-256. crypto_auth_hmacsha256 wants a 32-byte key;
   both HMAC keys here are 32 bytes (the salt, zero-filled when empty, and
   the PRK). A non-empty salt of another length would need the stateful
   crypto_auth_hmacsha256_init API."
  [ikm salt info len]
  (let [hmac (fn [k data] (.crypto_auth_hmacsha256 s data k))
        prk  (hmac (if (zero? (.-length salt)) (js/Uint8Array. 32) salt) ikm)]
    (loop [t (js/Uint8Array. 0) out (js/Uint8Array. 0) i 1]
      (if (>= (.-length out) len)
        (.slice out 0 len)
        (let [t' (hmac prk (concat-u8 t info (js/Uint8Array. #js [i])))]
          (recur t' (concat-u8 out t') (inc i)))))))

(p/let [_ (.-ready s)]
  (let [hex   #(.to_hex s %)
        unhex #(.from_hex s %)
        utf8  #(.from_string s %)
        {:keys [rfc xplatform]} vectors]
    (println "libsodium.js" (.sodium_version_string s))
    (let [{:keys [seed pk msg sig]} (:ed25519 rfc)
          kp (.crypto_sign_seed_keypair s (unhex seed))]
      (check "RFC 8032 public key" (= pk (hex (.-publicKey kp))))
      (check "RFC 8032 signature" (= sig (hex (.crypto_sign_detached s (utf8 msg) (.-privateKey kp))))))
    (let [{:keys [scalar u out]} (:x25519 rfc)]
      (check "RFC 7748 X25519" (= out (hex (.crypto_scalarmult s (unhex scalar) (unhex u))))))
    (let [{:keys [key nonce ad pt ct]} (:aead rfc)]
      (check "RFC 8439 ChaCha20-Poly1305"
             (= ct (hex (.crypto_aead_chacha20poly1305_ietf_encrypt s (utf8 pt) (unhex ad) nil (unhex nonce) (unhex key))))))
    (check "HKDF not exported by this libsodium.js (shim used)"
           (not (fn? (.-crypto_kdf_hkdf_sha256_extract s))))
    (let [v xplatform
          kp (.crypto_sign_seed_keypair s (unhex (:seed v)))]
      (check "xplatform signature" (= (:sig v) (hex (.crypto_sign_detached s (utf8 (:msg v)) (.-privateKey kp)))))
      (check "xplatform Ed25519 -> X25519 pk" (= (:x-pk v) (hex (.crypto_sign_ed25519_pk_to_curve25519 s (.-publicKey kp)))))
      (check "xplatform Ed25519 -> X25519 sk" (= (:x-sk v) (hex (.crypto_sign_ed25519_sk_to_curve25519 s (.-privateKey kp)))))
      (check "xplatform X25519 DH" (= (:dh v) (hex (.crypto_scalarmult s (unhex (:x-sk v)) (unhex (:peer-x-pk v))))))
      (check "xplatform AEAD" (= (:ct v) (hex (.crypto_aead_chacha20poly1305_ietf_encrypt s (utf8 (:pt v)) (utf8 (:ad v)) nil (unhex (:nonce v)) (unhex (:key v))))))
      (check "xplatform HKDF via HMAC shim" (= (:hkdf v) (hex (hkdf-sha256 (unhex (:key v)) (js/Uint8Array. 0) (utf8 "signet/box/v1") 32)))))
    (let [{:keys [key nonce valid]} (:aegis256 vectors)]
      (if (fn? (.-crypto_aead_aegis256_encrypt s))
        (doseq [{:keys [tv ad msg ct tag]} valid]
          (check (str "RFC 10032 AEGIS-256 TV" tv)
                 (= (str ct tag) (hex (.crypto_aead_aegis256_encrypt s (unhex msg) (unhex ad) nil (unhex nonce) (unhex key))))))
        (check "AEGIS-256 exported by this libsodium.js" false)))
    (check "randombytes_buf distinct" (= 1000 (count (set (repeatedly 1000 #(hex (.randombytes_buf s 16)))))))
    (println (str "\n" @fails " failed"))
    (js/process.exit (if (pos? @fails) 1 0))))
