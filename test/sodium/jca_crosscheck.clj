(ns sodium.jca-crosscheck
  "Random-input cross-check: libsodium (via babashka.ffi) vs signet's JCA
   backend (signet.impl.jvm) on identical inputs. JVM and bb only; needs
   ../signet/src on the classpath (bb test:jca)."
  (:require [sodium.core :as na]
            [signet.impl.jvm :as jca]))

(defn- same? [a b] (java.util.Arrays/equals ^bytes a ^bytes b))
(def results (atom []))
(defn- check [label ok] (swap! results conj [label ok]) (println (if ok "  ok  " "  FAIL") label))

(let [;; JCA generates the keypair; libsodium must derive the same pk from the seed
      [jca-pub seed] (jca/generate-ed25519-keypair)
      [na-pk na-sk]  (na/seed->keypair seed)
      msg            (.getBytes "canonical-edn bytes to sign" "UTF-8")
      jca-sig        (jca/ed25519-sign seed msg)
      na-sig         (na/sign na-sk msg)]
  (println "Ed25519")
  (check "seed -> public key identical (the path signet cannot do on bb)" (same? jca-pub na-pk))
  (check "signature byte-identical (Ed25519 is deterministic)" (same? jca-sig na-sig))
  (check "libsodium verifies JCA signature" (na/verify? na-pk msg jca-sig))
  (check "JCA verifies libsodium signature" (jca/ed25519-verify jca-pub msg na-sig))
  (check "libsodium rejects tampered message" (not (na/verify? na-pk (.getBytes "tampered") na-sig)))

  (println "Ed25519 -> X25519 conversion")
  (let [jca-xsk (jca/ed25519-seed->x25519-private seed)
        na-xsk  (na/ed-sk->x-sk na-sk)
        jca-xpk (jca/ed25519-pub->x25519-pub jca-pub)
        na-xpk  (na/ed-pk->x-pk na-pk)]
    (check "X25519 private key identical" (same? jca-xsk na-xsk))
    (check "X25519 public key identical (birational map)" (same? jca-xpk na-xpk))

    (println "X25519 Diffie-Hellman")
    (let [[peer-pub peer-priv] (jca/generate-x25519-keypair)]
      (check "DH shared secret identical, both directions"
             (and (same? (jca/x25519-dh jca-xsk peer-pub) (na/x25519 na-xsk peer-pub))
                  (same? (na/x25519 peer-priv na-xpk) (na/x25519 na-xsk peer-pub)))))))

(println "ChaCha20-Poly1305 IETF + HKDF-SHA-256")
(let [k (na/random-bytes 32) nonce (na/random-bytes 12)
      pt (.getBytes "hello signet" "UTF-8") ad (.getBytes "aad" "UTF-8")
      jca-ct (jca/chacha20-poly1305-encrypt k nonce pt ad)
      na-ct  (na/aead-encrypt k nonce pt ad)]
  (check "AEAD ciphertext+tag byte-identical" (same? jca-ct na-ct))
  (check "libsodium decrypts JCA ciphertext" (same? pt (na/aead-decrypt k nonce jca-ct ad)))
  (check "libsodium rejects wrong AAD"
         (try (na/aead-decrypt k nonce jca-ct (.getBytes "other")) false
              (catch clojure.lang.ExceptionInfo _ true)))
  (let [ikm (na/random-bytes 32) info (.getBytes "signet/box/v1" "UTF-8")]
    (check "HKDF-SHA-256 (empty salt) identical to signet's"
           (same? (jca/hkdf-sha-256 ikm (byte-array 0) info 32)
                  (na/hkdf-sha256 ikm (byte-array 0) info 32)))))

(println "randombytes_buf")
(let [xs (repeatedly 1000 #(vec (na/random-bytes 16)))]
  (check "1000 x 16 random bytes all distinct" (= 1000 (count (set xs)))))

(let [fails (remove second @results)]
  (println (format "\n%d checks, %d failed" (count @results) (count fails)))
  (System/exit (if (seq fails) 1 0)))
