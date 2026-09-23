(ns nacljc.signet-suite
  "Runs signet's own, unmodified test suite and reports which backend
   signet.impl.jvm resolved to. Usage: -m nacljc.signet-suite <expected>
   where <expected> is libsodium (shim ahead of signet's src on the
   classpath) or jca (signet's own JCA backend: the oracle run).
   Exits 1 on test failures, 2 if the wrong backend loaded."
  (:require [clojure.java.io :as io]
            [clojure.test :as t]))

(def ^:private test-nss
  '[signet.key-test signet.sign-test signet.chain-test signet.encryption-test
    signet.session-test signet.ssh-test signet.bb-smoke-test])

(defn -main [& [expected]]
  (let [expected (keyword (or expected "libsodium"))
        bb?      (System/getProperty "babashka.version")
        ;; BouncyCastle (secp256k1) is not loadable on bb
        nss      (cond-> test-nss (not bb?) (conj 'signet.secp256k1-test))]
    (require 'signet.impl.jvm)
    (let [marker (ns-resolve 'signet.impl.jvm 'backend)
          loaded (if marker @marker :jca)]
      (println "runtime:" (if bb? (str "babashka " bb?) (str "JVM " (System/getProperty "java.version")))
               "| backend:" loaded "| from" (str (io/resource "signet/impl/jvm.clj")))
      (when-not (= loaded expected)
        (println "WRONG BACKEND: expected" expected)
        (System/exit 2)))
    (apply require nss)
    (let [{:keys [fail error]} (apply t/run-tests nss)]
      (System/exit (if (pos? (+ fail error)) 1 0)))))
