;; Run by test/secrets/run.clj in a fresh process. Reads a secret's memory
;; directly, in the mode NACLJC_PROBE names:
;;   inside    during an open access window: must print READ
;;   outside   between calls (no-access): the read must fault
;;   destroyed after secret-destroy! (freed): the read must fault
(require '[babashka.ffi :as ffi]
         '[nacljc.core :as na])

(def mode #?(:clj (System/getenv "NACLJC_PROBE") :cljs (.-NACLJC_PROBE js/process.env)))

(defn- peek4 [p] (let [a (ffi/read-array p :char 4)] #?(:clj (vec a) :cljs (vec (array-seq a)))))

(let [s (na/secret-import! #?(:clj (byte-array [1 2 3 4]) :cljs (js/Int8Array.from #js [1 2 3 4])))
      p (.-ptr s)]
  (case mode
    "inside"    (do (#'na/open-secret! s) (println "READ" (peek4 p)))
    "outside"   (do (println "about to read") (println "READ" (peek4 p)))
    "destroyed" (do (na/secret-destroy! s) (println "about to read") (println "READ" (peek4 p)))))
