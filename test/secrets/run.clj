(ns secrets.run
  "Secret memory is really inaccessible outside calls: in a child process, a
   read of a secret's memory outside an access window, or after destroying
   it, must fault, while the same read inside a window works. The fault
   crashes bb and nbb (SIGSEGV/SIGBUS); the JVM turns it into
   InternalError \"a fault occurred in an unsafe memory access operation\".
   Either way no byte is read. On bb, the JVM and nbb.
   Run from the repo root: bb test:secrets"
  (:require [babashka.process :as p]
            [clojure.string :as str]))

(def child "test/secrets/child.cljc")

(defn- command [runtime]
  (case runtime
    :bb  ["bb" "-cp" "src" child]
    :nbb ["nbb" "-cp" "src" child]
    :jvm ["clojure" "-J--enable-native-access=ALL-UNNAMED" "-M" child]))

(defn- run-child [runtime mode]
  @(p/process (command runtime) {:out :string :err :string :extra-env {"NACLJC_PROBE" mode}}))

(defn -main [& _]
  (let [results
        (doall
         (for [runtime [:bb :jvm :nbb]
               [mode expect] [["inside" :reads] ["outside" :faults] ["destroyed" :faults]]]
           (let [{:keys [exit out]} (run-child runtime mode)
                 read? (str/includes? out "READ [1 2 3 4]")
                 ok    (case expect
                         :reads   (and (zero? exit) read?)
                         :faults  (and (not (zero? exit)) (not (str/includes? out "READ"))))]
             (println (if ok "  ok  " "  FAIL") (name runtime) mode "->"
                      (if (zero? exit) "exit 0" (str "faulted (exit " exit ")"))
                      (if read? "and read the bytes" ""))
             ok)))
        fails (count (remove true? results))]
    (println (format "\n%d secret-memory checks, %d failed" (count results) fails))
    (when (pos? fails) (System/exit 1))))
