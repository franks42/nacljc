(ns process.run
  "nacljc.process in fresh child processes on bb, the JVM and nbb (the
   changes are irreversible, so never in the test process itself):
   loading changes nothing; each option is applied where the platform has
   it and reported :unsupported where it does not.
   Run from the repo root: bb test:process"
  (:require [babashka.process :as proc]
            [clojure.edn :as edn]
            [clojure.string :as str]))

(def child "test/process/child.cljc")

(defn- command [runtime]
  (case runtime
    :bb  ["bb" "-cp" "src" child]
    :nbb ["nbb" "-cp" "src" child]
    :jvm ["clojure" "-J--enable-native-access=ALL-UNNAMED" "-M" child]))

(defn- run-child [runtime]
  (let [{:keys [exit out err]} @(proc/process (command runtime) {:out :string :err :string})]
    (if (zero? exit)
      (edn/read-string (last (str/split-lines out)))
      (do (println err) nil))))

(defn- checks
  "[label ok?] pairs for one runtime's report r."
  [runtime {:keys [before result after]}]
  (let [linux? (= :linux (:os after))
        jvm?   (= :jvm runtime)]
    [["loading changed nothing (hard core limit not 0)" (not= 0 (get-in before [:core-dumps :hard]))]
     ["core dumps disabled"                           (= :disabled (:core-dumps result))]
     ["core limit now 0/0"                            (= {:soft 0 :hard 0} (:core-dumps after))]
     ["dumpable: disabled on Linux, unsupported elsewhere"
      (if linux?
        (and (= :disabled (:dumpable result)) (false? (:dumpable after)))
        (= :unsupported (:dumpable result)))]
     ["heap dump on OOM: disabled on the JVM, unsupported elsewhere"
      (if jvm?
        (and (= :disabled (:heap-dump-on-oom result)) (false? (:heap-dump-on-oom after)))
        (= :unsupported (:heap-dump-on-oom result)))]]))

(defn -main [& _]
  (let [results (doall
                 (for [runtime [:bb :jvm :nbb]
                       :let [r (run-child runtime)]
                       [label ok] (if r (checks runtime r) [["child ran" false]])]
                   (do (println (if ok "  ok  " "  FAIL") (name runtime) label)
                       ok)))
        fails (count (remove true? results))]
    (println (format "\n%d process checks, %d failed" (count results) fails))
    (when (pos? fails) (System/exit 1))))
