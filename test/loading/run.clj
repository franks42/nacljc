(ns loading.run
  "Library loading, in fresh processes (the library loads once, when
   nacljc.core loads): the defaults, NACLJC_LIBSODIUM, the nacljc.libsodium
   system property (JVM and bb), a missing path, and a path that loads but
   is not libsodium. On bb, nbb and the JVM. Run from the repo root:
   bb test:loading"
  (:require [babashka.fs :as fs]
            [babashka.process :as p]
            [clojure.edn :as edn]
            [clojure.string :as str]))

(def child "test/loading/child.cljc")

(def real
  "A libsodium >= 1.0.19 on this machine."
  (or (System/getenv "NACLJC_TEST_LIBSODIUM")
      (first (filter fs/exists? ["/opt/homebrew/opt/libsodium/lib/libsodium.dylib"
                                 "/usr/local/opt/libsodium/lib/libsodium.dylib"
                                 "/usr/local/lib/libsodium.so.26"
                                 "/usr/lib/x86_64-linux-gnu/libsodium.so.26"]))
      (throw (ex-info "no libsodium found; set NACLJC_TEST_LIBSODIUM" {}))))

(def other
  "A shared library that loads but is not libsodium."
  (or (first (filter fs/exists? ["/opt/homebrew/lib/libzstd.1.dylib"
                                 "/usr/lib/x86_64-linux-gnu/libz.so.1"
                                 "/lib/x86_64-linux-gnu/libz.so.1"]))
      (throw (ex-info "no non-libsodium library found for the negative test" {}))))

(def missing "/nonexistent/libsodium-for-nacljc-test")

(defn- command [runtime props]
  (case runtime
    :bb  (concat ["bb"] (map #(str "-D" %) props) ["-cp" "src" child])
    :nbb ["nbb" "-cp" "src" child]
    :jvm (concat ["clojure"] (map #(str "-J-D" %) props)
                 ["-J--enable-native-access=ALL-UNNAMED" "-M" child])))

(defn- run-child [runtime {:keys [env props]}]
  (let [{:keys [out err]} @(p/process (command runtime props)
                                      {:out :string :err :string
                                       :extra-env (merge {"NACLJC_LIBSODIUM" ""} env)})
        line (last (str/split-lines (str/trim out)))]
    (try (edn/read-string line)
         (catch Exception _ {:error :no-edn :out out :err err}))))

(def cases
  "[label runtimes config check]"
  [["defaults" #{:bb :nbb :jvm} {} #(contains? % :ok)]
   ["empty NACLJC_LIBSODIUM = unset" #{:bb :nbb :jvm} {:env {"NACLJC_LIBSODIUM" ""}} #(contains? % :ok)]
   ["NACLJC_LIBSODIUM = libsodium" #{:bb :nbb :jvm} {:env {"NACLJC_LIBSODIUM" real}} #(contains? % :ok)]
   ["NACLJC_LIBSODIUM = missing path: only that path is tried" #{:bb :nbb :jvm}
    {:env {"NACLJC_LIBSODIUM" missing}}
    #(and (= :nacljc.core/library-not-found (:error %)) (= [missing] (:tried %))
          (= "environment variable NACLJC_LIBSODIUM" (:source %)))]
   ["NACLJC_LIBSODIUM = another library" #{:bb :nbb :jvm}
    {:env {"NACLJC_LIBSODIUM" other}} #(= :nacljc.core/not-libsodium (:error %))]
   ["property = missing path" #{:bb :jvm}
    {:props [(str "nacljc.libsodium=" missing)]}
    #(and (= :nacljc.core/library-not-found (:error %))
          (= "system property nacljc.libsodium" (:source %)))]
   ["property beats NACLJC_LIBSODIUM" #{:bb :jvm}
    {:env {"NACLJC_LIBSODIUM" missing} :props [(str "nacljc.libsodium=" real)]}
    #(contains? % :ok)]])

(defn -main [& _]
  (let [results (for [[label runtimes config check] cases
                      runtime [:bb :nbb :jvm]
                      :when (runtimes runtime)
                      :let [r (run-child runtime config)]]
                  (let [ok (boolean (check r))]
                    (println (if ok "  ok  " "  FAIL") (name runtime) "-" label
                             (if ok "" (str "\n        got: " (pr-str r))))
                    ok))
        results (doall results)
        fails   (count (remove true? results))]
    (println (format "\n%d loading checks, %d failed" (count results) fails))
    (when (pos? fails) (System/exit 1))))
