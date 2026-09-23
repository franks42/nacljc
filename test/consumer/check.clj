(ns consumer.check
  "Run nacljc's own test suite against a packaged jar, the way a user would
   get it: from a scratch project with no src/, on the JVM, bb and nbb.

     bb test:jar                ; the locally installed jar (build.clj's version)
     bb test:clojars 0.1.0      ; a release, fetched from Clojars

   For a release the JVM and bb use an empty local Maven repository, so the
   jar really comes from Clojars. The scratch project reaches the tests
   through a symlink to test/, since the suite reads
   test/nacljc/vectors.edn relative to the working directory."
  (:require [babashka.fs :as fs]
            [babashka.process :as p]
            [clojure.string :as str]))

(def coord 'com.github.franks42/nacljc)

(def run-suite
  "(require 'clojure.test 'nacljc.core-test) + exit 1 on any failure."
  (str "(require 'clojure.test 'nacljc.core-test)"
       "(let [r (clojure.test/run-tests 'nacljc.core-test)]"
       "  (when (pos? (+ (:fail r) (:error r))) (System/exit 1)))"))

(def where
  "Print where nacljc.core was loaded from."
  "(println :nacljc-from (str (clojure.java.io/resource \"nacljc/core.cljc\")))")

(defn- sh [dir & args]
  (println "  $" (str/join " " args))
  (let [{:keys [exit out err]} @(p/process args {:dir dir :out :string :err :string})]
    (print out) (flush)
    (when-not (zero? exit)
      (binding [*out* *err*] (println err))
      (throw (ex-info (str "failed: " (str/join " " args)) {:exit exit})))
    out))

(defn- from-jar! [runtime out]
  (if (re-find #":nacljc-from jar:file:" out)
    (println (str "  " runtime ": nacljc.core loaded from the jar"))
    (throw (ex-info (str runtime ": nacljc.core did not load from a jar") {:out out}))))

(defn check
  "Run the suite on the JVM, bb and nbb against nacljc version. With
   fresh-repo?, the JVM and bb resolve into an empty local repository."
  [version fresh-repo?]
  (let [dir  (str (fs/create-temp-dir {:prefix "nacljc-consumer-"}))
        repo (when fresh-repo? (str (fs/create-dirs (fs/path dir "m2"))))
        dep  (str "{" coord " {:mvn/version \"" version "\"}}")
        opts (str ":paths [\"test\"] :deps " dep
                  (when repo (str " :mvn/local-repo \"" repo "\"")))]
    (fs/create-sym-link (fs/path dir "test") (fs/absolutize "test"))
    (spit (str (fs/path dir "deps.edn"))
          (str "{" opts " :aliases {:native {:jvm-opts [\"--enable-native-access=ALL-UNNAMED\"]}}}"))
    (spit (str (fs/path dir "bb.edn")) (str "{" opts "}"))
    (spit (str (fs/path dir "nbb.edn")) (str "{:paths [\"test\"] :deps " dep "}"))
    (try
      (println "JVM")
      (from-jar! "JVM" (sh dir "clojure" "-M:native" "-e" where))
      (sh dir "clojure" "-M:native" "-e" run-suite)
      (println "bb")
      (from-jar! "bb" (sh dir "bb" "-e" where))
      (sh dir "bb" "-e" run-suite)
      (println "nbb (no src/ in the scratch project, so nacljc.core can only come from the jar)")
      (sh dir "nbb" "-e" "(require 'cljs.test 'nacljc.core-test) (cljs.test/run-tests 'nacljc.core-test)")
      (println (str "\n" coord " " version ": the suite passes from the jar on the JVM, bb and nbb"))
      (finally (fs/delete-tree dir)))))

(defn- build-version
  "The version build.clj builds, i.e. what bb install just installed."
  []
  (or (second (re-find #"\(def version \"([^\"]+)\"\)" (slurp "build.clj")))
      (throw (ex-info "cannot parse the version from build.clj" {}))))

(defn -main [& [mode version]]
  (case mode
    "local"    (check (or version (build-version)) false)
    "clojars"  (check (or version (throw (ex-info "usage: clojars <version>" {}))) true)))
