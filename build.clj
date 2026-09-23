(ns build
  "Build script for sodium.cljc — LOCAL installs only.

   Usage:
     clojure -T:build jar      ; target/sodium.jar
     clojure -T:build install  ; install to ~/.m2 as com.github.franks42/sodium 0.1.0-SNAPSHOT
     clojure -T:build clean

   There is deliberately no deploy: this is research code. The snapshot
   exists so consumers (signet) can test the packaged jar, as a real user
   would, before anything is published. Re-run install after every change —
   consumers keep using the old jar until you do."
  (:require [clojure.tools.build.api :as b]))

(def lib 'com.github.franks42/sodium)
(def version "0.1.0-SNAPSHOT")
(def class-dir "target/classes")
(def jar-file "target/sodium.jar")
;; :root nil keeps org.clojure/clojure out of the pom; the pom lists only
;; this project's :deps (org.babashka/ffi, needed on the JVM).
(def basis (delay (b/create-basis {:project "deps.edn" :root nil})))

(defn clean [_]
  (b/delete {:path "target"}))

(defn jar [_]
  (clean nil)
  (b/copy-dir {:src-dirs ["src"] :target-dir class-dir})
  (b/write-pom {:class-dir class-dir
                :lib       lib
                :version   version
                :basis     @basis
                :src-dirs  ["src"]
                :pom-data  [[:description "libsodium for Clojure on JVM, babashka and nbb via babashka.ffi (research)"]
                            [:url "https://github.com/franks42/sodium.cljc"]
                            [:licenses
                             [:license
                              [:name "EPL-2.0"]
                              [:url "https://www.eclipse.org/legal/epl-2.0/"]]]
                            [:scm
                             [:url "https://github.com/franks42/sodium.cljc"]
                             [:connection "scm:git:https://github.com/franks42/sodium.cljc.git"]]]})
  (b/jar {:class-dir class-dir :jar-file jar-file})
  (println "Created" jar-file))

(defn install [_]
  (jar nil)
  (b/install {:basis @basis :lib lib :version version
              :jar-file jar-file :class-dir class-dir})
  (println (format "Installed %s %s to ~/.m2/repository" lib version))
  (println (format "Use: %s {:mvn/version \"%s\"}" lib version)))
