(ns build
  "Build script for nacljc.

   Usage:
     clojure -T:build jar      ; target/nacljc.jar
     clojure -T:build install  ; install into ~/.m2 (re-run after every change:
                               ; consumers keep using the old jar until you do)
     clojure -T:build deploy   ; publish to Clojars (the release workflow does
                               ; this for a vX.Y.Z tag; needs CLOJARS_USERNAME
                               ; and CLOJARS_PASSWORD)
     clojure -T:build clean"
  (:require [clojure.tools.build.api :as b]
            [deps-deploy.deps-deploy :as dd]))

(def lib 'com.github.franks42/nacljc)
(def version "0.4.0-SNAPSHOT")
(def class-dir "target/classes")
(def jar-file "target/nacljc.jar")
;; :root nil keeps org.clojure/clojure out of the pom; the pom lists only
;; this project's :deps (org.babashka/ffi, needed on the JVM). But the root
;; deps.edn is also where Maven Central and Clojars are defined, so they are
;; added back: without them the basis cannot download anything, and a build
;; on a fresh machine fails with "Could not find artifact".
(def basis
  (delay (b/create-basis {:project "deps.edn"
                          :root    nil
                          :extra   {:mvn/repos {"central" {:url "https://repo1.maven.org/maven2/"}
                                                "clojars" {:url "https://repo.clojars.org/"}}}})))

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
                :pom-data  [[:description "libsodium for Clojure on the JVM, babashka and nbb via babashka.ffi, hardened at the C boundary. NaCl-aligned, not NaCl."]
                            [:url "https://github.com/franks42/nacljc"]
                            [:licenses
                             [:license
                              [:name "EPL-2.0"]
                              [:url "https://www.eclipse.org/legal/epl-2.0/"]]]
                            [:scm
                             [:url "https://github.com/franks42/nacljc"]
                             [:connection "scm:git:https://github.com/franks42/nacljc.git"]
                             [:developerConnection "scm:git:ssh://git@github.com/franks42/nacljc.git"]
                             [:tag (str "v" version)]]]})
  (b/jar {:class-dir class-dir :jar-file jar-file})
  (println "Created" jar-file))

(defn install [_]
  (jar nil)
  (b/install {:basis @basis :lib lib :version version
              :jar-file jar-file :class-dir class-dir})
  (println (format "Installed %s %s to ~/.m2/repository" lib version))
  (println (format "Use: %s {:mvn/version \"%s\"}" lib version)))

(defn deploy [_]
  (jar nil)
  (dd/deploy {:installer :remote
              :artifact  (b/resolve-path jar-file)
              :pom-file  (b/pom-path {:lib lib :class-dir class-dir})}))
