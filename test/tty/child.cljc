(ns tty.child
  "Run by test/tty/run.clj under a pseudo-terminal (or with a pipe for
   :fd): reads a password with nacljc.tty and prints one EDN line, the
   result: the bytes as hex (tests only export them), or the error type.
   Arg: read | confirm | fd."
  (:require [clojure.string :as str]
            [nacljc.core :as na]
            [nacljc.tty :as tty]))

(defn- hex [bs]
  (str/join (map #(let [b (bit-and % 0xff)]
                    #?(:clj  (format "%02x" b)
                       :cljs (let [s (str "0" (.toString b 16))] (subs s (- (count s) 2)))))
                 bs)))

(defn- report [s]
  (try {:hex (hex (na/secret-export s {:i-understand :exposes-secret}))}
       (finally (na/secret-destroy! s))))

(let [mode   (last #?(:clj *command-line-args* :cljs (.-argv js/process)))
      flags  (when (not= "fd" mode) (#'nacljc.tty/terminal-flags))
      result (try
               (case mode
                 "read"    (report (tty/read-password "pw: "))
                 "confirm" (report (tty/read-password "pw: " {:confirm "again: "}))
                 "fd"      (report (tty/read-password-fd 0)))
               (catch #?(:clj Throwable :cljs :default) e
                 {:error (:type (ex-data e)) :message (ex-message e)}))]
  (println)
  (prn (cond-> result
         flags (assoc :restored (= flags (#'nacljc.tty/terminal-flags))))))
