(ns tty.run
  "nacljc.tty in child processes on bb, the JVM and nbb, under a
   pseudo-terminal made by script(1): each prompt is awaited before the
   test types (the reader discards typeahead, as readpassphrase does), and
   the output must not contain what was typed (no echo).
   Run from the repo root: bb test:tty"
  (:require [babashka.process :as proc]
            [clojure.edn :as edn]
            [clojure.string :as str]))

(def child "test/tty/child.cljc")

(defn- command [runtime mode]
  (case runtime
    :bb  ["bb" "-cp" "src:test" child mode]
    :nbb ["nbb" "-cp" "src:test" child mode]
    :jvm ["clojure" "-J--enable-native-access=ALL-UNNAMED" "-M" child mode]))

(def ^:private mac? (str/includes? (str/lower-case (System/getProperty "os.name")) "mac"))

(defn- under-pty
  "cmd under a pseudo-terminal: script(1), whose flags differ by OS."
  [cmd]
  (if mac?
    (into ["script" "-q" "/dev/null"] cmd)
    ["script" "-qec" (str/join " " cmd) "/dev/null"]))

(defn- run-pty
  "Run cmd under a pseudo-terminal; for each [prompt input] in steps, wait
   for prompt in the output, then type input. Returns [output result]."
  [cmd steps]
  (let [p   (proc/process (under-pty cmd) {:err :out})
        out (StringBuilder.)
        rdr (future (let [in (:out p)]
                      (loop []
                        (let [c (.read ^java.io.InputStream in)]
                          (when-not (neg? c)
                            (locking out (.append out (char c)))
                            (recur))))))
        seen (fn [s] (locking out (str/includes? (str out) s)))
        await! (fn [s] (loop [n 0]
                         (cond (seen s)  true
                               (> n 1200) (throw (ex-info (str "no prompt " s ": " out) {}))
                               :else      (do (Thread/sleep 50) (recur (inc n))))))
        w   (:in p)]
    (doseq [[prompt input] steps]
      (await! prompt)
      (Thread/sleep 300)                       ; the reader switched echo off after printing
      (.write ^java.io.OutputStream w (.getBytes ^String input "UTF-8"))
      (.flush ^java.io.OutputStream w))
    (let [done (deref p 120000 nil)]
      (when-not done (proc/destroy-tree p))
      (deref rdr 5000 nil)
      (let [o (locking out (str out))
            line (last (filter #(str/starts-with? % "{") (map str/trim (str/split-lines o))))]
        [o (some-> line edn/read-string)]))))

(defn- run-pipe [cmd input]
  (let [{:keys [out]} @(proc/process cmd {:in input :out :string :err :string})]
    (some-> (last (filter #(str/starts-with? % "{") (map str/trim (str/split-lines out)))) edn/read-string)))

(defn- hex [^String s] (apply str (map #(format "%02x" (bit-and % 0xff)) (.getBytes s "UTF-8"))))

(defn- checks [runtime]
  (let [[o r] (run-pty (command runtime "read") [["pw: " "hunter2\n"]])]
    (concat
     [["reads the password"          (= (hex "hunter2") (:hex r))]
      ["no echo"                     (not (str/includes? o "hunter2"))]
      ["terminal settings restored"  (true? (:restored r))]]
     (let [[_ r] (run-pty (command runtime "read") [["pw: " "abcX\u007fd\n"]])]
       [["backspace is the terminal's"  (= (hex "abcd") (:hex r))]])
     (let [[_ r] (run-pty (command runtime "read") [["pw: " "pässwörd\n"]])]
       [["UTF-8 as typed"  (= (hex "pässwörd") (:hex r))]])
     (let [[_ r] (run-pty (command runtime "read") [["pw: " "abc\u0003\n"]])]
       [["^C ends the read"  (and (= :nacljc.tty/interrupted (:error r)) (true? (:restored r)))]])
     (let [[_ r] (run-pty (command runtime "read") [["pw: " "\n"]])]
       [["an empty password is refused"  (= :nacljc.tty/empty (:error r))]])
     (let [[_ r] (run-pty (command runtime "confirm") [["pw: " "same\n"] ["again: " "same\n"]])]
       [["confirmation"  (= (hex "same") (:hex r))]])
     (let [[_ r] (run-pty (command runtime "confirm") [["pw: " "one\n"] ["again: " "two\n"]])]
       [["a different confirmation"  (= :nacljc.tty/mismatch (:error r))]])
     [["read-password-fd: up to the newline"  (= (hex "from a pipe") (:hex (run-pipe (command runtime "fd") "from a pipe\nnext line\n")))]
      ["read-password-fd: to the end"         (= (hex "no newline") (:hex (run-pipe (command runtime "fd") "no newline")))]
      ["read-password-fd: too long"           (= :nacljc.tty/too-long (:error (run-pipe (command runtime "fd") (apply str (repeat 1100 "a")))))]])))

(defn -main [& args]
  (let [runtimes (if (seq args) (map keyword args) [:bb :jvm :nbb])
        results  (doall
                  (for [runtime runtimes
                        [label ok] (try (checks runtime)
                                        (catch Exception e [[(str "ran: " (ex-message e)) false]]))]
                    (do (println (if ok "  ok  " "  FAIL") (name runtime) label)
                        ok)))
        fails    (count (remove true? results))]
    (println (format "\n%d tty checks, %d failed" (count results) fails))
    (shutdown-agents)
    (System/exit (if (pos? fails) 1 0))))
