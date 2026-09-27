(ns nacljc.process-test
  "Tests for nacljc.process that change nothing: the public API, option
   checking, and the status report. Applying the options (irreversible for
   core dumps) is tested in child processes: bb test:process."
  (:require [clojure.test :refer [deftest is]]
            [nacljc.process :as p]))

(deftest public-api-is-exactly-the-documented-one
  (is (= '#{process-status harden-process!} (set (keys (ns-publics 'nacljc.process))))))

(deftest process-status-reports-every-setting
  (let [st (p/process-status)]
    (is (= #{:os :core-dumps :dumpable :heap-dump-on-oom} (set (keys st))))
    (is (#{:mac :linux :other} (:os st)))
    (is (or (= :unknown (:core-dumps st)) (= #{:soft :hard} (set (keys (:core-dumps st))))))))

(deftest bad-options-are-refused-before-anything-changes
  (let [before (p/process-status)]
    (doseq [opts [{:core-dumps true}            ; only disabling is offered
                  {:core-dump false}            ; misspelt
                  {:core-dumps false :swap false}]]
      (is (= :nacljc.process/bad-option
             (try (p/harden-process! opts) :no-throw
                  (catch #?(:clj Exception :cljs :default) e (:type (ex-data e)))))
          (pr-str opts)))
    (is (= before (p/process-status)) "a refused call changed nothing, not even the valid options")
    (is (= {} (p/harden-process! {})) "no options: nothing to do")))
