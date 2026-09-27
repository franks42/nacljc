(ns process.child
  "Run in a fresh process by test/process/run.clj: loads nacljc.process,
   reads the status, hardens everything, reads it again, prints EDN."
  (:require [nacljc.process :as p]))

(let [before (p/process-status)
      result (p/harden-process! {:core-dumps false :dumpable false :heap-dump-on-oom false})
      after  (p/process-status)]
  (prn {:before before :result result :after after}))
