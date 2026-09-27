(ns nacljc.process
  "Opt-in process hardening for programs that hold secrets.

   Nothing here runs by itself: loading nacljc (or this namespace) changes
   no process setting. Hardening is a deployment choice, made by calling
   harden-process! with the options you want, because each one also takes
   something away (core dumps and debugger access are how crashes and hangs
   get diagnosed). process-status reports the current settings.

   Options (only disabling is offered; all are off unless asked for):
     :core-dumps false        setrlimit(RLIMIT_CORE, 0, 0): no core dump,
                              and the hard limit 0 cannot be raised again.
                              macOS and Linux.
     :dumpable false          prctl(PR_SET_DUMPABLE, 0): no core dump, and
                              other processes of the same user can no
                              longer attach a debugger (ptrace) or read
                              /proc/<pid>/mem. Linux only.
     :heap-dump-on-oom false  switch off -XX:+HeapDumpOnOutOfMemoryError,
                              which writes the whole heap to disk. HotSpot
                              JVM only.

   Not settable from a running process, so documented only (README,
   \"Deployment hardening\"): -XX:+DisableAttachMechanism and
   -XX:ErrorFile on the JVM, swap and hibernation on the machine.

   Uses libc through babashka.ffi on the JVM, bb and nbb. This namespace is
   separate from nacljc.core, which binds libsodium only."
  (:require [babashka.ffi :as ffi]
            [clojure.string :as str]))

;; ---------------------------------------------------------------------------
;; Platform
;; ---------------------------------------------------------------------------

(defn- os
  "The operating system: :mac, :linux or :other. Impure: reads the os.name
   property (process.platform on nbb)."
  []
  (let [s (str #?(:clj (System/getProperty "os.name") :cljs js/process.platform))]
    (cond (re-find #"(?i)mac|darwin" s) :mac
          (re-find #"(?i)linux" s)      :linux
          :else                         :other)))

(def ^:private libc
  "The C library, loaded on first use. Impure (a delay): loads a library."
  (delay (ffi/load-system-library "c")))

(defn- libc-fn
  "The libc function c-name, bound over FFI. Impure: reads the library."
  [c-name argtypes rettype]
  (ffi/cfn @libc c-name argtypes rettype))

(def ^:private rlimit-core
  "RLIMIT_CORE: 4 on Linux and on macOS."
  4)

(def ^:private pr-get-dumpable 3)
(def ^:private pr-set-dumpable 4)

;; ---------------------------------------------------------------------------
;; Core dumps: getrlimit / setrlimit (struct rlimit is two 64-bit rlim_t)
;; ---------------------------------------------------------------------------

(defn- limit-value
  "A rlim_t as a number, or :unlimited for RLIM_INFINITY: all ones on
   Linux (-1 as a signed long), 2^63-1 on macOS. Pure."
  [v]
  #?(:clj  (if (or (neg? v) (= v 9223372036854775807)) :unlimited v)
     ;; nbb reads a uint64 as a BigInt, unsigned: all ones is 2^64-1
     :cljs (let [n (js/BigInt v)]              ; a BigInt, or a whole number
             (if (or (= n (js/BigInt "9223372036854775807"))
                     (= n (js/BigInt "18446744073709551615")))
               :unlimited
               (js/Number n)))))

(defn- core-limit
  "{:soft … :hard …} for RLIMIT_CORE, or nil if getrlimit fails.
   Impure: reads the process's resource limits."
  []
  (let [arena (ffi/confined-arena)]
    (try
      (let [p (ffi/alloc arena 16)]
        (when (zero? ((libc-fn "getrlimit" [:int :pointer] :int) rlimit-core p))
          {:soft (limit-value (ffi/read p :uint64 0))
           :hard (limit-value (ffi/read p :uint64 8))}))
      (finally (.close arena)))))

(defn- disable-core-dumps!
  "setrlimit(RLIMIT_CORE, {0, 0}). Returns true on success.
   Impure: lowers the process's core-dump limit for good."
  []
  (let [arena (ffi/confined-arena)]
    (try
      (let [p (ffi/alloc arena 16)]
        (ffi/write p :uint64 0 0)
        (ffi/write p :uint64 0 8)
        (zero? ((libc-fn "setrlimit" [:int :pointer] :int) rlimit-core p)))
      (finally (.close arena)))))

;; ---------------------------------------------------------------------------
;; Dumpable: prctl (Linux)
;; ---------------------------------------------------------------------------

(defn- prctl
  "prctl(option, arg2, 0, 0, 0). Impure: reads or writes process
   attributes."
  [option arg2]
  ((libc-fn "prctl" [:int :ulong :ulong :ulong :ulong] :int) option arg2 0 0 0))

(defn- dumpable
  "true or false on Linux; :unsupported elsewhere. Impure: reads the
   process's dumpable flag."
  []
  (if (= :linux (os))
    (let [r (prctl pr-get-dumpable 0)]
      (cond (neg? r) :unknown (zero? r) false :else true))
    :unsupported))

;; ---------------------------------------------------------------------------
;; HeapDumpOnOutOfMemoryError: HotSpot only, reached by reflection so that
;; bb (no such classes) simply reports :unsupported.
;; ---------------------------------------------------------------------------

#?(:clj
   (defn- hotspot-bean
     "The HotSpotDiagnosticMXBean, or nil where there is none (bb, other
      JVMs). Impure: reads the JVM's management beans."
     []
     (try
       (let [mf   (Class/forName "java.lang.management.ManagementFactory")
             bean (Class/forName "com.sun.management.HotSpotDiagnosticMXBean")]
         (.invoke (.getMethod mf "getPlatformMXBean" (into-array Class [Class]))
                  nil (object-array [bean])))
       (catch Throwable _ nil))))

(defn- heap-dump-on-oom
  "true or false on a HotSpot JVM; :unsupported elsewhere. Impure: reads
   the JVM's flag."
  []
  #?(:clj  (if-let [b (hotspot-bean)]
             (try (= "true" (.getValue (.getVMOption b "HeapDumpOnOutOfMemoryError")))
                  (catch Throwable _ :unsupported))
             :unsupported)
     :cljs :unsupported))

(defn- disable-heap-dump-on-oom!
  "Set HeapDumpOnOutOfMemoryError to false. :disabled, :unsupported or
   :failed. Impure: writes the JVM's flag."
  []
  #?(:clj  (if-let [b (hotspot-bean)]
             (try (.setVMOption b "HeapDumpOnOutOfMemoryError" "false") :disabled
                  (catch Throwable _ :failed))
             :unsupported)
     :cljs :unsupported))

;; ---------------------------------------------------------------------------
;; Public API
;; ---------------------------------------------------------------------------

(defn process-status
  "The current settings harden-process! can change:

     {:os               :mac | :linux | :other
      :core-dumps       {:soft n-or-:unlimited :hard n-or-:unlimited} or :unknown
      :dumpable         true | false | :unsupported | :unknown
      :heap-dump-on-oom true | false | :unsupported}

   Impure: reads the process's resource limits and attributes, and the
   JVM's flags. Never throws."
  []
  {:os               (os)
   :core-dumps       (or (try (core-limit) (catch #?(:clj Throwable :cljs :default) _ nil)) :unknown)
   :dumpable         (try (dumpable) (catch #?(:clj Throwable :cljs :default) _ :unknown))
   :heap-dump-on-oom (heap-dump-on-oom)})

(def ^:private options #{:core-dumps :dumpable :heap-dump-on-oom})

(defn harden-process!
  "Apply the hardening options asked for, e.g.
     (harden-process! {:core-dumps false :dumpable false})
   and return what happened to each: :disabled, :unsupported (not on this
   OS or runtime) or :failed. See the namespace docstring for the options
   and what each one costs. Nothing is changed unless asked for, and
   :core-dumps false cannot be undone within the process.

   Impure: writes process settings (resource limits, the dumpable flag,
   the JVM's flags).
   Throws ex-info {:type ::bad-option} for an unknown option or a value
   other than false (only disabling is offered), before changing anything."
  [opts]
  (doseq [[k v] opts]
    (when-not (and (options k) (false? v))
      (throw (ex-info (str "harden-process!: unknown option or value " (pr-str [k v])
                           " (options: " (str/join ", " (sort options)) ", each with false)")
                      {:type ::bad-option :option k :value v}))))
  (cond-> {}
    (contains? opts :core-dumps)
    (assoc :core-dumps (try (if (disable-core-dumps!) :disabled :failed)
                            (catch #?(:clj Throwable :cljs :default) _ :failed)))

    (contains? opts :dumpable)
    (assoc :dumpable (if (= :linux (os))
                       (try (if (zero? (prctl pr-set-dumpable 0)) :disabled :failed)
                            (catch #?(:clj Throwable :cljs :default) _ :failed))
                       :unsupported))

    (contains? opts :heap-dump-on-oom)
    (assoc :heap-dump-on-oom (disable-heap-dump-on-oom!))))
