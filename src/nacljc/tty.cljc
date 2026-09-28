(ns nacljc.tty
  "Read a password from the terminal straight into guarded memory.

     (read-password \"Vault password: \")                     → a secret
     (read-password \"New password: \" {:confirm \"Again: \"})  ; read twice
     (read-password-fd 0)                                   ; a pipe or file (no terminal)

   The password never exists as a String or a byte array on the heap: the
   terminal's bytes go from read(2) into sodium_malloc memory, and the
   newline and ^C are found there with memchr, so no password byte passes
   through a Clojure value. The result is a nacljc secret (destroy it when
   done, or hand it to a function that consumes it).

   How: open /dev/tty (the terminal even when stdin is a pipe), switch off
   ECHO and ISIG with tcsetattr (so ^C is a byte, not a signal that would
   kill the process with echo still off), and keep canonical mode, so the
   kernel does the line editing (backspace, ^U). The settings are restored
   in finally. A process killed by a signal while reading can leave echo
   off: `stty sane` repairs the terminal.

   Limits: keystrokes still pass through the kernel's terminal layer and
   the terminal emulator. The same password can be typed as different
   bytes on different systems (Unicode normalization: é as one code point
   or two); ASCII passwords or plain-word passphrases avoid that.

   Uses libc through babashka.ffi on the JVM, bb and nbb; macOS and Linux.
   Separate from nacljc.core, which binds libsodium only."
  (:require [babashka.ffi :as ffi]
            [nacljc.core :as na]))

;; ---------------------------------------------------------------------------
;; libc
;; ---------------------------------------------------------------------------

(def ^:private libc
  "The C library, loaded on first use. Impure (a delay): loads a library."
  (delay (ffi/load-system-library "c")))

(defn- libc-fn
  "The libc function c-name, bound over FFI. Impure: reads the library."
  [c-name argtypes rettype]
  (ffi/cfn @libc c-name argtypes rettype))

(defn- os
  "The operating system: :mac, :linux or :other. Impure: reads the os.name
   property (process.platform on nbb)."
  []
  (let [s (str #?(:clj (System/getProperty "os.name") :cljs js/process.platform))]
    (cond (re-find #"(?i)mac|darwin" s) :mac
          (re-find #"(?i)linux" s)      :linux
          :else                         :other)))

(def ^:private new-secret!
  "nacljc.core's secret allocator: (new-secret! n fill!) calls fill! with
   the read-write memory."
  @#'nacljc.core/new-secret!)

(def ^:private o-rdwr 2)
(def ^:private tcsaflush 2)

;; struct termios: the local-flags word (c_lflag), and the flags we clear.
;; macOS: tcflag_t is unsigned long (8 bytes), c_lflag at offset 24;
;; Linux: unsigned int (4 bytes), c_lflag at offset 12. Both are read and
;; written as a 32-bit :int: the flags we change are in the low 32 bits,
;; which come first on the little-endian CPUs both platforms run on
;; (x86-64, arm64), and nbb would read a 64-bit word as a BigInt.
(defn- lflag-layout
  "{:offset :type :echo :isig} for this OS. Impure: reads the OS name.
   Throws ex-info {:type ::unsupported} elsewhere."
  []
  (case (os)
    :mac   {:offset 24 :type :int  :echo 0x8 :isig 0x80}
    :linux {:offset 12 :type :int  :echo 0x8 :isig 0x1}
    (throw (ex-info "nacljc.tty: terminal input needs macOS or Linux" {:type ::unsupported}))))

(def ^:private termios-size
  "Generous: 72 bytes on macOS, 60 on Linux."
  256)

;; ---------------------------------------------------------------------------
;; Reading a line into guarded memory
;; ---------------------------------------------------------------------------

(def ^:private max-length 1024)

(defn- pointer-offset
  "The offset of pointer q from pointer p, or nil when q is null. Pure."
  [p q]
  (when-not (ffi/null? q) (- (ffi/address q) (ffi/address p))))

(defn- read-line-into!
  "Read one line from fd into p (max bytes): until a newline, the end of
   the input, or max bytes. Returns the line's length (without the
   newline, and without a carriage return before it). The bytes are
   checked with memchr inside p, never copied out.
   Impure: reads fd, writes p.
   Throws ex-info {:type ::interrupted} for ^C, {:type ::too-long} when no
   newline comes within max bytes, and {:type ::read-failed}."
  [fd p max]
  (let [read-fn   (libc-fn "read" [:int :pointer :ulong] :long)
        memchr-fn (libc-fn "memchr" [:pointer :int :ulong] :pointer)]
    (loop [n 0]
      (let [r (read-fn fd (ffi/slice p n (- max n)) (- max n))]
        (if (neg? r)
          (throw (ex-info "nacljc.tty: read failed" {:type ::read-failed}))
          (let [n'  (+ n r)
                nl  (pointer-offset p (memchr-fn p 10 n'))
                end (or nl n')]
            (when (pointer-offset p (memchr-fn p 3 end))
              (throw (ex-info "nacljc.tty: interrupted (^C)" {:type ::interrupted})))
            (cond
              nl          (let [cr (pointer-offset p (memchr-fn p 13 nl))]
                            (if (and cr (= cr (dec nl))) cr nl))
              (zero? r)   n'                                   ; end of input
              (= n' max)  (throw (ex-info (str "nacljc.tty: longer than " max " bytes") {:type ::too-long}))
              :else       (recur n'))))))))

(defn- line-secret
  "A secret holding one line read from fd, of its exact length.
   Impure: reads fd, allocates guarded memory.
   Throws ex-info {:type ::empty} for an empty line, and what
   read-line-into! throws."
  [fd]
  (let [len (volatile! 0)
        big (new-secret! max-length #(vreset! len (read-line-into! fd % max-length)))]
    (try
      (when (zero? @len)
        (throw (ex-info "nacljc.tty: empty password" {:type ::empty})))
      (let [[s rest] (na/secret-split big [@len (- max-length @len)])]
        (na/secret-destroy! rest)
        s)
      (finally (na/secret-destroy! big)))))

;; ---------------------------------------------------------------------------
;; The terminal
;; ---------------------------------------------------------------------------

(defn- write-str!
  "Write s (not secret: a prompt) to fd. Impure: writes fd."
  [fd s]
  (let [arena (ffi/confined-arena)]
    (try
      (let [bs #?(:clj (.getBytes ^String s "UTF-8") :cljs (let [u (.encode (js/TextEncoder.) s)] (js/Int8Array. (.-buffer u) (.-byteOffset u) (.-length u))))
            n  #?(:clj (alength ^bytes bs) :cljs (.-length bs))]
        (when (pos? n)
          (let [p (ffi/alloc arena n)]
            (ffi/write-array p :char bs)
            ((libc-fn "write" [:int :pointer :ulong] :long) fd p n))))
      (finally (.close arena)))))

(defn- with-tty
  "Open /dev/tty, switch off ECHO and ISIG, call (f fd), and restore the
   settings and close it, whatever happens.
   Impure: opens the terminal and changes its settings for the call.
   Throws ex-info {:type ::no-tty} when the process has no terminal."
  [f]
  (let [{:keys [offset type echo isig]} (lflag-layout)
        arena (ffi/confined-arena)]
    (try
      (let [fd ((libc-fn "open" [:pointer :int] :int) (ffi/string->ptr arena "/dev/tty") o-rdwr)]
        (when (neg? fd)
          (throw (ex-info "nacljc.tty: no terminal (/dev/tty); use read-password-fd, or an agent"
                          {:type ::no-tty})))
        (try
          (let [saved (ffi/alloc arena termios-size)
                raw   (ffi/alloc arena termios-size)
                tcget (libc-fn "tcgetattr" [:int :pointer] :int)
                tcset (libc-fn "tcsetattr" [:int :int :pointer] :int)]
            (when-not (zero? (tcget fd saved))
              (throw (ex-info "nacljc.tty: /dev/tty is not a terminal" {:type ::no-tty})))
            (ffi/copy saved raw termios-size)
            (ffi/write raw type (bit-and-not (ffi/read raw type offset) (bit-or echo isig)) offset)
            (tcset fd tcsaflush raw)
            (try (f fd)
                 (finally
                   (tcset fd tcsaflush saved)
                   (write-str! fd "\n"))))
          (finally ((libc-fn "close" [:int] :int) fd))))
      (finally (.close arena)))))

(defn- ^{:clj-kondo/ignore [:unused-private-var]} terminal-flags
  "The terminal's local-flags word (c_lflag), for tests: it must be the
   same before and after a read. Impure: reads the terminal settings.
   Throws ex-info {:type ::no-tty}."
  []
  (let [{:keys [offset type]} (lflag-layout)
        arena (ffi/confined-arena)]
    (try
      (let [fd ((libc-fn "open" [:pointer :int] :int) (ffi/string->ptr arena "/dev/tty") o-rdwr)]
        (when (neg? fd) (throw (ex-info "nacljc.tty: no terminal" {:type ::no-tty})))
        (try
          (let [t (ffi/alloc arena termios-size)]
            ((libc-fn "tcgetattr" [:int :pointer] :int) fd t)
            (ffi/read t type offset))
          (finally ((libc-fn "close" [:int] :int) fd))))
      (finally (.close arena)))))

;; ---------------------------------------------------------------------------
;; Public API
;; ---------------------------------------------------------------------------

(defn read-password
  "Show prompt on the terminal and read a password without echo, straight
   into guarded memory. Returns a nacljc secret with the bytes typed (the
   terminal's encoding, normally UTF-8), without the newline.

   opts:
     :confirm  a second prompt: the password is read twice and the two
               compared (constant time); on a mismatch both are destroyed.

   Line editing (backspace, ^U) is the terminal's own. ^C ends the read.
   Impure: reads the terminal and changes its settings during the call,
   allocates guarded memory.
   Throws ex-info {:type ::no-tty} when the process has no terminal (an
   editor's REPL, CI, a service), {:type ::interrupted} for ^C,
   {:type ::empty} for an empty password, {:type ::too-long} beyond 1024
   bytes, {:type ::mismatch} when the confirmation differs, and
   {:type ::unsupported} outside macOS and Linux."
  ([prompt] (read-password prompt nil))
  ([prompt {:keys [confirm]}]
   (let [read-one #(with-tty (fn [fd] (write-str! fd %) (line-secret fd)))
         s        (read-one prompt)]
     (if-not confirm
       s
       (let [s2 (try (read-one confirm)
                     (catch #?(:clj Throwable :cljs :default) e (na/secret-destroy! s) (throw e)))]
         (try
           (if (na/constant-time-equal? s s2)
             s
             (do (na/secret-destroy! s)
                 (throw (ex-info "nacljc.tty: the passwords do not match" {:type ::mismatch}))))
           (finally (na/secret-destroy! s2))))))))

(defn read-password-fd
  "Read a password from file descriptor fd (0 is stdin: a pipe, a file,
   systemd credentials) up to the first newline or the end, straight into
   guarded memory; bytes after the newline in the same read are dropped
   (wiped). No prompt, no terminal settings.
   Impure: reads fd, allocates guarded memory.
   Throws ex-info {:type ::empty}, {:type ::too-long}, {:type ::interrupted}
   (a ^C byte), and {:type ::read-failed}."
  [fd]
  (line-secret fd))
