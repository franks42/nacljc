;; Loaded as a script by test/loading/run.clj on bb, nbb and the JVM, under
;; different library configurations. Prints one EDN map: {:ok version} or
;; the nacljc error that stopped nacljc.core from loading.

(defn- nacljc-error
  "The first exception in e's cause chain whose ::type is a nacljc one
   (nbb wraps load errors in :sci/error)."
  [e]
  (loop [e e]
    (cond (nil? e) nil
          (= "nacljc.core" (some-> (ex-data e) :type namespace)) e
          :else (recur (ex-cause e)))))

(defn- report [e]
  (if-let [c (nacljc-error e)]
    (prn (merge {:error (:type (ex-data c)) :message (ex-message c)}
                (select-keys (ex-data c) [:tried :source :path])))
    (prn {:error :unexpected :message (ex-message e)})))

#?(:clj  (try (require 'nacljc.core)
              (prn {:ok ((resolve 'nacljc.core/libsodium-version))})
              (catch Throwable e (report e)))
   :cljs (-> (js/Promise.resolve nil)
             (.then (fn [_] (require '[nacljc.core])))
             (.then (fn [_] (prn {:ok ((resolve 'nacljc.core/libsodium-version))})))
             (.catch report)))
