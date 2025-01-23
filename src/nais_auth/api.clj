(ns nais-auth.api
  (:import
   [java.net URI URLEncoder]
   [java.nio.charset StandardCharsets]
   [java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers HttpResponse HttpResponse$BodyHandlers]
   [org.jose4j.jwk HttpsJwks]
   [org.jose4j.jwt JwtClaims]
   [org.jose4j.jwt.consumer InvalidJwtException JwtConsumer JwtConsumerBuilder]
   [org.jose4j.keys.resolvers HttpsJwksVerificationKeyResolver]))

(def http-client (HttpClient/newHttpClient))

(defn get-consumer ^JwtConsumer [jwk-url expected-audiences]
  (assert (string? jwk-url) "jwk-url should be a string")
  (assert (coll? expected-audiences) "expected-audiences should be a list of strings")
  (-> (JwtConsumerBuilder.)
      (JwtConsumerBuilder/.setExpectedAudience (into-array String expected-audiences))
      (JwtConsumerBuilder/.setVerificationKeyResolver (HttpsJwksVerificationKeyResolver. (HttpsJwks. jwk-url)))
      JwtConsumerBuilder/.build))

(defn verify-token ^JwtClaims [^JwtConsumer consumer jwt-token]
  (try
    (->> (JwtConsumer/.processToClaims consumer jwt-token) (JwtClaims/.getClaimsMap) (into {}))
    (catch InvalidJwtException _
      nil)))

(defn make-form-data [data]
  (String/join "&" (map (fn [[k v]]
                          (str (URLEncoder/encode (cond-> k (keyword? k) name) StandardCharsets/UTF_8)
                               "="
                               (URLEncoder/encode v StandardCharsets/UTF_8))) data)))

(defn get-obo-token
  ([token scope]
   (let [env-vars {:token-url (System/getenv "AZURE_OPENID_CONFIG_TOKEN_ENDPOINT")
                   :client-id (System/getenv "AZURE_APP_CLIENT_ID")
                   :client-secret (System/getenv "AZURE_APP_CLIENT_SECRET")}]
     (get-obo-token env-vars token scope)))
  ([{:keys [token-url client-id client-secret] :as _config} token scope]
   (let [request (-> (HttpRequest/newBuilder)
                     (.uri (URI/create token-url))
                     (.header "Content-Type" "application/x-www-form-urlencoded")
                     (.POST (HttpRequest$BodyPublishers/ofString
                             (make-form-data
                              {:grant_type "urn:ietf:params:oauth:grant-type:jwt-bearer"
                               :client_id client-id
                               :client_secret client-secret
                               :assertion token
                               :scope scope
                               :requested_token_use "on_behalf_of"})
                             StandardCharsets/UTF_8))
                     (.build))
         result (HttpClient/.send http-client request (HttpResponse$BodyHandlers/ofString))]
     (when (= (HttpResponse/.statusCode result) 200)
       (let [body (HttpResponse/.body result)]
         (-> (re-seq #"\"access_token\".*?:.*?\"(.*?)\"" body)
             first
             second))))))

(defn wrap-authentication [handler & {:keys [jwk-url expected-audiences]}]
  (let [ensured-jwk-url (if jwk-url jwk-url (System/getenv "AZURE_OPENID_CONFIG_JWKS_URI"))
        consumer (get-consumer ensured-jwk-url expected-audiences)]
    (fn [req]
      (handler (if-let [auth (get-in req [:headers "authorization"])]
                 (let [verified-token (verify-token consumer (String/.replace auth "Bearer " ""))]
                   (assoc req :authorization verified-token))
                 req)))))
