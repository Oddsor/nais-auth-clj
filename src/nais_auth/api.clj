(ns nais-auth.api
  (:import
    [org.jose4j.jwk HttpsJwks]
    [org.jose4j.jwt JwtClaims]
    [org.jose4j.jwt.consumer InvalidJwtException JwtConsumer JwtConsumerBuilder]
    [org.jose4j.keys.resolvers HttpsJwksVerificationKeyResolver]))

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

(comment (verify-token nil nil))
