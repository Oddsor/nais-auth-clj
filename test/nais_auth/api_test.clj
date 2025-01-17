(ns nais-auth.api-test
  (:require
    [babashka.http-client :as http]
    [charred.api :as charred]
    [clojure.test :refer [deftest is testing use-fixtures]]
    [nais-auth.api :as sut])
  (:import
    [no.nav.security.mock.oauth2 MockOAuth2Server OAuth2Config]
    [no.nav.security.mock.oauth2.token DefaultOAuth2TokenCallback]))

(def ^:dynamic *server* nil)

(defn with-server [f]
  (let [server (MockOAuth2Server. (OAuth2Config.))]
    (try
      (MockOAuth2Server/.start server)
      (binding [*server* server]
        (f))
      (finally
        (MockOAuth2Server/.shutdown server)))))

(use-fixtures :once with-server)

(defn get-token [^String issuer]
  (.serialize (MockOAuth2Server/.issueToken *server* issuer "client1" (DefaultOAuth2TokenCallback.))))

(deftest can-verify-token-test
  (testing "Test if a token provided by a mock-server can be validated using its public jwk"
    (let [issuer "default"
          well-known-url (str (MockOAuth2Server/.wellKnownUrl *server* issuer))
          well-known-data (-> (http/request {:method :get
                                             :uri    well-known-url
                                             :as     :stream})
                              :body
                              (charred/read-json :key-fn keyword))]
      (is (some? (sut/verify-token (sut/get-consumer (:jwks_uri well-known-data) ["default"])
                                   (get-token issuer))))

      (is (nil? (sut/verify-token (sut/get-consumer (:jwks_uri well-known-data) ["default"])
                                   (get-token "bad")))))))
