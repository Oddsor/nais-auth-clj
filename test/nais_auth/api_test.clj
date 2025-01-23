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

(deftest can-produce-on-behalf-of-token
  (testing "Test if a on-behalf-of-token provided by a mock-server can be validated using its public jwk"
    (let [issuer "default"
          well-known-url (str (MockOAuth2Server/.wellKnownUrl *server* issuer))
          well-known-data (-> (http/request {:method :get
                                             :uri    well-known-url
                                             :as     :stream})
                              :body
                              (charred/read-json :key-fn keyword))
          token (get-token issuer)
          token-url (:token_endpoint well-known-data)]
      #_(http/request {:uri token-url
                       :method :post
                       :form-params {:grant_type "urn:ietf:params:oauth:grant-type:jwt-bearer"
                                     :client_id "1234567"
                                     :client_secret "1234567"
                                     :assertion token
                                     :scope "dev-gcp.arbeidsgiver.tiltaksgjennomforing"
                                     :requested_token_use "on_behalf_of"}})
      (is (some? (sut/verify-token (sut/get-consumer (:jwks_uri well-known-data) ["dev-gcp.arbeidsgiver.tiltaksgjennomforing"])
                                   (sut/get-obo-token {:token-url token-url
                                                       :client-id "123456"
                                                       :client-secret "123456"} token "dev-gcp.arbeidsgiver.tiltaksgjennomforing"))))

      (is (nil? (sut/verify-token (sut/get-consumer (:jwks_uri well-known-data) ["dev-gcp.arbeidsgiver.tiltaksgjennomforing"])
                                  (sut/get-obo-token {:token-url token-url
                                                      :client-id "123456"
                                                      :client-secret "123456"} token "bla")))))))

(deftest wrapper-can-auth-request
  (testing "Test if the ring middleware function can handle requests with an auth header"
    (let [issuer "default"
          well-known-url (str (MockOAuth2Server/.wellKnownUrl *server* issuer))
          well-known-data (-> (http/request {:method :get
                                             :uri    well-known-url
                                             :as     :stream})
                              :body
                              (charred/read-json :key-fn keyword))
          token (get-token issuer)
          auth-holder (volatile! nil)
          handler (sut/wrap-authentication (fn [req]
                                             (vreset! auth-holder (-> req :authorization))
                                             {:status 200
                                              :body "Ok!"})
                                           {:jwk-url (:jwks_uri well-known-data)
                                            :expected-audiences ["default"]})]
      #_(http/request {:uri token-url
                       :method :post
                       :form-params {:grant_type "urn:ietf:params:oauth:grant-type:jwt-bearer"
                                     :client_id "1234567"
                                     :client_secret "1234567"
                                     :assertion token
                                     :scope "dev-gcp.arbeidsgiver.tiltaksgjennomforing"
                                     :requested_token_use "on_behalf_of"}})
      (handler {:uri "/"
                :method :get
                :headers {"authorization" (str "Bearer " token)}})
      (is (some? @auth-holder))
      (vreset! auth-holder nil)

      (handler {:uri "/"
                :method :get
                :headers {}})
      (is (nil? @auth-holder)))))

(comment
  (with-server
    can-produce-on-behalf-of-token)
  (with-server
    wrapper-can-auth-request))
