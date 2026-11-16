#![allow(dead_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use mondo_lambda_authorizer::rest_api::{ApiGatewayCustomAuthorizerRequest, Config};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

pub const AUDIENCE: &str = "https://app.mondoidentity.com";
pub const METHOD_ARN: &str =
    "arn:aws:execute-api:us-east-1:123456789012:a1b2c3d4e5/prod/GET/customers/123";
pub const PRIVATE_KEY: &[u8] = include_bytes!("../fixtures/es256-private.pem");
pub const PUBLIC_X: &str = "NrZMG8kCniR52o4PIUzwfG_tFhkBerv4uLjpuXBm4zY";
pub const PUBLIC_Y: &str = "LPx0qdr48k3QbpZq9FnfCl6FUKrx_udYSCZ5mCEK2kA";
/// Mondo Identity signs with RS256.
pub const RSA_PRIVATE_KEY: &[u8] = include_bytes!("../fixtures/rs256-private.pem");
pub const RSA_PUBLIC_N: &str = "lo97HYEvyWoaxsZ3_zITtacPIJRhJdR3tP1Dp6EiIjQ82x0_W292dOGvpaA8grV4ApoJnBBQ8tOQ_2-WwY2H8pGwBMqOynTHsBikZz4rdlcO_wwsktu_NpxtQLZyr1eUqeu0q7sEicR7C3WXv4BrCzafns9R6ygC1mexKolgO4zCMsp4Ruo6c24a1YLrTuTlGESwdA5Z1L5Ny32HQ7FV4Vd_qC64I8ZUjdiohAso6L_zC1AMSoVGhDSAKmje5uPEXFr7xmFOQ3Ot59PUa_-L_2mXmRuh78ZvBTDCwYvP7ZSL3LmxcnG6PD0qptIJhCpDFl0HfKIfpwp_4zsEYiD7KQ";

pub struct Idp {
    pub server: MockServer,
}

impl Idp {
    pub async fn start() -> Self {
        let server = MockServer::start().await;
        let issuer = server.uri();

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": issuer,
                "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "keys": [
                    { "kty": "RSA", "kid": "unsupported", "alg": "RSA-OAEP-256", "use": "enc" },
                    {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": PUBLIC_X,
                        "y": PUBLIC_Y,
                        "alg": "ES256",
                        "kid": "test-key",
                        "use": "sig",
                    },
                    {
                        "kty": "RSA",
                        "n": RSA_PUBLIC_N,
                        "e": "AQAB",
                        "alg": "RS256",
                        "kid": "rsa-key",
                        "use": "sig",
                    },
                ],
            })))
            .mount(&server)
            .await;

        Self { server }
    }

    pub fn issuer(&self) -> String {
        self.server.uri()
    }

    pub fn config(&self) -> Config {
        Config::new(self.issuer(), [AUDIENCE])
    }

    pub fn token(&self, overrides: Value) -> String {
        sign(&self.claims(overrides), "test-key")
    }

    pub fn rs256_token(&self, overrides: Value) -> String {
        sign_rs256(&self.claims(overrides), "rsa-key")
    }

    pub fn claims(&self, overrides: Value) -> Value {
        let mut claims = json!({
            "aud": AUDIENCE,
            "azp": "app_123",
            "exp": now() + 300,
            "iss": self.issuer(),
            "sub": "usr_123",
            "tnt": "tnt_123",
        });
        claims
            .as_object_mut()
            .unwrap()
            .extend(overrides.as_object().unwrap().clone());
        claims
    }
}

pub fn sign(claims: &Value, kid: &str) -> String {
    let header = Header {
        kid: Some(kid.to_owned()),
        ..Header::new(Algorithm::ES256)
    };

    jsonwebtoken::encode(
        &header,
        claims,
        &EncodingKey::from_ec_pem(PRIVATE_KEY).unwrap(),
    )
    .unwrap()
}

pub fn sign_rs256(claims: &Value, kid: &str) -> String {
    let header = Header {
        kid: Some(kid.to_owned()),
        ..Header::new(Algorithm::RS256)
    };

    jsonwebtoken::encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY).unwrap(),
    )
    .unwrap()
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn event(token: &str) -> ApiGatewayCustomAuthorizerRequest {
    event_with_authorization(&format!("Bearer {token}"))
}

pub fn event_with_authorization(authorization: &str) -> ApiGatewayCustomAuthorizerRequest {
    // The type is `#[non_exhaustive]`, so it can't be built with a struct literal.
    let mut event = ApiGatewayCustomAuthorizerRequest::default();
    event.type_ = Some("TOKEN".to_owned());
    event.authorization_token = Some(authorization.to_owned());
    event.method_arn = Some(METHOD_ARN.to_owned());
    event
}
