use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::{
    AlgorithmParameters, EllipticCurve, Jwk, KeyAlgorithm, KeyOperations, PublicKeyUse,
};
use jsonwebtoken::{Algorithm, DecodingKey, Header};
use serde::Deserialize;
use tokio::sync::Mutex;

use super::error::Error;

/// Matches jose's `createRemoteJWKSet` defaults.
const JWKS_CACHE_MAX_AGE: Duration = Duration::from_secs(10 * 60);
const JWKS_COOLDOWN: Duration = Duration::from_secs(30);
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct Discovery {
    pub(crate) issuer: String,
    pub(crate) jwks: RemoteJwks,
}

#[derive(Deserialize)]
struct OpenIdConfiguration {
    issuer: Option<String>,
    jwks_uri: Option<String>,
}

#[derive(Deserialize)]
struct RawJwkSet {
    keys: Vec<serde_json::Value>,
}

impl Discovery {
    pub(crate) async fn fetch(
        client: &reqwest::Client,
        discovery_url: String,
    ) -> Result<Self, Error> {
        let discovery_url = discovery_url.as_str();
        tracing::info!(discovery_url, "Fetching OIDC discovery configuration");

        let response = client
            .get(discovery_url)
            .timeout(HTTP_TIMEOUT)
            .send()
            .await?;
        let status = response.status();

        if !status.is_success() {
            tracing::error!(
                discovery_url,
                status = status.as_u16(),
                "OIDC discovery request failed"
            );

            return Err(Error::DiscoveryStatus(status.as_u16()));
        }

        let configuration: OpenIdConfiguration = response.json().await?;
        let issuer = configuration.issuer.filter(|value| !value.is_empty());
        let jwks_uri = configuration.jwks_uri.filter(|value| !value.is_empty());

        let (Some(issuer), Some(jwks_uri)) = (issuer.clone(), jwks_uri.clone()) else {
            tracing::error!(
                has_issuer = issuer.is_some(),
                has_jwks_uri = jwks_uri.is_some(),
                "OIDC discovery response is missing required fields"
            );

            return Err(Error::DiscoveryIncomplete);
        };

        tracing::info!(%issuer, %jwks_uri, "OIDC discovery configuration loaded");

        Ok(Self {
            issuer,
            jwks: RemoteJwks {
                client: client.clone(),
                uri: jwks_uri,
                max_age: JWKS_CACHE_MAX_AGE,
                cooldown: JWKS_COOLDOWN,
                state: Mutex::default(),
            },
        })
    }
}

/// A JSON Web Key Set fetched on demand and refreshed when stale or when no key matches.
pub(crate) struct RemoteJwks {
    client: reqwest::Client,
    uri: String,
    max_age: Duration,
    cooldown: Duration,
    state: Mutex<JwksState>,
}

#[derive(Default)]
struct JwksState {
    cached: Option<CachedJwks>,
    last_fetch_attempt: Option<Instant>,
}

struct CachedJwks {
    fetched_at: Instant,
    keys: Vec<Arc<JwksKey>>,
}

/// A key from the set, decoded once when the set is fetched.
pub(crate) struct JwksKey {
    jwk: Jwk,
    pub(crate) decoding_key: DecodingKey,
}

impl RemoteJwks {
    /// Returns the keys that can verify a token with `header`.
    ///
    /// The set is refreshed when it is older than the max age, or when no key matches so that
    /// rotated keys are picked up, at most once per cooldown. Once a set has been fetched, a
    /// failed refresh is logged and the cached keys keep being used.
    pub(crate) async fn candidate_keys(&self, header: &Header) -> Result<Vec<Arc<JwksKey>>, Error> {
        let mut state = self.state.lock().await;

        let Some(cached) = &state.cached else {
            // Nothing to fall back to, so the first fetch must succeed.
            return self.reload(&mut state, header).await;
        };

        let candidates = select_keys(&cached.keys, header);
        let needs_refresh = candidates.is_empty() || cached.fetched_at.elapsed() >= self.max_age;
        let in_cooldown = state
            .last_fetch_attempt
            .is_some_and(|attempt| attempt.elapsed() < self.cooldown);

        if needs_refresh && !in_cooldown {
            match self.reload(&mut state, header).await {
                Ok(reloaded) => return Ok(reloaded),
                Err(error) => {
                    tracing::warn!(error = %error, "JWKS refresh failed; using cached keys");
                }
            }
        }

        Ok(candidates)
    }

    async fn reload(
        &self,
        state: &mut JwksState,
        header: &Header,
    ) -> Result<Vec<Arc<JwksKey>>, Error> {
        state.last_fetch_attempt = Some(Instant::now());

        let cached = self.fetch().await?;
        let candidates = select_keys(&cached.keys, header);
        state.cached = Some(cached);

        Ok(candidates)
    }

    async fn fetch(&self) -> Result<CachedJwks, Error> {
        tracing::debug!(jwks_uri = %self.uri, "Fetching JWKS");

        let response = self
            .client
            .get(&self.uri)
            .timeout(HTTP_TIMEOUT)
            .send()
            .await?;
        let status = response.status();

        if !status.is_success() {
            tracing::error!(jwks_uri = %self.uri, status = status.as_u16(), "JWKS request failed");

            return Err(Error::JwksStatus(status.as_u16()));
        }

        let raw: RawJwkSet = response.json().await.map_err(|_| Error::JwksInvalid)?;
        // Parse keys individually so one unsupported key doesn't invalidate the whole set.
        let keys = raw
            .keys
            .into_iter()
            .filter_map(|key| {
                let jwk: Jwk = serde_json::from_value(key).ok()?;
                let decoding_key = DecodingKey::from_jwk(&jwk).ok()?;

                Some(Arc::new(JwksKey { jwk, decoding_key }))
            })
            .collect();

        Ok(CachedJwks {
            fetched_at: Instant::now(),
            keys,
        })
    }
}

/// Mirrors jose's JWKS key selection: kid, key type, curve, `alg`, `use`, and `key_ops` must all
/// be compatible with the token header.
fn select_keys(keys: &[Arc<JwksKey>], header: &Header) -> Vec<Arc<JwksKey>> {
    keys.iter()
        .filter(|key| key_matches_header(&key.jwk, header))
        .cloned()
        .collect()
}

fn key_matches_header(jwk: &Jwk, header: &Header) -> bool {
    let common = &jwk.common;

    header
        .kid
        .as_ref()
        .is_none_or(|kid| common.key_id.as_ref() == Some(kid))
        && key_supports_algorithm(jwk, header.alg)
        && common
            .key_algorithm
            .is_none_or(|key_alg| signing_algorithm(key_alg) == Some(header.alg))
        && common
            .public_key_use
            .as_ref()
            .is_none_or(|key_use| *key_use == PublicKeyUse::Signature)
        && common
            .key_operations
            .as_ref()
            .is_none_or(|ops| ops.contains(&KeyOperations::Verify))
}

/// Maps a JWK `alg` to the JWS algorithm it signs with; encryption algorithms map to `None`.
fn signing_algorithm(key_algorithm: KeyAlgorithm) -> Option<Algorithm> {
    match key_algorithm {
        KeyAlgorithm::HS256 => Some(Algorithm::HS256),
        KeyAlgorithm::HS384 => Some(Algorithm::HS384),
        KeyAlgorithm::HS512 => Some(Algorithm::HS512),
        KeyAlgorithm::ES256 => Some(Algorithm::ES256),
        KeyAlgorithm::ES384 => Some(Algorithm::ES384),
        KeyAlgorithm::RS256 => Some(Algorithm::RS256),
        KeyAlgorithm::RS384 => Some(Algorithm::RS384),
        KeyAlgorithm::RS512 => Some(Algorithm::RS512),
        KeyAlgorithm::PS256 => Some(Algorithm::PS256),
        KeyAlgorithm::PS384 => Some(Algorithm::PS384),
        KeyAlgorithm::PS512 => Some(Algorithm::PS512),
        KeyAlgorithm::EdDSA => Some(Algorithm::EdDSA),
        _ => None,
    }
}

fn key_supports_algorithm(jwk: &Jwk, alg: Algorithm) -> bool {
    match (&jwk.algorithm, alg) {
        (
            AlgorithmParameters::RSA(_),
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512,
        ) => true,
        (AlgorithmParameters::EllipticCurve(params), Algorithm::ES256) => {
            params.curve == EllipticCurve::P256
        }
        (AlgorithmParameters::EllipticCurve(params), Algorithm::ES384) => {
            params.curve == EllipticCurve::P384
        }
        (AlgorithmParameters::OctetKeyPair(params), Algorithm::EdDSA) => {
            params.curve == EllipticCurve::Ed25519
        }
        // Symmetric (HS*) tokens are never accepted from a remote key set.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn jwk(value: serde_json::Value) -> Jwk {
        serde_json::from_value(value).unwrap()
    }

    fn header(alg: Algorithm, kid: Option<&str>) -> Header {
        Header {
            kid: kid.map(str::to_owned),
            ..Header::new(alg)
        }
    }

    const X: &str = "NrZMG8kCniR52o4PIUzwfG_tFhkBerv4uLjpuXBm4zY";
    const Y: &str = "LPx0qdr48k3QbpZq9FnfCl6FUKrx_udYSCZ5mCEK2kA";

    #[test]
    fn selects_keys_compatible_with_the_token_header() {
        let keys = [
            jwk(json!({ "kty": "EC", "crv": "P-256", "x": X, "y": Y, "kid": "a" })),
            jwk(json!({ "kty": "EC", "crv": "P-256", "x": X, "y": Y, "kid": "b", "use": "enc" })),
            jwk(json!({ "kty": "EC", "crv": "P-256", "x": X, "y": Y, "kid": "c", "alg": "ES384" })),
            jwk(
                json!({ "kty": "EC", "crv": "P-256", "x": X, "y": Y, "kid": "d", "key_ops": ["sign"] }),
            ),
            jwk(json!({ "kty": "RSA", "n": "AQAB", "e": "AQAB", "kid": "e" })),
        ];
        let kids = |header: &Header| -> Vec<String> {
            keys.iter()
                .filter(|jwk| key_matches_header(jwk, header))
                .filter_map(|jwk| jwk.common.key_id.clone())
                .collect()
        };

        assert_eq!(kids(&header(Algorithm::ES256, None)), ["a"]);
        assert_eq!(kids(&header(Algorithm::ES256, Some("a"))), ["a"]);
        assert!(kids(&header(Algorithm::ES256, Some("missing"))).is_empty());
        assert!(kids(&header(Algorithm::ES384, Some("c"))).is_empty());
        assert_eq!(kids(&header(Algorithm::RS256, None)), ["e"]);
        assert!(kids(&header(Algorithm::HS256, None)).is_empty());
    }

    /// A key set server that serves one key on the first request and 503 afterwards.
    async fn flaky_jwks_server() -> wiremock::MockServer {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "keys": [{ "kty": "EC", "crv": "P-256", "x": X, "y": Y, "kid": "current" }],
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        server
    }

    fn remote_jwks(
        server: &wiremock::MockServer,
        max_age: Duration,
        cooldown: Duration,
    ) -> RemoteJwks {
        RemoteJwks {
            client: reqwest::Client::new(),
            uri: server.uri(),
            max_age,
            cooldown,
            state: Mutex::default(),
        }
    }

    async fn candidate_count(jwks: &RemoteJwks, kid: &str) -> usize {
        jwks.candidate_keys(&header(Algorithm::ES256, Some(kid)))
            .await
            .unwrap()
            .len()
    }

    async fn request_count(server: &wiremock::MockServer) -> usize {
        server.received_requests().await.unwrap().len()
    }

    #[tokio::test]
    async fn fails_when_the_first_fetch_fails() {
        let server = flaky_jwks_server().await;
        // Use up the server's one successful response so the next fetch gets a 503.
        reqwest::get(server.uri()).await.unwrap();
        let jwks = remote_jwks(&server, JWKS_CACHE_MAX_AGE, JWKS_COOLDOWN);

        assert!(matches!(
            jwks.candidate_keys(&header(Algorithm::ES256, Some("current")))
                .await,
            Err(Error::JwksStatus(503))
        ));
    }

    #[tokio::test]
    async fn returns_no_keys_instead_of_failing_when_an_unknown_kid_reload_fails() {
        let server = flaky_jwks_server().await;
        let jwks = remote_jwks(&server, JWKS_CACHE_MAX_AGE, Duration::ZERO);

        assert_eq!(candidate_count(&jwks, "current").await, 1);
        assert_eq!(candidate_count(&jwks, "rotated").await, 0);
        assert_eq!(candidate_count(&jwks, "current").await, 1);
        assert_eq!(request_count(&server).await, 2);
    }

    #[tokio::test]
    async fn serves_stale_keys_when_a_refresh_fails() {
        let server = flaky_jwks_server().await;
        let jwks = remote_jwks(&server, Duration::ZERO, Duration::ZERO);

        assert_eq!(candidate_count(&jwks, "current").await, 1);
        assert_eq!(candidate_count(&jwks, "current").await, 1);
        assert_eq!(candidate_count(&jwks, "current").await, 1);
        assert_eq!(request_count(&server).await, 3);
    }

    #[tokio::test]
    async fn waits_for_the_cooldown_before_refreshing_again() {
        let server = flaky_jwks_server().await;
        let jwks = remote_jwks(&server, Duration::ZERO, JWKS_COOLDOWN);

        // The first fetch starts the cooldown, so neither the stale set nor the unknown kid
        // triggers another request.
        assert_eq!(candidate_count(&jwks, "current").await, 1);
        assert_eq!(candidate_count(&jwks, "current").await, 1);
        assert_eq!(candidate_count(&jwks, "rotated").await, 0);
        assert_eq!(request_count(&server).await, 1);
    }

    #[test]
    fn maps_key_algorithms_to_signing_algorithms() {
        assert_eq!(
            signing_algorithm(KeyAlgorithm::ES256),
            Some(Algorithm::ES256)
        );
        assert_eq!(
            signing_algorithm(KeyAlgorithm::EdDSA),
            Some(Algorithm::EdDSA)
        );
        assert_eq!(signing_algorithm(KeyAlgorithm::RSA_OAEP), None);
    }
}
