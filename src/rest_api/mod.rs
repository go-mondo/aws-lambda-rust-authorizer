//! API Gateway REST API `TOKEN` authorizer for Mondo Identity.
//!
//! The [`Authorizer`] parses bearer tokens, discovers issuer and JWKS metadata from
//! `/.well-known/openid-configuration`, verifies JWTs, validates issuer, audience, and expiration,
//! then returns `tenantId`, `appId`, and `userId` in the authorizer context. Implement
//! [`AuthorizerHooks`] to add custom validation, context, or policy decisions.

mod claims;
mod config;
mod discovery;
mod error;
mod policy;

use std::future::Future;

use jsonwebtoken::Validation;
use lambda_runtime::{LambdaEvent, service_fn};
use serde_json::{Value, json};
use tokio::sync::OnceCell;

pub use claims::{
    ClaimExpectation, Claims, Context, ScalarValue, assert_required_claims, build_default_context,
    build_mapped_context, get_claim, get_scopes,
};
pub use config::Config;
pub use error::{BoxError, Error};
pub use policy::{
    AuthorizerResponse, PolicyDocument, PolicyEffect, PolicyStatement, PolicyStatementOverride,
    StringOrArray, TokenAuthorizerEvent, build_all_methods_resource,
};

use claims::safe_claim_log_context;
use discovery::Discovery;
use error::{error_log_context, unauthorized};

/// Principal used when a verified token has no `sub` claim.
const DEFAULT_PRINCIPAL_ID: &str = "mondo-user";

/// Bounds how much of a malformed authorization value is logged as its scheme.
const MAX_LOGGED_SCHEME_CHARS: usize = 16;

/// Callbacks that customize an [`Authorizer`]. They run after the token has been verified and the
/// configured required claims have been checked. Every method has a no-op default.
///
/// Returning an error from [`validate_claims`](Self::validate_claims) denies the request. Errors
/// from the other hooks fail the request with a 500, except [`Error::Unauthorized`]
/// (`Err(Error::Unauthorized.into())`), which denies it.
pub trait AuthorizerHooks: Send + Sync {
    fn validate_claims(
        &self,
        claims: &Claims,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        let _ = claims;
        async { Ok(()) }
    }

    /// Context merged over the default and `MONDO_CONTEXT_CLAIMS` context.
    fn build_additional_context(
        &self,
        claims: &Claims,
    ) -> impl Future<Output = Result<Context, BoxError>> + Send {
        let _ = claims;
        async { Ok(Context::new()) }
    }

    /// Fields merged over the `MONDO_POLICY_STATEMENT` policy statement.
    fn build_policy_statement(
        &self,
        input: PolicyInput<'_>,
    ) -> impl Future<Output = Result<PolicyStatementOverride, BoxError>> + Send {
        let _ = input;
        async { Ok(PolicyStatementOverride::default()) }
    }
}

/// Input to [`AuthorizerHooks::build_policy_statement`].
#[derive(Clone, Copy, Debug)]
pub struct PolicyInput<'a> {
    pub claims: &'a Claims,
    pub method_arn: &'a str,
}

/// The default [`AuthorizerHooks`], which adds nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoHooks;

impl AuthorizerHooks for NoHooks {}

/// A REST API token authorizer. Create one per Lambda execution environment so the OIDC discovery
/// document and JWKS are cached across invocations.
pub struct Authorizer<H = NoHooks> {
    config: Config,
    hooks: H,
    client: reqwest::Client,
    discovery: OnceCell<Discovery>,
}

impl Authorizer {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            hooks: NoHooks,
            client: reqwest::Client::new(),
            discovery: OnceCell::new(),
        }
    }

    /// Creates an authorizer configured from the `MONDO_*` environment variables.
    pub fn from_env() -> Result<Self, Error> {
        Ok(Self::new(Config::from_env()?))
    }
}

impl<H: AuthorizerHooks> Authorizer<H> {
    pub fn with_hooks<T: AuthorizerHooks>(self, hooks: T) -> Authorizer<T> {
        Authorizer {
            config: self.config,
            hooks,
            client: self.client,
            discovery: self.discovery,
        }
    }

    pub fn with_http_client(self, client: reqwest::Client) -> Self {
        Self {
            client,
            discovery: OnceCell::new(),
            ..self
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Authorizes a request. Denied requests return [`Error::Unauthorized`].
    pub async fn authorize(
        &self,
        event: &TokenAuthorizerEvent,
    ) -> Result<AuthorizerResponse, Error> {
        let result = self.try_authorize(event).await;

        if let Err(error) = &result
            && !error.is_unauthorized()
        {
            tracing::error!(error = %error, "Authorizer failed");
        }

        result
    }

    async fn try_authorize(
        &self,
        event: &TokenAuthorizerEvent,
    ) -> Result<AuthorizerResponse, Error> {
        let token = get_bearer_token(event.authorization_token.as_deref())?;
        let claims = self.verify_token(token).await?;

        tracing::info!(details = %safe_claim_log_context(&claims), "Token verified");

        assert_required_claims(&claims, &self.config.required_claims)?;
        self.hooks.validate_claims(&claims).await.map_err(|error| {
            let mut details = safe_claim_log_context(&claims);
            if let (Value::Object(details), Value::Object(error_context)) =
                (&mut details, error_log_context(error.as_ref()))
            {
                details.extend(error_context);
            }

            unauthorized("custom_claim_validation_failed", details)
        })?;

        let mut context = build_default_context(&claims);
        context.extend(build_mapped_context(&claims, &self.config.context_claims));
        context.extend(
            self.hooks
                .build_additional_context(&claims)
                .await
                .map_err(Error::from_hook)?,
        );

        let policy_statement = self.config.policy_statement.clone().merge(
            self.hooks
                .build_policy_statement(PolicyInput {
                    claims: &claims,
                    method_arn: &event.method_arn,
                })
                .await
                .map_err(Error::from_hook)?,
        );
        let principal_id =
            get_claim(&claims, "sub").unwrap_or_else(|| DEFAULT_PRINCIPAL_ID.to_owned());
        let response =
            AuthorizerResponse::new(principal_id, &event.method_arn, policy_statement, context);

        tracing::debug!(method_arn = %event.method_arn, "Authorizer success");

        Ok(response)
    }

    /// Verifies a JWT's signature against the IdP's JWKS and validates its issuer, audience, and
    /// expiration.
    pub async fn verify_token(&self, token: &str) -> Result<Claims, Error> {
        let discovery = self.discovery().await?;

        tracing::debug!(
            audience = ?self.config.audience,
            issuer = %discovery.issuer,
            "Verifying JWT"
        );

        let header = jsonwebtoken::decode_header(token).map_err(jwt_verification_failed)?;
        let mut validation = Validation::new(header.alg);
        validation.leeway = 0;
        validation.validate_nbf = true;
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.set_issuer(&[&discovery.issuer]);
        validation.set_audience(&self.config.audience);

        let candidates = discovery.jwks.candidate_keys(&header).await?;
        let mut last_error = None;

        for key in &candidates {
            match jsonwebtoken::decode::<Claims>(token, &key.decoding_key, &validation) {
                Ok(data) => return Ok(data.claims),
                Err(error) => last_error = Some(error),
            }
        }

        Err(match last_error {
            Some(error) => jwt_verification_failed(error),
            None => unauthorized(
                "jwt_verification_failed",
                json!({
                    "errorMessage": "no applicable key found in the JSON Web Key Set",
                    "errorName": "JWKSNoMatchingKey",
                }),
            ),
        })
    }

    async fn discovery(&self) -> Result<&Discovery, Error> {
        self.discovery
            .get_or_try_init(|| Discovery::fetch(&self.client, self.config.discovery_url()))
            .await
    }
}

/// Extracts the token from a `Bearer <token>` authorization value (case-insensitive scheme).
pub fn get_bearer_token(authorization_token: Option<&str>) -> Result<&str, Error> {
    let token = authorization_token
        .and_then(|value| {
            value
                .get(..6)
                .filter(|scheme| scheme.eq_ignore_ascii_case("bearer"))
                .map(|_| &value[6..])
        })
        .filter(|rest| rest.starts_with(char::is_whitespace))
        .map(str::trim_start)
        // Like `^Bearer\s+(.+)$`, the token itself may not span lines.
        .filter(|token| !token.contains(['\n', '\r', '\u{2028}', '\u{2029}']))
        .map(str::trim)
        .filter(|token| !token.is_empty());

    let Some(token) = token else {
        // Only a word followed by whitespace is a scheme; a bare value may be the credential.
        let authorization_scheme = authorization_token
            .and_then(|value| value.split_once(char::is_whitespace))
            .map(|(scheme, _)| scheme)
            .filter(|scheme| !scheme.is_empty())
            .map(|scheme| {
                scheme
                    .chars()
                    .take(MAX_LOGGED_SCHEME_CHARS)
                    .collect::<String>()
            });

        return Err(unauthorized(
            "authorization_header_missing_or_malformed",
            json!({
                "authorizationScheme": authorization_scheme,
                "hasAuthorizationToken": authorization_token.is_some_and(|value| !value.is_empty()),
            }),
        ));
    };

    tracing::debug!(
        token_length = token.len(),
        "Bearer token extracted from authorization header"
    );

    Ok(token)
}

fn jwt_verification_failed(error: jsonwebtoken::errors::Error) -> Error {
    unauthorized("jwt_verification_failed", error_log_context(&error))
}

/// Runs `authorizer` as the Lambda function handler.
pub async fn run<H: AuthorizerHooks>(
    authorizer: Authorizer<H>,
) -> Result<(), lambda_runtime::Error> {
    let authorizer = &authorizer;

    lambda_runtime::run(service_fn(
        move |event: LambdaEvent<TokenAuthorizerEvent>| async move {
            authorizer.authorize(&event.payload).await
        },
    ))
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_bearer_tokens() {
        assert_eq!(
            get_bearer_token(Some("Bearer abc.def.ghi")).unwrap(),
            "abc.def.ghi"
        );
        assert_eq!(get_bearer_token(Some("bearer token")).unwrap(), "token");
        assert_eq!(get_bearer_token(Some("BEARER\t token ")).unwrap(), "token");
    }

    #[test]
    fn rejects_missing_bearer_tokens_as_unauthorized() {
        for value in [
            None,
            Some(""),
            Some("Token abc"),
            Some("Bearer"),
            Some("Bearer    "),
            Some("Bearerabc"),
            Some("Bearer abc\ndef"),
            Some("Bé"),
        ] {
            assert!(
                get_bearer_token(value).unwrap_err().is_unauthorized(),
                "{value:?}"
            );
        }
    }
}
