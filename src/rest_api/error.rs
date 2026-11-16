use serde_json::{Value, json};

/// Boxed error returned by [`AuthorizerHooks`](super::AuthorizerHooks) callbacks.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Errors returned by the authorizer.
///
/// [`Error::Unauthorized`] displays as `Unauthorized`, which API Gateway maps to a 401 response.
/// Every other variant surfaces as a 500.
///
/// New variants may be added in minor releases, so a `match` on this type needs a wildcard arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("{0} is required")]
    MissingEnv(&'static str),
    #[error("the authorizer event has no methodArn")]
    MissingMethodArn,
    #[error("{name} contains invalid JSON: {source}")]
    InvalidEnvJson {
        name: &'static str,
        source: serde_json::Error,
    },
    #[error("MONDO_AUDIENCE must be a non-empty string or JSON array of non-empty strings")]
    InvalidAudience,
    #[error("OIDC discovery request failed with status {0}")]
    DiscoveryStatus(u16),
    #[error("OIDC discovery response is not valid JSON")]
    DiscoveryInvalid,
    #[error("OIDC discovery response is missing issuer or jwks_uri")]
    DiscoveryIncomplete,
    #[error("OIDC discovery failed recently and is not retried until the cooldown has passed")]
    DiscoveryCooldown,
    #[error("JWKS request failed with status {0}")]
    JwksStatus(u16),
    #[error("JWKS response is not a valid JSON Web Key Set")]
    JwksInvalid,
    #[error("JWKS request failed recently and is not retried until the cooldown has passed")]
    JwksCooldown,
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Hook(BoxError),
}

impl Error {
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, Self::Unauthorized)
    }

    /// Hooks deny a request by returning [`Error::Unauthorized`]; any other error is a failure.
    pub(crate) fn from_hook(error: BoxError) -> Self {
        if error
            .downcast_ref::<Self>()
            .is_some_and(Self::is_unauthorized)
        {
            Self::Unauthorized
        } else {
            Self::Hook(error)
        }
    }
}

impl From<Error> for lambda_runtime::Diagnostic {
    fn from(error: Error) -> Self {
        let error_type = if error.is_unauthorized() {
            "Unauthorized"
        } else {
            "AuthorizerError"
        };

        Self {
            error_type: error_type.to_owned(),
            error_message: error.to_string(),
        }
    }
}

/// Logs why a request was denied and returns [`Error::Unauthorized`].
pub(crate) fn unauthorized(reason: &str, details: Value) -> Error {
    tracing::warn!(reason, details = %details, "REST API authorizer request denied");

    Error::Unauthorized
}

pub(crate) fn error_log_context(error: &(dyn std::error::Error + 'static)) -> Value {
    json!({
        "errorMessage": error.to_string(),
        "errorName": error_name(error),
    })
}

fn error_name(error: &(dyn std::error::Error + 'static)) -> String {
    if let Some(error) = error.downcast_ref::<jsonwebtoken::errors::Error>() {
        return format!("{:?}", error.kind());
    }

    "Error".to_owned()
}
