use std::collections::BTreeMap;

use serde::de::DeserializeOwned;

use super::claims::ClaimExpectation;
use super::error::Error;
use super::policy::PolicyStatementOverride;

/// Authorizer settings, usually read from the `MONDO_*` environment variables set by the CDK
/// construct.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Config {
    /// Mondo IdP domain or URL used to discover OpenID Provider metadata (`MONDO_IDP_DOMAIN_NAME`).
    pub idp_domain_name: String,
    /// Accepted JWT audiences; a token must match at least one (`MONDO_AUDIENCE`).
    pub audience: Vec<String>,
    /// Additional claim requirements evaluated after JWT verification (`MONDO_REQUIRED_CLAIMS`).
    pub required_claims: BTreeMap<String, ClaimExpectation>,
    /// Context keys mapped to the claim names they are read from (`MONDO_CONTEXT_CLAIMS`).
    pub context_claims: BTreeMap<String, String>,
    /// Overrides for the returned IAM policy statement (`MONDO_POLICY_STATEMENT`).
    pub policy_statement: PolicyStatementOverride,
}

impl Config {
    pub fn new<A: Into<String>>(
        idp_domain_name: impl Into<String>,
        audience: impl IntoIterator<Item = A>,
    ) -> Self {
        Self {
            idp_domain_name: idp_domain_name.into(),
            audience: audience.into_iter().map(Into::into).collect(),
            ..Default::default()
        }
    }

    pub fn from_env() -> Result<Self, Error> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, Error> {
        let lookup = |name| lookup(name).filter(|value: &String| !value.is_empty());
        let required = |name: &'static str| {
            lookup(name).ok_or_else(|| {
                tracing::error!(env_name = name, "Required environment variable is missing");
                Error::MissingEnv(name)
            })
        };

        Ok(Self {
            idp_domain_name: strip_wrapping_quotes(&required("MONDO_IDP_DOMAIN_NAME")?).to_owned(),
            audience: parse_audience(&required("MONDO_AUDIENCE")?)?,
            required_claims: parse_json_env(
                "MONDO_REQUIRED_CLAIMS",
                lookup("MONDO_REQUIRED_CLAIMS"),
            )?
            .unwrap_or_default(),
            context_claims: parse_json_env("MONDO_CONTEXT_CLAIMS", lookup("MONDO_CONTEXT_CLAIMS"))?
                .unwrap_or_default(),
            policy_statement: parse_json_env(
                "MONDO_POLICY_STATEMENT",
                lookup("MONDO_POLICY_STATEMENT"),
            )?
            .unwrap_or_default(),
        })
    }

    /// The OIDC discovery document URL derived from [`Config::idp_domain_name`].
    pub fn discovery_url(&self) -> String {
        let base_url = self.idp_domain_name.trim().trim_end_matches('/');

        if base_url.starts_with("https://") || base_url.starts_with("http://") {
            format!("{base_url}/.well-known/openid-configuration")
        } else {
            format!("https://{base_url}/.well-known/openid-configuration")
        }
    }
}

/// Accepts a plain (optionally quoted) string or a JSON string array. Only values that look like
/// an array are parsed as JSON, so an audience such as `1234567890` stays a string.
fn parse_audience(raw_audience: &str) -> Result<Vec<String>, Error> {
    let raw_audience = strip_wrapping_quotes(raw_audience);
    let audience = if raw_audience.starts_with('[') {
        serde_json::from_str(raw_audience).map_err(|_| Error::InvalidAudience)?
    } else {
        vec![raw_audience.to_owned()]
    };

    if audience.is_empty() || audience.iter().any(String::is_empty) {
        return Err(Error::InvalidAudience);
    }

    Ok(audience)
}

fn parse_json_env<T: DeserializeOwned>(
    name: &'static str,
    raw_value: Option<String>,
) -> Result<Option<T>, Error> {
    raw_value
        .map(|raw_value| {
            serde_json::from_str(&raw_value).map_err(|source| {
                tracing::error!(env_name = name, error = %source, "Environment variable contains invalid JSON");
                Error::InvalidEnvJson { name, source }
            })
        })
        .transpose()
}

fn strip_wrapping_quotes(value: &str) -> &str {
    let value = value.trim();

    for quote in ['"', '\''] {
        if let Some(unquoted) = value
            .strip_prefix(quote)
            .and_then(|value| value.strip_suffix(quote))
        {
            return unquoted;
        }
    }

    value
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use aws_lambda_events::iam::IamPolicyEffect;

    fn from_vars(vars: &[(&str, &str)]) -> Result<Config, Error> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();

        Config::from_lookup(|name| vars.get(name).cloned())
    }

    #[test]
    fn reads_config_from_environment_variables() {
        let config = from_vars(&[
            ("MONDO_IDP_DOMAIN_NAME", "\"mondo.auth.mondoidentity.com\""),
            ("MONDO_AUDIENCE", "https://app.mondoidentity.com"),
            ("MONDO_REQUIRED_CLAIMS", r#"{"scope":["openid","email"]}"#),
            ("MONDO_CONTEXT_CLAIMS", r#"{"scopes":"scope"}"#),
            ("MONDO_POLICY_STATEMENT", r#"{"effect":"Deny"}"#),
        ])
        .unwrap();

        assert_eq!(config.idp_domain_name, "mondo.auth.mondoidentity.com");
        assert_eq!(config.audience, ["https://app.mondoidentity.com"]);
        assert_eq!(
            config.required_claims["scope"],
            ClaimExpectation::ContainsAll(vec!["openid".into(), "email".into()])
        );
        assert_eq!(config.context_claims["scopes"], "scope");
        assert_eq!(config.policy_statement.effect, Some(IamPolicyEffect::Deny));
    }

    #[test]
    fn requires_domain_name_and_audience() {
        assert!(matches!(
            from_vars(&[("MONDO_AUDIENCE", "aud")]),
            Err(Error::MissingEnv("MONDO_IDP_DOMAIN_NAME"))
        ));
        assert!(matches!(
            from_vars(&[
                ("MONDO_IDP_DOMAIN_NAME", "example.com"),
                ("MONDO_AUDIENCE", "")
            ]),
            Err(Error::MissingEnv("MONDO_AUDIENCE"))
        ));
    }

    #[test]
    fn rejects_invalid_json_settings() {
        assert!(matches!(
            from_vars(&[
                ("MONDO_IDP_DOMAIN_NAME", "example.com"),
                ("MONDO_AUDIENCE", "aud"),
                ("MONDO_CONTEXT_CLAIMS", "{"),
            ]),
            Err(Error::InvalidEnvJson {
                name: "MONDO_CONTEXT_CLAIMS",
                ..
            })
        ));
    }

    #[test]
    fn rejects_unknown_policy_statement_fields() {
        assert!(matches!(
            from_vars(&[
                ("MONDO_IDP_DOMAIN_NAME", "example.com"),
                ("MONDO_AUDIENCE", "aud"),
                ("MONDO_POLICY_STATEMENT", r#"{"Effect":"Deny"}"#),
            ]),
            Err(Error::InvalidEnvJson {
                name: "MONDO_POLICY_STATEMENT",
                ..
            })
        ));
    }

    #[test]
    fn parses_audience_strings_and_arrays() {
        assert_eq!(parse_audience("aud").unwrap(), ["aud"]);
        assert_eq!(parse_audience("'aud'").unwrap(), ["aud"]);
        assert_eq!(parse_audience(r#""aud""#).unwrap(), ["aud"]);
        assert_eq!(parse_audience(r#"["a","b"]"#).unwrap(), ["a", "b"]);
        assert_eq!(parse_audience("1234567890").unwrap(), ["1234567890"]);
        assert_eq!(parse_audience("true").unwrap(), ["true"]);
        assert!(matches!(parse_audience("[1]"), Err(Error::InvalidAudience)));
        assert!(matches!(parse_audience("[]"), Err(Error::InvalidAudience)));
        assert!(matches!(
            parse_audience(r#"["a",""]"#),
            Err(Error::InvalidAudience)
        ));
        assert!(matches!(parse_audience("''"), Err(Error::InvalidAudience)));
    }

    #[test]
    fn builds_discovery_url_from_domain_or_url() {
        let url = |domain: &str| Config::new(domain, ["aud"]).discovery_url();

        assert_eq!(
            url("mondo.auth.mondoidentity.com"),
            "https://mondo.auth.mondoidentity.com/.well-known/openid-configuration"
        );
        assert_eq!(
            url(" https://mondo.auth.mondoidentity.com// "),
            "https://mondo.auth.mondoidentity.com/.well-known/openid-configuration"
        );
        assert_eq!(
            url("http://localhost:8080"),
            "http://localhost:8080/.well-known/openid-configuration"
        );
    }
}
