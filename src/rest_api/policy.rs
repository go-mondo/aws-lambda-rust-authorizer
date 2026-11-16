use serde::{Deserialize, Serialize};

use super::claims::Context;

/// The API Gateway `TOKEN` authorizer event.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenAuthorizerEvent {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub authorization_token: Option<String>,
    pub method_arn: String,
}

/// The API Gateway authorizer result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizerResponse {
    pub principal_id: String,
    pub policy_document: PolicyDocument,
    pub context: Context,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PolicyDocument {
    pub version: String,
    pub statement: Vec<PolicyStatement>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PolicyStatement {
    pub action: StringOrArray,
    pub effect: PolicyEffect,
    pub resource: StringOrArray,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyEffect {
    #[default]
    Allow,
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrArray {
    String(String),
    Array(Vec<String>),
}

impl From<String> for StringOrArray {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for StringOrArray {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<Vec<String>> for StringOrArray {
    fn from(value: Vec<String>) -> Self {
        Self::Array(value)
    }
}

/// Overrides for the IAM policy statement returned by the authorizer.
///
/// Omitted fields default to `execute-api:Invoke`, `Allow`, and every method and path in the
/// incoming `methodArn`'s API stage (see [`build_all_methods_resource`]), so a policy cached by
/// API Gateway for a token applies to every endpoint that token calls.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PolicyStatementOverride {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<StringOrArray>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<PolicyEffect>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<StringOrArray>,
}

impl PolicyStatementOverride {
    /// Returns `self` with every field set on `other` taking precedence.
    pub fn merge(self, other: Self) -> Self {
        Self {
            action: other.action.or(self.action),
            effect: other.effect.or(self.effect),
            resource: other.resource.or(self.resource),
        }
    }
}

impl AuthorizerResponse {
    pub(crate) fn new(
        principal_id: String,
        method_arn: &str,
        policy_statement: PolicyStatementOverride,
        context: Context,
    ) -> Self {
        Self {
            context,
            policy_document: PolicyDocument {
                statement: vec![PolicyStatement {
                    action: policy_statement
                        .action
                        .unwrap_or_else(|| "execute-api:Invoke".into()),
                    effect: policy_statement.effect.unwrap_or_default(),
                    resource: policy_statement
                        .resource
                        .unwrap_or_else(|| build_all_methods_resource(method_arn).into()),
                }],
                version: "2012-10-17".to_owned(),
            },
            principal_id,
        }
    }
}

/// Converts a method ARN into an execute-api resource covering every method and path in the
/// same API stage, e.g. `.../a1b2c3d4e5/prod/GET/customers/123` becomes
/// `.../a1b2c3d4e5/prod/*/*`. API Gateway caches authorizer results per token, not per method,
/// so a cached policy must cover every endpoint the token may call. Malformed ARNs are returned
/// unchanged.
pub fn build_all_methods_resource(method_arn: &str) -> String {
    // The resource is the sixth field and may itself contain `:`, e.g. in a path segment.
    let mut arn_parts: Vec<&str> = method_arn.splitn(6, ':').collect();
    let Some(execute_api_resource) = arn_parts.get(5).filter(|part| !part.is_empty()) else {
        return method_arn.to_owned();
    };

    let mut segments = execute_api_resource.split('/');
    let (Some(api_id), Some(stage)) = (segments.next(), segments.next()) else {
        return method_arn.to_owned();
    };

    if api_id.is_empty() || stage.is_empty() {
        return method_arn.to_owned();
    }

    let resource = format!("{api_id}/{stage}/*/*");
    arn_parts[5] = &resource;

    arn_parts.join(":")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn builds_an_execute_api_resource_that_covers_all_methods_in_the_stage() {
        assert_eq!(
            build_all_methods_resource(
                "arn:aws:execute-api:us-east-1:123456789012:a1b2c3d4e5/prod/GET/customers/123"
            ),
            "arn:aws:execute-api:us-east-1:123456789012:a1b2c3d4e5/prod/*/*"
        );
        assert_eq!(
            build_all_methods_resource(
                "arn:aws:execute-api:us-east-1:123456789012:a1b2c3d4e5/prod/GET/items/urn:x:1"
            ),
            "arn:aws:execute-api:us-east-1:123456789012:a1b2c3d4e5/prod/*/*"
        );
    }

    #[test]
    fn keeps_malformed_method_arns_unchanged() {
        assert_eq!(
            build_all_methods_resource("arn:aws:execute-api:us-east-1:123456789012"),
            "arn:aws:execute-api:us-east-1:123456789012"
        );
        assert_eq!(
            build_all_methods_resource("arn:aws:execute-api:us-east-1:123456789012:a1b2c3d4e5"),
            "arn:aws:execute-api:us-east-1:123456789012:a1b2c3d4e5"
        );
    }

    #[test]
    fn merges_policy_statement_overrides() {
        let base: PolicyStatementOverride =
            serde_json::from_value(json!({ "action": "execute-api:*", "effect": "Deny" })).unwrap();
        let merged = base.merge(PolicyStatementOverride {
            effect: Some(PolicyEffect::Allow),
            resource: Some(vec!["a".to_owned(), "b".to_owned()].into()),
            ..Default::default()
        });

        assert_eq!(
            merged,
            PolicyStatementOverride {
                action: Some("execute-api:*".into()),
                effect: Some(PolicyEffect::Allow),
                resource: Some(vec!["a".to_owned(), "b".to_owned()].into()),
            }
        );
    }

    #[test]
    fn serializes_the_authorizer_response_in_api_gateway_format() {
        let response = AuthorizerResponse::new(
            "usr_123".to_owned(),
            "arn:aws:execute-api:us-east-1:123456789012:a1b2c3d4e5/prod/GET/",
            PolicyStatementOverride::default(),
            Context::from([("tenantId".to_owned(), "tnt_123".into())]),
        );

        assert_eq!(
            serde_json::to_value(response).unwrap(),
            json!({
                "context": { "tenantId": "tnt_123" },
                "policyDocument": {
                    "Statement": [{
                        "Action": "execute-api:Invoke",
                        "Effect": "Allow",
                        "Resource": "arn:aws:execute-api:us-east-1:123456789012:a1b2c3d4e5/prod/*/*",
                    }],
                    "Version": "2012-10-17",
                },
                "principalId": "usr_123",
            })
        );
    }
}
