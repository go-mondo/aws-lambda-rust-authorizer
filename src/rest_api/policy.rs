use aws_lambda_events::apigw::{
    ApiGatewayCustomAuthorizerPolicy, ApiGatewayCustomAuthorizerResponse,
};
use aws_lambda_events::iam::{IamPolicyEffect, IamPolicyStatement};
use serde::{Deserialize, Deserializer, Serialize};

use super::claims::Context;

/// The API Gateway authorizer result, with the authorizer's [`Context`].
pub type AuthorizerResponse = ApiGatewayCustomAuthorizerResponse<Context>;

/// Overrides for the IAM policy statement returned by the authorizer.
///
/// Omitted fields default to `execute-api:Invoke`, `Allow`, and every method and path in the
/// incoming `methodArn`'s API stage (see [`build_all_methods_resource`]), so a policy cached by
/// API Gateway for a token applies to every endpoint that token calls.
///
/// Unknown fields are rejected, so a misspelled or IAM-style `"Effect"` key fails at startup
/// instead of being ignored in favor of the default `Allow`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyStatementOverride {
    /// Accepts a string or an array of strings.
    #[serde(
        default,
        deserialize_with = "string_or_array",
        skip_serializing_if = "Option::is_none"
    )]
    pub action: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<IamPolicyEffect>,
    /// Accepts a string or an array of strings.
    #[serde(
        default,
        deserialize_with = "string_or_array",
        skip_serializing_if = "Option::is_none"
    )]
    pub resource: Option<Vec<String>>,
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

/// Reads `"value"` as `["value"]`, so settings written for the Node.js authorizer still parse.
fn string_or_array<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrArray {
        String(String),
        Array(Vec<String>),
    }

    Ok(
        Option::<StringOrArray>::deserialize(deserializer)?.map(|value| match value {
            StringOrArray::String(value) => vec![value],
            StringOrArray::Array(values) => values,
        }),
    )
}

/// Builds the response for `method_arn`. The `aws_lambda_events` types are `#[non_exhaustive]`, so
/// they're built from their defaults rather than with struct literals.
pub(crate) fn build_response(
    principal_id: String,
    method_arn: &str,
    policy_statement: PolicyStatementOverride,
    context: Context,
) -> AuthorizerResponse {
    let mut statement = IamPolicyStatement::default();
    statement.action = policy_statement
        .action
        .unwrap_or_else(|| vec!["execute-api:Invoke".to_owned()]);
    statement.effect = policy_statement.effect.unwrap_or_default();
    statement.resource = policy_statement
        .resource
        .unwrap_or_else(|| vec![build_all_methods_resource(method_arn)]);

    let mut policy_document = ApiGatewayCustomAuthorizerPolicy::default();
    policy_document.version = Some("2012-10-17".to_owned());
    policy_document.statement = vec![statement];

    let mut response = AuthorizerResponse::default();
    response.principal_id = Some(principal_id);
    response.policy_document = policy_document;
    response.context = context;

    response
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
            effect: Some(IamPolicyEffect::Allow),
            resource: Some(vec!["a".to_owned(), "b".to_owned()]),
            ..Default::default()
        });

        assert_eq!(
            merged,
            PolicyStatementOverride {
                action: Some(vec!["execute-api:*".to_owned()]),
                effect: Some(IamPolicyEffect::Allow),
                resource: Some(vec!["a".to_owned(), "b".to_owned()]),
            }
        );
    }

    #[test]
    fn reads_policy_statement_actions_and_resources_as_strings_or_arrays() {
        let statement: PolicyStatementOverride = serde_json::from_value(
            json!({ "action": ["execute-api:Invoke"], "resource": "*", "effect": null }),
        )
        .unwrap();

        assert_eq!(
            statement,
            PolicyStatementOverride {
                action: Some(vec!["execute-api:Invoke".to_owned()]),
                effect: None,
                resource: Some(vec!["*".to_owned()]),
            }
        );
    }

    #[test]
    fn rejects_unknown_policy_statement_fields() {
        for value in [
            json!({ "Effect": "Deny" }),
            json!({ "efect": "Deny" }),
            json!({ "effect": "Deny", "condition": {} }),
        ] {
            assert!(
                serde_json::from_value::<PolicyStatementOverride>(value.clone()).is_err(),
                "{value}"
            );
        }
    }

    #[test]
    fn serializes_the_authorizer_response_in_api_gateway_format() {
        let response = build_response(
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
                        "Action": ["execute-api:Invoke"],
                        "Effect": "Allow",
                        "Resource": ["arn:aws:execute-api:us-east-1:123456789012:a1b2c3d4e5/prod/*/*"],
                    }],
                    "Version": "2012-10-17",
                },
                "principalId": "usr_123",
                "usageIdentifierKey": null,
            })
        );
    }
}
