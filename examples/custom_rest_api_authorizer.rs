//! The custom handler from the README. Keep the two in sync.

use mondo_lambda_authorizer::rest_api::{
    self, Authorizer, AuthorizerHooks, BoxError, Claims, Context, Error, IamPolicyEffect,
    PolicyInput, PolicyStatementOverride, get_claim, get_scopes,
};

struct Hooks {
    expected_app_id: String,
}

impl AuthorizerHooks for Hooks {
    async fn validate_claims(&self, claims: &Claims) -> Result<(), BoxError> {
        let tenant_id = get_claim(claims, "tnt").unwrap_or_default();
        let app_id = get_claim(claims, "azp");

        // Any error from validate_claims denies the request.
        if !tenant_id.starts_with("tnt_") || app_id.as_deref() != Some(&self.expected_app_id) {
            return Err(Error::Unauthorized.into());
        }

        Ok(())
    }

    async fn build_context(
        &self,
        claims: &Claims,
        mut context: Context,
    ) -> Result<Context, BoxError> {
        for (key, claim_name) in [
            ("email", "email"),
            ("scopes", "scope"),
            ("tenantRegion", "https://example.com/tenant_region"),
        ] {
            if let Some(value) = get_claim(claims, claim_name) {
                context.insert(key.to_owned(), value.into());
            }
        }

        Ok(context)
    }

    // This decides per method, so the authorizer must not cache results: API Gateway caches them
    // per token and would reuse this method's decision for the token's other requests. Set
    // `resultsCacheTtl: Duration.seconds(0)` on the `MondoAuthorizer`.
    async fn build_policy_statement(
        &self,
        input: PolicyInput<'_>,
    ) -> Result<PolicyStatementOverride, BoxError> {
        // Every method but a read needs the `api:write` scope, so DELETE, PATCH, and methods
        // added later are covered, and a method ARN that can't be parsed is denied.
        let is_read_request = matches!(
            http_method(input.method_arn),
            Some("GET" | "HEAD" | "OPTIONS")
        );
        let can_write = get_scopes(input.claims, "scope")
            .iter()
            .any(|scope| scope == "api:write");

        Ok(PolicyStatementOverride {
            effect: Some(if is_read_request || can_write {
                IamPolicyEffect::Allow
            } else {
                IamPolicyEffect::Deny
            }),
            resource: Some(vec![input.method_arn.to_owned()]),
            ..Default::default()
        })
    }
}

/// Reads the HTTP method from a method ARN, e.g. `GET` from
/// `arn:aws:execute-api:us-east-1:123456789012:a1b2c3d4e5/prod/GET/customers/123`. It reads the
/// method's own segment, so a path such as `/blog/POST/1` isn't mistaken for a POST.
fn http_method(method_arn: &str) -> Option<&str> {
    // The sixth `:`-separated field is `<api id>/<stage>/<method>/<path>`.
    method_arn.splitn(6, ':').nth(5)?.split('/').nth(2)
}

#[tokio::main]
async fn main() -> Result<(), lambda_runtime::Error> {
    mondo_lambda_authorizer::logging::init();

    let authorizer = Authorizer::from_env()?.with_hooks(Hooks {
        expected_app_id: std::env::var("EXPECTED_MONDO_APP_ID")?,
    });

    rest_api::run(authorizer).await
}
