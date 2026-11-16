//! The custom handler from the README. Keep the two in sync.

use mondo_lambda_authorizer::rest_api::{
    self, Authorizer, AuthorizerHooks, BoxError, Claims, Context, Error, PolicyEffect, PolicyInput,
    PolicyStatementOverride, get_claim, get_scopes,
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

    async fn build_additional_context(&self, claims: &Claims) -> Result<Context, BoxError> {
        let mut context = Context::new();

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
        let is_write_request =
            input.method_arn.contains("/POST/") || input.method_arn.contains("/PUT/");
        let can_write = get_scopes(input.claims, "scope")
            .iter()
            .any(|scope| scope == "api:write");

        Ok(PolicyStatementOverride {
            effect: Some(if is_write_request && !can_write {
                PolicyEffect::Deny
            } else {
                PolicyEffect::Allow
            }),
            resource: Some(input.method_arn.into()),
            ..Default::default()
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), lambda_runtime::Error> {
    mondo_lambda_authorizer::logging::init();

    let authorizer = Authorizer::from_env()?.with_hooks(Hooks {
        expected_app_id: std::env::var("EXPECTED_MONDO_APP_ID")?,
    });

    rest_api::run(authorizer).await
}
