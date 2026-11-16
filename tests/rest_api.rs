mod common;

use common::{AUDIENCE, Idp, METHOD_ARN, event, event_with_authorization, now, sign, sign_rs256};
use mondo_lambda_authorizer::rest_api::{
    Authorizer, AuthorizerHooks, BoxError, Claims, Config, Context, Error, IamPolicyEffect,
    PolicyInput, PolicyStatementOverride, get_claim, get_scopes,
};
use serde_json::json;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn authorizes_a_valid_token_with_default_context_and_policy() {
    let idp = Idp::start().await;
    let authorizer = Authorizer::new(idp.config());

    let response = authorizer
        .authorize(&event(&idp.token(json!({}))))
        .await
        .unwrap();

    assert_eq!(
        serde_json::to_value(response).unwrap(),
        json!({
            "context": { "appId": "app_123", "tenantId": "tnt_123", "userId": "usr_123" },
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

#[tokio::test]
async fn verifies_rs256_tokens() {
    let idp = Idp::start().await;
    let authorizer = Authorizer::new(idp.config());

    let response = authorizer
        .authorize(&event(&idp.rs256_token(json!({}))))
        .await
        .unwrap();
    assert_eq!(response.principal_id.as_deref(), Some("usr_123"));

    // An RS256 signature never verifies against the EC key, even when the header names it.
    let mismatched = sign_rs256(&idp.claims(json!({})), "test-key");
    let error = authorizer.authorize(&event(&mismatched)).await.unwrap_err();
    assert!(error.is_unauthorized());
}

#[tokio::test]
async fn uses_a_default_principal_without_sub() {
    let idp = Idp::start().await;
    let mut claims = idp.claims(json!({}));
    claims.as_object_mut().unwrap().remove("sub");

    let response = Authorizer::new(idp.config())
        .authorize(&event(&sign(&claims, "test-key")))
        .await
        .unwrap();

    assert_eq!(response.principal_id.as_deref(), Some("mondo-user"));
    assert!(!response.context.contains_key("userId"));
}

#[tokio::test]
async fn caches_discovery_across_invocations() {
    let idp = Idp::start().await;
    let authorizer = Authorizer::new(idp.config());

    for _ in 0..3 {
        authorizer
            .authorize(&event(&idp.token(json!({}))))
            .await
            .unwrap();
    }

    let discovery_requests = idp
        .server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|request| request.url.path() == "/.well-known/openid-configuration")
        .count();
    assert_eq!(discovery_requests, 1);
}

#[tokio::test]
async fn normalizes_jwt_verification_failures_to_unauthorized() {
    let idp = Idp::start().await;
    let authorizer = Authorizer::new(idp.config());
    let expired = idp.token(json!({ "exp": now() - 10 }));
    let wrong_audience = idp.token(json!({ "aud": "https://other.example.com" }));
    let wrong_issuer = idp.token(json!({ "iss": "https://evil.example.com" }));
    let not_yet_valid = idp.token(json!({ "nbf": now() + 300 }));
    let mut missing_exp = json!({ "aud": AUDIENCE, "iss": idp.issuer(), "sub": "usr_123" });
    let missing_exp = sign(&missing_exp.take(), "test-key");
    let unknown_kid = sign(
        &json!({ "aud": AUDIENCE, "exp": now() + 300, "iss": idp.issuer() }),
        "rotated",
    );
    let tampered = {
        let token = idp.token(json!({}));
        let (rest, _) = token.rsplit_once('.').unwrap();
        format!("{rest}.{}", "A".repeat(86))
    };

    for token in [
        "not-a-jwt",
        &expired,
        &wrong_audience,
        &wrong_issuer,
        &not_yet_valid,
        &missing_exp,
        &unknown_kid,
        &tampered,
    ] {
        let error = authorizer.verify_token(token).await.unwrap_err();

        assert!(error.is_unauthorized(), "{token}: {error:?}");
        assert_eq!(error.to_string(), "Unauthorized");
    }
}

#[tokio::test]
async fn accepts_any_configured_audience() {
    let idp = Idp::start().await;
    let authorizer = Authorizer::new(Config::new(idp.issuer(), ["https://other", AUDIENCE]));

    let claims = authorizer
        .verify_token(&idp.token(json!({ "aud": ["https://third", AUDIENCE] })))
        .await
        .unwrap();

    assert_eq!(get_claim(&claims, "sub").as_deref(), Some("usr_123"));
}

#[tokio::test]
async fn rejects_missing_bearer_tokens() {
    let idp = Idp::start().await;
    let authorizer = Authorizer::new(idp.config());

    let error = authorizer
        .authorize(&event_with_authorization("Basic abc"))
        .await
        .unwrap_err();

    assert!(error.is_unauthorized());
}

#[tokio::test]
async fn fails_without_a_method_arn() {
    let idp = Idp::start().await;
    let authorizer = Authorizer::new(idp.config());
    let mut event = event(&idp.token(json!({})));
    event.method_arn = None;

    let error = authorizer.authorize(&event).await.unwrap_err();

    assert!(matches!(error, Error::MissingMethodArn));
}

#[tokio::test]
async fn applies_configured_claims_context_and_policy() {
    let idp = Idp::start().await;
    let mut config = idp.config();
    config.required_claims =
        serde_json::from_value(json!({ "scope": ["openid", "email"], "tnt": "tnt_123" })).unwrap();
    config.context_claims = serde_json::from_value(json!({ "scopes": "scope" })).unwrap();
    config.policy_statement =
        serde_json::from_value(json!({ "action": ["execute-api:Invoke"], "resource": "*" }))
            .unwrap();
    let authorizer = Authorizer::new(config);

    let response = authorizer
        .authorize(&event(
            &idp.token(json!({ "scope": "openid profile email" })),
        ))
        .await
        .unwrap();

    assert_eq!(response.context["scopes"], "openid profile email".into());
    assert_eq!(
        response.policy_document.statement[0].action,
        ["execute-api:Invoke"]
    );
    assert_eq!(response.policy_document.statement[0].resource, ["*"]);

    let error = authorizer
        .authorize(&event(&idp.token(json!({ "scope": "openid profile" }))))
        .await
        .unwrap_err();

    assert!(error.is_unauthorized());
}

struct CustomHooks {
    expected_app_id: &'static str,
}

impl AuthorizerHooks for CustomHooks {
    async fn validate_claims(&self, claims: &Claims) -> Result<(), BoxError> {
        if get_claim(claims, "azp").as_deref() != Some(self.expected_app_id) {
            return Err("unexpected app".into());
        }

        Ok(())
    }

    async fn build_context(
        &self,
        claims: &Claims,
        mut context: Context,
    ) -> Result<Context, BoxError> {
        if get_claim(claims, "email").as_deref() == Some("blocked@example.com") {
            return Err(Error::Unauthorized.into());
        }
        if get_claim(claims, "email").as_deref() == Some("broken@example.com") {
            return Err("database unavailable".into());
        }
        if get_claim(claims, "email").as_deref() == Some("lookalike@example.com") {
            // Only `Error::Unauthorized` denies; other errors with the same message are failures.
            return Err("Unauthorized".into());
        }

        context.insert("appId".to_owned(), "overridden".into());
        context.insert("isAdmin".to_owned(), true.into());
        context.remove("userId");

        Ok(context)
    }

    async fn build_policy_statement(
        &self,
        input: PolicyInput<'_>,
    ) -> Result<PolicyStatementOverride, BoxError> {
        let can_write = get_scopes(input.claims, "scope").contains(&"api:write".to_owned());

        Ok(PolicyStatementOverride {
            effect: Some(if can_write {
                IamPolicyEffect::Allow
            } else {
                IamPolicyEffect::Deny
            }),
            resource: Some(vec![input.method_arn.to_owned()]),
            ..Default::default()
        })
    }
}

#[tokio::test]
async fn runs_custom_hooks() {
    let idp = Idp::start().await;
    let authorizer = Authorizer::new(idp.config()).with_hooks(CustomHooks {
        expected_app_id: "app_123",
    });

    let response = authorizer
        .authorize(&event(&idp.token(json!({ "scope": "api:read" }))))
        .await
        .unwrap();

    assert_eq!(response.context["appId"], "overridden".into());
    assert_eq!(response.context["isAdmin"], true.into());
    assert_eq!(response.context["tenantId"], "tnt_123".into());
    assert!(!response.context.contains_key("userId"));
    assert_eq!(
        response.policy_document.statement[0].effect,
        IamPolicyEffect::Deny
    );
    assert_eq!(response.policy_document.statement[0].resource, [METHOD_ARN]);

    let wrong_app = authorizer
        .authorize(&event(&idp.token(json!({ "azp": "app_other" }))))
        .await
        .unwrap_err();
    assert!(wrong_app.is_unauthorized());

    let blocked = authorizer
        .authorize(&event(
            &idp.token(json!({ "email": "blocked@example.com" })),
        ))
        .await
        .unwrap_err();
    assert!(blocked.is_unauthorized());

    let broken = authorizer
        .authorize(&event(&idp.token(json!({ "email": "broken@example.com" }))))
        .await
        .unwrap_err();
    assert!(matches!(broken, Error::Hook(_)));
    assert_eq!(broken.to_string(), "database unavailable");

    let lookalike = authorizer
        .authorize(&event(
            &idp.token(json!({ "email": "lookalike@example.com" })),
        ))
        .await
        .unwrap_err();
    assert!(matches!(lookalike, Error::Hook(_)));
}

#[tokio::test]
async fn fails_without_unauthorized_when_discovery_fails() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let authorizer = Authorizer::new(Config::new(server.uri(), [AUDIENCE]));

    let error = authorizer.verify_token("a.b.c").await.unwrap_err();
    assert!(matches!(error, Error::DiscoveryStatus(503)));

    // An unreachable IdP isn't retried on every request.
    let error = authorizer.verify_token("a.b.c").await.unwrap_err();
    assert!(matches!(error, Error::DiscoveryCooldown));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}
