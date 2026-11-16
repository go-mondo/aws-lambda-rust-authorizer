//! A single test in its own test binary: a thread-scoped tracing subscriber can miss events while
//! other tests run concurrently in the same process.

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use common::{Idp, METHOD_ARN, event, event_with_authorization};
use mondo_lambda_authorizer::logging::LogConfig;
use mondo_lambda_authorizer::rest_api::{
    Authorizer, AuthorizerHooks, BoxError, Claims, Context, Error,
};
use serde_json::{Value, json};
use tracing::Instrument;
use tracing::level_filters::LevelFilter;

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl LogBuffer {
    fn lines(&self) -> Vec<Value> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap_or_else(|_| panic!("not JSON: {line}")))
            .collect()
    }

    fn line(&self, message: &str) -> Option<Value> {
        self.lines()
            .into_iter()
            .find(|line| line["message"] == message)
    }
}

impl Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

struct SecretContextHooks;

impl AuthorizerHooks for SecretContextHooks {
    async fn build_context(
        &self,
        _claims: &Claims,
        mut context: Context,
    ) -> Result<Context, BoxError> {
        context.insert("sensitiveValue".to_owned(), "do-not-log".into());

        Ok(context)
    }
}

/// The span `lambda_runtime` opens around each invocation.
fn invocation_span() -> tracing::Span {
    tracing::info_span!(
        target: "lambda_runtime::layers::trace",
        "Lambda runtime invoke",
        requestId = "req-123",
        xrayTraceId = "Root=1-abc"
    )
}

#[tokio::test]
async fn writes_structured_lambda_json_logs_without_secrets() {
    let idp = Idp::start().await;
    let logs = LogBuffer::default();
    let subscriber = LogConfig::from_env()
        .with_json(true)
        .with_level(LevelFilter::TRACE)
        .subscriber(logs.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    let authorizer = Authorizer::new(idp.config()).with_hooks(SecretContextHooks);
    let token = idp.token(json!({}));

    let response = authorizer
        .authorize(&event(&token))
        .instrument(invocation_span())
        .await
        .unwrap();
    assert_eq!(response.context["sensitiveValue"], "do-not-log".into());

    // A credential sent without a scheme must not be logged as the scheme.
    let error = authorizer
        .authorize(&event_with_authorization(&token))
        .instrument(invocation_span())
        .await
        .unwrap_err();
    assert!(error.is_unauthorized());

    // What lambda_runtime logs for each error the handler returns, and for a panic.
    tracing::error!(target: "lambda_runtime::layers::panic", "{:?}", Error::Unauthorized);
    tracing::error!(target: "lambda_runtime::layers::panic", "{:?}", Error::DiscoveryStatus(503));
    tracing::error!(target: "lambda_runtime::layers::panic", error = "boom", "user handler panicked");
    tracing::debug!(target: "hyper_util::client::legacy::pool", "pooling idle connection");

    let lines = logs.lines();
    for line in &lines {
        let timestamp = line["timestamp"].as_str().unwrap();
        assert!(
            timestamp.contains('T') && timestamp.ends_with('Z'),
            "{line}"
        );
        assert!(line["level"].is_string(), "{line}");
        assert!(line["message"].is_string(), "{line}");
        assert_eq!(line["service"], "mondo-rest-api-authorizer");
        assert!(
            line.get("fields").is_none() && line.get("spans").is_none(),
            "{line}"
        );
    }

    let success = logs.line("Authorizer success").unwrap();
    assert_eq!(success["level"], "DEBUG");
    assert_eq!(success["requestId"], "req-123");
    assert_eq!(success["xrayTraceId"], "Root=1-abc");
    assert_eq!(success["methodArn"], METHOD_ARN);

    let verified = logs.line("Token verified").unwrap();
    assert_eq!(verified["details"]["tenantId"], "tnt_123");

    let denied = logs.line("REST API authorizer request denied").unwrap();
    assert_eq!(denied["level"], "WARN");
    assert_eq!(
        denied["reason"],
        "authorization_header_missing_or_malformed"
    );
    assert_eq!(denied["details"]["hasAuthorizationToken"], true);
    assert_eq!(denied["details"]["authorizationScheme"], Value::Null);

    // The authorizer logs each outcome itself, so the runtime's duplicates are dropped.
    assert!(logs.line("Unauthorized").is_none());
    assert!(logs.line("DiscoveryStatus(503)").is_none());
    assert_eq!(
        logs.line("user handler panicked").unwrap()["level"],
        "ERROR"
    );
    assert!(logs.line("pooling idle connection").is_none());

    let output = serde_json::to_string(&lines).unwrap();
    assert!(!output.contains("do-not-log"));
    assert!(!output.contains(&token[..20]));

    // At `WARN`, lines keep the fields of the `INFO` invocation span.
    let warn_logs = LogBuffer::default();
    let warn_subscriber = LogConfig::from_env()
        .with_json(true)
        .with_level(LevelFilter::WARN)
        .subscriber(warn_logs.clone());
    {
        let _guard = tracing::subscriber::set_default(warn_subscriber);
        authorizer
            .authorize(&event(&idp.token(json!({ "aud": "other" }))))
            .instrument(invocation_span())
            .await
            .unwrap_err();
    }

    let denied = warn_logs
        .line("REST API authorizer request denied")
        .unwrap();
    assert_eq!(denied["requestId"], "req-123");
    assert_eq!(denied["xrayTraceId"], "Root=1-abc");
    // Parsing sorts keys, so check their order in the raw line.
    let raw = String::from_utf8(warn_logs.0.lock().unwrap().clone()).unwrap();
    assert!(
        raw.starts_with(r#"{"timestamp":"#) && raw.contains(r#","level":"WARN","message":"#),
        "{raw}"
    );
    assert_eq!(warn_logs.lines().len(), 1);
}
