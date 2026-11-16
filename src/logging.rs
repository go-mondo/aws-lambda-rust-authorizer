//! Structured logging for Lambda.
//!
//! With Lambda's JSON log format (`AWS_LAMBDA_LOG_FORMAT=JSON`), each line is a JSON object with
//! top-level `timestamp` (RFC 3339), `level`, `message`, `service`, `requestId`, and
//! `xrayTraceId`, followed by the event's own fields in camelCase. A field named `details` that
//! holds a JSON object is emitted as a nested object, so it can be queried in CloudWatch Logs
//! Insights (e.g. `details.claimName`). Otherwise, logs use tracing's plain text format.
//!
//! The level comes from `AWS_LAMBDA_LOG_LEVEL` (set by the function's application log level),
//! then `RUST_LOG`, defaulting to `INFO`. `DEBUG` and `TRACE` don't apply to the HTTP client
//! libraries, whose connection-level logs would drown out the authorizer's.

use std::fmt;
use std::str::FromStr;

use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::{Event, Metadata, Subscriber};
use tracing_subscriber::filter::FilterExt;
use tracing_subscriber::fmt::format::{JsonFields, Writer};
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, FormattedFields, MakeWriter};
use tracing_subscriber::layer::{Context, Filter, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{EnvFilter, Layer, Registry};

/// The `service` reported by the packaged authorizer.
pub const DEFAULT_SERVICE_NAME: &str = "mondo-rest-api-authorizer";

/// Dependencies whose `DEBUG` and `TRACE` logs are suppressed.
const NOISY_TARGETS: &[&str] = &["h2", "hyper", "hyper_util", "reqwest", "rustls", "tower"];

/// Where `lambda_runtime` logs every error a handler returns, at `ERROR`.
const RUNTIME_HANDLER_ERROR_TARGET: &str = "lambda_runtime::layers::panic";

/// Installs the global subscriber, configured from the environment.
///
/// # Panics
///
/// Panics if a global subscriber is already installed.
pub fn init() {
    LogConfig::from_env().init();
}

/// Logging settings. [`LogConfig::from_env`] reads Lambda's logging environment variables.
#[derive(Clone, Debug)]
pub struct LogConfig {
    service_name: String,
    directives: String,
    json: bool,
}

impl LogConfig {
    pub fn from_env() -> Self {
        let directives = match std::env::var("AWS_LAMBDA_LOG_LEVEL") {
            Ok(level) => level_directives(parse_level(&level)),
            Err(_) => {
                std::env::var("RUST_LOG").unwrap_or_else(|_| level_directives(LevelFilter::INFO))
            }
        };

        Self {
            service_name: DEFAULT_SERVICE_NAME.to_owned(),
            directives,
            json: std::env::var("AWS_LAMBDA_LOG_FORMAT")
                .is_ok_and(|format| format.eq_ignore_ascii_case("json")),
        }
    }

    pub fn with_service_name(mut self, service_name: impl Into<String>) -> Self {
        self.service_name = service_name.into();
        self
    }

    pub fn with_level(mut self, level: LevelFilter) -> Self {
        self.directives = level_directives(level);
        self
    }

    pub fn with_json(mut self, json: bool) -> Self {
        self.json = json;
        self
    }

    /// Installs the global subscriber, writing to stdout.
    ///
    /// # Panics
    ///
    /// Panics if a global subscriber is already installed.
    pub fn init(self) {
        tracing::subscriber::set_global_default(self.subscriber(std::io::stdout))
            .expect("a global tracing subscriber is already installed");
    }

    /// Builds the subscriber without installing it.
    pub fn subscriber<W>(self, make_writer: W) -> impl Subscriber + Send + Sync
    where
        W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
    {
        let filter = || {
            EnvFilter::try_new(&self.directives)
                .unwrap_or_else(|_| EnvFilter::new("info"))
                .and(SuppressRuntimeUnauthorized)
        };

        let layer = if self.json {
            tracing_subscriber::fmt::layer()
                .fmt_fields(JsonFields::new())
                .event_format(LambdaJsonFormat {
                    service_name: self.service_name.clone(),
                })
                .with_writer(make_writer)
                .with_filter(filter())
                .boxed()
        } else {
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .without_time()
                .with_writer(make_writer)
                .with_filter(filter())
                .boxed()
        };

        Registry::default().with(layer)
    }
}

/// Lambda's levels include `FATAL`, which tracing doesn't have.
fn parse_level(level: &str) -> LevelFilter {
    if level.eq_ignore_ascii_case("fatal") {
        return LevelFilter::ERROR;
    }

    LevelFilter::from_str(level).unwrap_or(LevelFilter::INFO)
}

fn level_directives(level: LevelFilter) -> String {
    let mut directives = level.to_string();

    if level > LevelFilter::INFO {
        for target in NOISY_TARGETS {
            directives.push_str(&format!(",{target}=info"));
        }
    }

    directives
}

/// Drops `lambda_runtime`'s `ERROR` line for denied requests. A denial is expected traffic, and
/// the authorizer already logs it as a warning with the reason.
struct SuppressRuntimeUnauthorized;

impl<S> Filter<S> for SuppressRuntimeUnauthorized {
    fn enabled(&self, _metadata: &Metadata<'_>, _cx: &Context<'_, S>) -> bool {
        true
    }

    fn event_enabled(&self, event: &Event<'_>, _cx: &Context<'_, S>) -> bool {
        if event.metadata().target() != RUNTIME_HANDLER_ERROR_TARGET {
            return true;
        }

        let mut fields = FieldVisitor::default();
        event.record(&mut fields);

        // The runtime logs the handler's error with `{:?}`, which is `Unauthorized` for a denial.
        fields.message.as_deref() != Some("Unauthorized")
    }
}

struct LambdaJsonFormat {
    service_name: String,
}

impl<S, N> FormatEvent<S, N> for LambdaJsonFormat
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut timestamp = String::new();
        SystemTime.format_time(&mut Writer::new(&mut timestamp))?;

        let mut fields = FieldVisitor::default();
        event.record(&mut fields);

        let mut entries = vec![
            ("timestamp".to_owned(), Value::String(timestamp)),
            (
                "level".to_owned(),
                Value::String(event.metadata().level().to_string()),
            ),
            (
                "message".to_owned(),
                Value::String(fields.message.unwrap_or_default()),
            ),
            (
                "service".to_owned(),
                Value::String(self.service_name.clone()),
            ),
        ];

        // Span fields, outermost first, e.g. lambda_runtime's `requestId` and `xrayTraceId`.
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                let extensions = span.extensions();
                let Some(formatted) = extensions.get::<FormattedFields<N>>() else {
                    continue;
                };
                let Ok(span_fields) = serde_json::from_str::<Map<String, Value>>(formatted) else {
                    continue;
                };

                entries.extend(
                    span_fields
                        .into_iter()
                        .map(|(name, value)| (camel_case(&name), value)),
                );
            }
        }

        entries.extend(fields.fields);

        // Later entries win, so event fields override span fields with the same name.
        let mut line = Map::new();
        let mut order = Vec::new();
        for (name, value) in entries {
            if line.insert(name.clone(), value).is_none() {
                order.push(name);
            }
        }

        let mut output = String::from("{");
        for (index, name) in order.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            output.push_str(&Value::String(name.clone()).to_string());
            output.push(':');
            output.push_str(&line[name].to_string());
        }
        output.push('}');

        writeln!(writer, "{output}")
    }
}

#[derive(Default)]
struct FieldVisitor {
    message: Option<String>,
    fields: Vec<(String, Value)>,
}

impl FieldVisitor {
    fn record(&mut self, field: &Field, value: Value) {
        match (field.name(), value) {
            ("message", Value::String(message)) => self.message = Some(message),
            ("details", Value::String(details)) => {
                let value = match serde_json::from_str::<Value>(&details) {
                    Ok(object @ Value::Object(_)) => object,
                    _ => Value::String(details),
                };
                self.fields.push(("details".to_owned(), value));
            }
            (name, value) => self.fields.push((camel_case(name), value)),
        }
    }
}

impl Visit for FieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.record(field, Value::String(value.to_owned()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record(field, Value::Bool(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record(field, value.into());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record(field, value.into());
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.record(field, value.into());
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.record(field, Value::String(value.to_string()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.record(field, Value::String(format!("{value:?}")));
    }
}

/// Converts tracing's snake_case field names to the camelCase used by Lambda's own fields.
fn camel_case(name: &str) -> String {
    let mut parts = name.split('_');
    let mut output = parts.next().unwrap_or_default().to_owned();

    for part in parts {
        let mut chars = part.chars();
        if let Some(first) = chars.next() {
            output.extend(first.to_uppercase());
            output.push_str(chars.as_str());
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_field_names_to_camel_case() {
        assert_eq!(camel_case("token_length"), "tokenLength");
        assert_eq!(camel_case("has_jwks_uri"), "hasJwksUri");
        assert_eq!(camel_case("requestId"), "requestId");
        assert_eq!(camel_case("reason"), "reason");
    }

    #[test]
    fn parses_lambda_log_levels() {
        assert_eq!(parse_level("DEBUG"), LevelFilter::DEBUG);
        assert_eq!(parse_level("warn"), LevelFilter::WARN);
        assert_eq!(parse_level("FATAL"), LevelFilter::ERROR);
        assert_eq!(parse_level("nonsense"), LevelFilter::INFO);
    }

    #[test]
    fn keeps_dependencies_at_info_when_debugging() {
        assert_eq!(level_directives(LevelFilter::WARN), "warn");
        assert_eq!(level_directives(LevelFilter::INFO), "info");
        assert_eq!(
            level_directives(LevelFilter::DEBUG),
            "debug,h2=info,hyper=info,hyper_util=info,reqwest=info,rustls=info,tower=info"
        );
    }
}
