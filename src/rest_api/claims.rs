use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value, json};

use super::error::{Error, unauthorized};

/// Verified JWT payload.
pub type Claims = Map<String, Value>;

/// API Gateway authorizer context. Values must be strings, numbers, or booleans.
pub type Context = BTreeMap<String, ScalarValue>;

/// Context keys and the claims they're read from, returned by every Mondo authorizer.
const DEFAULT_CONTEXT_CLAIMS: [(&str, &str); 3] =
    [("appId", "azp"), ("tenantId", "tnt"), ("userId", "sub")];

/// A string, number, or boolean, as accepted by API Gateway authorizer context.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ScalarValue {
    String(String),
    Number(Number),
    Bool(bool),
}

impl ScalarValue {
    /// Formats the value the way JavaScript's `String(value)` would.
    pub fn to_js_string(&self) -> String {
        match self {
            Self::String(value) => value.clone(),
            Self::Number(value) => js_number_string(value),
            Self::Bool(value) => value.to_string(),
        }
    }

    fn matches(&self, actual: &Value) -> bool {
        match (self, actual) {
            (Self::String(expected), Value::String(actual)) => expected == actual,
            (Self::Bool(expected), Value::Bool(actual)) => expected == actual,
            (Self::Number(expected), Value::Number(actual)) => expected.as_f64() == actual.as_f64(),
            _ => false,
        }
    }
}

impl From<String> for ScalarValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for ScalarValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<bool> for ScalarValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<i64> for ScalarValue {
    fn from(value: i64) -> Self {
        Self::Number(value.into())
    }
}

impl From<u64> for ScalarValue {
    fn from(value: u64) -> Self {
        Self::Number(value.into())
    }
}

impl From<Number> for ScalarValue {
    fn from(value: Number) -> Self {
        Self::Number(value)
    }
}

/// An additional claim requirement evaluated after JWT verification.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ClaimExpectation {
    /// The claim must contain every value. Works for array claims and space-delimited string
    /// claims such as `scope`.
    ContainsAll(Vec<ScalarValue>),
    /// The claim must strictly equal the value.
    Equals(ScalarValue),
}

/// Reads a claim as a context-safe string. Arrays are joined with spaces; objects are ignored.
pub fn get_claim(claims: &Claims, claim_name: &str) -> Option<String> {
    stringify_context_value(claims.get(claim_name))
}

/// Reads a scope-like claim from either a space-delimited string or an array.
pub fn get_scopes(claims: &Claims, claim_name: &str) -> Vec<String> {
    normalize_claim_values(claims.get(claim_name))
}

pub fn assert_required_claims(
    claims: &Claims,
    required_claims: &BTreeMap<String, ClaimExpectation>,
) -> Result<(), Error> {
    for (claim_name, expected) in required_claims {
        let actual = claims.get(claim_name);

        match expected {
            ClaimExpectation::ContainsAll(expected) => {
                let actual_values = normalize_claim_values(actual);
                let expected_values: Vec<String> =
                    expected.iter().map(ScalarValue::to_js_string).collect();
                let missing_values: Vec<&String> = expected_values
                    .iter()
                    .filter(|value| !actual_values.contains(value))
                    .collect();

                if !missing_values.is_empty() {
                    return Err(unauthorized(
                        "required_claim_values_missing",
                        json!({
                            "actualValues": actual_values,
                            "claimName": claim_name,
                            "expectedValues": expected_values,
                            "missingExpectedValues": missing_values,
                        }),
                    ));
                }
            }
            ClaimExpectation::Equals(expected) => {
                if !actual.is_some_and(|actual| expected.matches(actual)) {
                    return Err(unauthorized(
                        "required_claim_mismatch",
                        json!({
                            "actualValue": actual.map(summarize_log_value),
                            "claimName": claim_name,
                            "expectedValue": expected,
                            "hasClaim": actual.is_some(),
                        }),
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Builds the `tenantId`, `appId`, and `userId` context returned by every Mondo authorizer.
pub fn build_default_context(claims: &Claims) -> Context {
    build_mapped_context(claims, DEFAULT_CONTEXT_CLAIMS)
}

/// Maps context keys to claim names, skipping claims that are missing or not context-safe.
/// `claim_mappings` can be any `(context key, claim name)` pairs, such as a
/// `&BTreeMap<String, String>` or an array of `(&str, &str)`.
pub fn build_mapped_context<K, C>(
    claims: &Claims,
    claim_mappings: impl IntoIterator<Item = (K, C)>,
) -> Context
where
    K: AsRef<str>,
    C: AsRef<str>,
{
    claim_mappings
        .into_iter()
        .filter_map(|(context_key, claim_name)| {
            get_claim(claims, claim_name.as_ref())
                .map(|value| (context_key.as_ref().to_owned(), value.into()))
        })
        .collect()
}

pub(crate) fn safe_claim_log_context(claims: &Claims) -> Value {
    let context: BTreeMap<&str, String> = [
        ("appId", "azp"),
        ("audience", "aud"),
        ("issuer", "iss"),
        ("subject", "sub"),
        ("tenantId", "tnt"),
    ]
    .into_iter()
    .filter_map(|(key, claim_name)| get_claim(claims, claim_name).map(|value| (key, value)))
    .collect();

    json!(context)
}

fn stringify_context_value(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::Null | Value::Object(_) => None,
        Value::Array(items) => Some(items.iter().map(js_string).collect::<Vec<_>>().join(" ")),
        value => Some(js_string(value)),
    }
}

fn normalize_claim_values(value: Option<&Value>) -> Vec<String> {
    match value {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items.iter().map(js_string).collect(),
        Some(Value::String(value)) => value.split_whitespace().map(str::to_owned).collect(),
        Some(value) => vec![js_string(value)],
    }
}

/// Formats a JSON value the way JavaScript's `String(value)` would.
fn js_string(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => js_number_string(value),
        Value::String(value) => value.clone(),
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::Null => String::new(),
                item => js_string(item),
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".to_owned(),
    }
}

fn js_number_string(value: &Number) -> String {
    match value.as_f64() {
        Some(float) if value.is_f64() => js_float_string(float),
        // Integers within `i64`/`u64` print the same way in both languages.
        _ => value.to_string(),
    }
}

/// Formats a float the way JavaScript's `Number.prototype.toString` does.
fn js_float_string(value: f64) -> String {
    if value == 0.0 {
        return "0".to_owned();
    }

    if value.abs() >= 1e21 || value.abs() < 1e-6 {
        // Both languages print the shortest round-tripping digits, but JavaScript always signs
        // the exponent: `1e+21`, `1.5e-7`.
        let formatted = format!("{value:e}");
        return match formatted.split_once('e') {
            Some((mantissa, exponent)) if !exponent.starts_with('-') => {
                format!("{mantissa}e+{exponent}")
            }
            _ => formatted,
        };
    }

    // `f64`'s Display prints whole floats without a fraction (`2.0` as `2`), like JavaScript,
    // whereas `Number`'s Display keeps it.
    value.to_string()
}

fn summarize_log_value(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(summarize_log_value).collect()),
        Value::Object(_) => Value::String("[object]".to_owned()),
        value => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(value: Value) -> Claims {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn builds_default_mondo_context_from_token_claims() {
        let context = build_default_context(&claims(json!({
            "azp": "app_123",
            "sub": "usr_123",
            "tnt": "tnt_123",
        })));

        assert_eq!(
            context,
            Context::from([
                ("appId".to_owned(), "app_123".into()),
                ("tenantId".to_owned(), "tnt_123".into()),
                ("userId".to_owned(), "usr_123".into()),
            ])
        );
    }

    #[test]
    fn maps_additional_context_claims() {
        let context = build_mapped_context(
            &claims(json!({
                "email": "user@example.com",
                "roles": ["admin", "operator"],
            })),
            &BTreeMap::from([
                ("email".to_owned(), "email".to_owned()),
                ("roles".to_owned(), "roles".to_owned()),
                ("missing".to_owned(), "missing".to_owned()),
            ]),
        );

        assert_eq!(
            context,
            Context::from([
                ("email".to_owned(), "user@example.com".into()),
                ("roles".to_owned(), "admin operator".into()),
            ])
        );
    }

    #[test]
    fn reads_claims_as_context_safe_strings() {
        let claims = claims(json!({
            "enabled": true,
            "email": "user@example.com",
            "roles": ["admin", "operator"],
            "version": 2,
            "ratio": 2.0,
            "nested": { "a": 1 },
        }));

        assert_eq!(
            get_claim(&claims, "email").as_deref(),
            Some("user@example.com")
        );
        assert_eq!(
            get_claim(&claims, "roles").as_deref(),
            Some("admin operator")
        );
        assert_eq!(get_claim(&claims, "version").as_deref(), Some("2"));
        assert_eq!(get_claim(&claims, "ratio").as_deref(), Some("2"));
        assert_eq!(get_claim(&claims, "enabled").as_deref(), Some("true"));
        assert_eq!(get_claim(&claims, "nested"), None);
        assert_eq!(get_claim(&claims, "missing"), None);
    }

    #[test]
    fn reads_scopes_from_string_or_array_claims() {
        assert_eq!(
            get_scopes(
                &claims(json!({ "scope": "openid  profile email" })),
                "scope"
            ),
            ["openid", "profile", "email"]
        );
        assert_eq!(
            get_scopes(
                &claims(json!({ "permissions": ["api:read", "api:write"] })),
                "permissions"
            ),
            ["api:read", "api:write"]
        );
        assert!(get_scopes(&claims(json!({})), "scope").is_empty());
    }

    #[test]
    fn validates_required_claims() {
        let required: BTreeMap<String, ClaimExpectation> = serde_json::from_value(
            json!({ "scope": ["openid", "email"], "tnt": "tnt_123", "ver": 2 }),
        )
        .unwrap();

        assert!(
            assert_required_claims(
                &claims(json!({ "scope": "openid profile email", "tnt": "tnt_123", "ver": 2.0 })),
                &required,
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_missing_required_claim_values() {
        let required: BTreeMap<String, ClaimExpectation> =
            serde_json::from_value(json!({ "scope": ["email"] })).unwrap();

        let error =
            assert_required_claims(&claims(json!({ "scope": "openid profile" })), &required)
                .unwrap_err();

        assert!(error.is_unauthorized());
    }

    #[test]
    fn rejects_required_claim_mismatches() {
        let required: BTreeMap<String, ClaimExpectation> =
            serde_json::from_value(json!({ "admin": true, "tnt": "tnt_123" })).unwrap();

        assert!(assert_required_claims(&claims(json!({ "admin": true })), &required).is_err());
        assert!(
            assert_required_claims(
                &claims(json!({ "admin": "true", "tnt": "tnt_123" })),
                &required
            )
            .is_err()
        );
    }

    #[test]
    fn formats_numbers_like_javascript() {
        assert_eq!(js_string(&json!(1)), "1");
        assert_eq!(js_string(&json!(1.5)), "1.5");
        assert_eq!(js_string(&json!(-3)), "-3");
        assert_eq!(js_string(&json!([1, null, "a"])), "1,,a");
        assert_eq!(js_string(&json!(2.0)), "2");
        assert_eq!(js_string(&json!(1e21)), "1e+21");
        assert_eq!(js_string(&json!(1.5e300)), "1.5e+300");
        assert_eq!(js_string(&json!(-1e21)), "-1e+21");
        assert_eq!(js_string(&json!(1e20)), "100000000000000000000");
        assert_eq!(js_string(&json!(1e-7)), "1e-7");
        assert_eq!(js_string(&json!(1.5e-7)), "1.5e-7");
        assert_eq!(js_string(&json!(0.000001)), "0.000001");
    }
}
