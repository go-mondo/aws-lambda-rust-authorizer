# @go-mondo/aws-lambda-rust-authorizer

AWS Lambda Rust authorizers for Mondo Identity, with AWS CDK constructs.

This is a Rust port of
[`@go-mondo/aws-lambda-nodejs-authorizer`](https://github.com/go-mondo/aws-lambda-nodejs-authorizer).
The repository contains two packages that ship together:

- `mondo-lambda-authorizer`, a Rust crate with the authorizer library and the packaged
  `mondo-rest-api-authorizer` Lambda binary.
- `@go-mondo/aws-lambda-rust-authorizer`, an npm package with CDK constructs that build that crate
  with [cargo-lambda](https://www.cargo-lambda.info/).

## CDK REST API

Create the authorizer Lambda and wire it into API Gateway.

```ts
import { Duration } from "aws-cdk-lib";
import * as apigateway from "aws-cdk-lib/aws-apigateway";
import {
  MondoAuthorizer,
  MondoAuthorizerHandler,
} from "@go-mondo/aws-lambda-rust-authorizer/cdk-rest-api";

const authorizerHandler = new MondoAuthorizerHandler(this, "MondoAuthorizerHandler", {
  additionalContextClaims: {
    scopes: "scope",
  },
  audience: "https://app.mondoidentity.com",
  domainName: "mondo.auth.mondoidentity.com",
  requiredClaims: {
    scope: ["openid", "email"],
  },
});

const authorizer = new MondoAuthorizer(this, "MondoAuthorizer", {
  handler: authorizerHandler,
  resultsCacheTtl: Duration.minutes(5),
});

new apigateway.RestApi(this, "Api").root.addMethod("GET", integration, {
  authorizationType: apigateway.AuthorizationType.CUSTOM,
  authorizer,
});
```

`MondoAuthorizer` is a thin `apigateway.TokenAuthorizer` subclass with Mondo-friendly defaults, and
`MondoAuthorizerHandler` is a cargo-lambda-cdk `RustFunction` that builds the Rust handler shipped
in this package for `provided.al2023` on arm64, with JSON logging enabled. Any `RustFunction` prop
can be overridden.

Synthesizing builds the handler, so `cargo-lambda` (with Rust and Zig) must be installed. Without
it, cargo-lambda-cdk falls back to building in Docker.

The Lambda handler parses bearer tokens, discovers issuer and JWKS metadata from
`/.well-known/openid-configuration`, verifies JWTs, validates issuer, audience, and expiration,
then returns `tenantId`, `appId`, and `userId` in the authorizer context. The discovery document
and JWKS are cached for the lifetime of the Lambda execution environment, and the JWKS is reloaded
when a token's `kid` is not found, so signing-key rotation is picked up automatically. Refreshes
happen at most every 30 seconds, and if one fails, the cached keys stay in use. If the first fetch
of either document fails, requests fail with a 500 without contacting the IdP for 30 seconds, then
the fetch is retried, so an unreachable IdP doesn't hold every request until its 5-second timeout.

By default the returned policy allows every method and path in the requested API stage (for
example `.../a1b2c3d4e5/prod/*/*`), not just the requested `methodArn`. API Gateway caches
authorizer results per token, so a policy for a single method would wrongly deny that token's
other requests until the cache expires. Set `policyStatement.resource` to narrow it.

Additional claim validation can be configured through `MONDO_REQUIRED_CLAIMS`, additional context
values can be mapped through `MONDO_CONTEXT_CLAIMS`, and the returned IAM statement can be
customized with `MONDO_POLICY_STATEMENT`.

### Environment variables

| Variable                 | Construct prop            | Format                                                                                                 |
| ------------------------ | ------------------------- | ------------------------------------------------------------------------------------------------------ |
| `MONDO_IDP_DOMAIN_NAME`  | `domainName`              | Domain or URL, e.g. `mondo.auth.mondoidentity.com` (required)                                          |
| `MONDO_AUDIENCE`         | `audience`                | String, or JSON array of strings when it starts with `[` (required)                                    |
| `MONDO_REQUIRED_CLAIMS`  | `requiredClaims`          | JSON object of claim name to expected value; arrays must all be present                                |
| `MONDO_CONTEXT_CLAIMS`   | `additionalContextClaims` | JSON object of context key to claim name                                                               |
| `MONDO_POLICY_STATEMENT` | `policyStatement`         | JSON object with optional `action`, `effect` (`Allow`/`Deny`), and `resource`; other keys are rejected |

`MondoAuthorizerHandler` fails synthesis when `MONDO_IDP_DOMAIN_NAME` or `MONDO_AUDIENCE` is
missing, whether you set them through props, `environment`, or `addEnvironment`. The handler reads
its configuration once at cold start. If a required variable is missing or a value is invalid
anyway, the function fails to initialize, and API Gateway returns a 500.

### Logging

`MondoAuthorizerHandler` enables Lambda's JSON log format. Each log line is a JSON object with
top-level `timestamp`, `level`, `message`, `service`, `requestId`, and `xrayTraceId`, followed by
the event's fields in camelCase. Structured details, such as why a request was denied, are a nested
`details` object:

```json
{
  "timestamp": "2026-11-16T16:56:30.734248Z",
  "level": "WARN",
  "message": "REST API authorizer request denied",
  "service": "mondo-rest-api-authorizer",
  "requestId": "19d1c50e-f448-4021-8347-6290a0831372",
  "xrayTraceId": "Root=1-6afb35bd-b7eecb6e92dfcfea5aa1c1bb;Parent=ccd2577dc4855687;Sampled=1",
  "reason": "authorization_header_missing_or_malformed",
  "details": { "authorizationScheme": "Basic", "hasAuthorizationToken": true }
}
```

Denied requests log a single `WARN` line with a `reason`, and each failure that returns a 500 logs
a single `ERROR` line, `Authorizer failed`, so `ERROR` counts track failed requests. The level follows the function's application log level
(`applicationLogLevelV2`, which sets `AWS_LAMBDA_LOG_LEVEL`), then `RUST_LOG`, defaulting to
`INFO`. At `DEBUG` and `TRACE`, the HTTP client libraries stay at `INFO`.

For example, to count denials by reason in CloudWatch Logs Insights:

```
filter message = "REST API authorizer request denied"
| stats count(*) by reason
```

Custom handlers get the same output by calling `mondo_lambda_authorizer::logging::init()`, or
`LogConfig::from_env().with_service_name("my-authorizer").init()` to set their own `service`.

## Custom Handler

Use the Rust crate when your API needs custom validation, context, or policy decisions. The
`Authorizer` still handles bearer-token parsing, OIDC discovery, JWKS lookup, and JWT verification
before your hooks run.

Create a binary crate that depends on the library:

```toml
[dependencies]
lambda_runtime = "1"
mondo-lambda-authorizer = { git = "https://github.com/go-mondo/aws-lambda-rust-authorizer" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust
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
```

`build_context` receives the default and `MONDO_CONTEXT_CLAIMS` context and returns the context to
send, so it can also replace or remove entries, such as dropping `appId`. Errors from
`build_context` and `build_policy_statement` fail the request with a 500,
unless the error is `Error::Unauthorized`, which denies it.

This example decides per method and returns a policy for the requested `methodArn` only. Because
API Gateway caches results per token, turn result caching off for an authorizer like this, as
below. Otherwise a cached decision for one method is reused for the token's other requests.

Then point the helper construct at your crate. Set `binaryName` too if the crate has more than one
binary.

```ts
const authorizerHandler = new MondoAuthorizerHandler(this, "MondoAuthorizerHandler", {
  manifestPath: "authorizers/mondo-rest-api/Cargo.toml",
  environment: {
    EXPECTED_MONDO_APP_ID: "app_123",
  },
  domainName: "mondo.auth.mondoidentity.com",
  audience: "https://app.mondoidentity.com",
});

const authorizer = new MondoAuthorizer(this, "MondoAuthorizer", {
  handler: authorizerHandler,
  resultsCacheTtl: Duration.seconds(0),
});
```

## Migrating from the Node.js authorizer

Apps that use the packaged handler through `MondoAuthorizerHandler` can switch by changing the
import. The class names and Mondo props (`domainName`, `audience`, `requiredClaims`,
`additionalContextClaims`, `policyStatement`) are unchanged, and the authorizer returns the same
`principalId` and context keys, so API integrations and backends need no changes.

1. Install the Rust build toolchain wherever `cdk synth` runs, including CI: Rust,
   [cargo-lambda](https://www.cargo-lambda.info/guide/installation.html), and Zig. Without
   cargo-lambda, the build falls back to Docker, which is slower. Caching Cargo's `target`
   directory in CI keeps repeat builds fast.
2. Swap the package and the import path:

   ```diff
   - import { MondoAuthorizer, MondoAuthorizerHandler } from "@go-mondo/aws-lambda-nodejs-authorizer/cdk-rest-api";
   + import { MondoAuthorizer, MondoAuthorizerHandler } from "@go-mondo/aws-lambda-rust-authorizer/cdk-rest-api";
   ```

3. Remove props that only apply to `NodejsFunction`, such as `entry`, `handler`, `runtime`, and
   esbuild `bundling` options. TypeScript flags them. Common `lambda.Function` props such as
   `memorySize`, `timeout`, and `environment` still work.
4. Deploy. With the same construct IDs, CloudFormation updates the existing function in place: the
   runtime changes from `nodejs24.x` to `provided.al2023` and the architecture from x86_64 to
   arm64, while the function ARN, the API Gateway authorizer, and your methods stay the same. To
   roll back, revert the import and deploy again.

Behavior that differs from the Node.js authorizer:

- **Log format.** Lines keep the Powertools logger's top-level `timestamp`, `level`, `message`,
  and `service` keys, so queries on those carry over. Other fields change:
  - Denial attributes move from top-level keys into a nested `details` object (for example
    `claimName` becomes `details.claimName`); `reason` stays top-level.
  - `Token verified` reports its claims under `details` instead of `context`.
  - Lines inside an invocation now include `requestId` and `xrayTraceId` (Powertools used
    `xray_trace_id`), and Powertools' `sampling_rate` is gone.
  - The Node.js runtime also logged every thrown error, including denials, as an `ERROR`
    "Invoke Error" line. The Rust authorizer logs a denial once, as `WARN`, so alarms on `ERROR`
    counts now track only real failures.

  See [Logging](#logging).
- **Default policy resource.** The default policy allows every method and path in the requested
  API stage instead of only the requested `methodArn`, so cached results no longer deny the same
  token's requests to other endpoints. A `policyStatement.resource` you set still takes precedence.
- **Response format.** The policy statement's `Action` and `Resource` are always arrays, such as
  `"Action": ["execute-api:Invoke"]` where the Node.js authorizer returned
  `"Action": "execute-api:Invoke"`, and the response includes `"usageIdentifierKey": null`. API
  Gateway treats both forms the same. This only matters for something that reads the Lambda's
  output directly, such as a test that invokes the function and compares the response.
- **Configuration checks.** Synthesis fails when the IdP domain or audience is missing. A string
  `audience` starting with `[` is rejected; pass an array instead. `MONDO_POLICY_STATEMENT` accepts
  only `action`, `effect`, and `resource`. Any other key, such as an IAM-style `Effect`, makes the
  function fail to initialize instead of being ignored.
- **Signing-key outages.** If refreshing the JWKS fails, the authorizer keeps using the keys it
  already has instead of failing requests. If the first fetch of the discovery document or JWKS
  fails, requests fail without contacting the IdP for 30 seconds before it's retried.

Apps with a custom handler built with `createRestApiAuthorizerHandler` need their callbacks ported
to Rust as `AuthorizerHooks` methods: `validateClaims` becomes `validate_claims`,
`buildPolicyStatement` becomes `build_policy_statement`, and `buildAdditionalContext` becomes
`build_context`. `build_context` receives the assembled context and returns the final one, so
instead of returning `{ key: undefined }` to drop a key, call `context.remove("key")`.

`build_policy_statement` returns a `PolicyStatementOverride`, whose fields are `Option`s.
`action` and `resource` are lists of strings even when there's a single value, and `effect` is an
`IamPolicyEffect`:

```diff
- return { effect: "Deny", resource: methodArn };
+ Ok(PolicyStatementOverride {
+     effect: Some(IamPolicyEffect::Deny),
+     resource: Some(vec![input.method_arn.to_owned()]),
+     ..Default::default()
+ })
```

The event and response use the standard
[`aws_lambda_events`](https://docs.rs/aws_lambda_events) types,
`ApiGatewayCustomAuthorizerRequest` and `ApiGatewayCustomAuthorizerResponse`. They're re-exported
from `mondo_lambda_authorizer::rest_api`, along with `IamPolicyEffect` and `IamPolicyStatement`,
so you don't need to add `aws_lambda_events` as a dependency. Those types are `#[non_exhaustive]`,
so build one from `Default::default()` and set its fields rather than with a struct literal. See
[Custom Handler](#custom-handler).

## Development

```sh
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
pnpm install && pnpm check && pnpm build
cargo lambda build --release --arm64   # optional: build the Lambda binary locally
```

The npm package publishes `Cargo.toml`, `Cargo.lock`, and `src/**/*.rs` so the construct can build
the handler from `node_modules`. Keep the versions in `Cargo.toml` and `package.json` in sync.
