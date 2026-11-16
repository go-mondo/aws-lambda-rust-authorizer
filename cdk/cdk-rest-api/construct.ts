import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Duration, Stack } from "aws-cdk-lib";
import * as apigateway from "aws-cdk-lib/aws-apigateway";
import * as lambda from "aws-cdk-lib/aws-lambda";
import { RustFunction, type RustFunctionProps } from "cargo-lambda-cdk";
import type { Construct } from "constructs";

export type ClaimExpectation = string | number | boolean | string[] | number[] | boolean[];

export interface PolicyStatementOverride {
  readonly action?: string | string[];
  readonly effect?: "Allow" | "Deny";
  readonly resource?: string | string[];
}

export type MondoAuthorizerProps = apigateway.TokenAuthorizerProps;

/**
 * Name of the packaged authorizer binary in this package's `Cargo.toml`.
 */
export const DEFAULT_AUTHORIZER_BINARY_NAME = "mondo-rest-api-authorizer";

export interface MondoAuthorizerHandlerProps extends RustFunctionProps {
  /**
   * Mondo IdP domain or URL used to discover OpenID Provider metadata.
   *
   * Examples: `mondo.auth.mondoidentity.com` or `https://mondo.auth.mondoidentity.com`.
   */
  readonly domainName?: string;

  /**
   * Expected JWT audience. A token must match at least one value.
   */
  readonly audience?: string | string[];

  /**
   * Additional exact-match claim requirements evaluated after JWT verification.
   *
   * Arrays mean the JWT claim must contain every configured value. This works for either array
   * claims or space-delimited string claims such as `scope`.
   */
  readonly requiredClaims?: Record<string, ClaimExpectation>;

  /**
   * Additional context values to return from the authorizer.
   *
   * Keys become API Gateway context keys. Values are JWT claim paths, such as `email` or
   * `https://example.com/custom_claim`.
   */
  readonly additionalContextClaims?: Record<string, string>;

  /**
   * Overrides the IAM policy statement returned by the authorizer Lambda.
   *
   * Omitted fields default to `execute-api:Invoke`, `Allow`, and every method and path in the
   * incoming `event.methodArn`'s API stage, so a policy cached by API Gateway for a token applies to
   * every endpoint that token calls.
   */
  readonly policyStatement?: PolicyStatementOverride;
}

/**
 * Environment variables the authorizer cannot start without.
 */
const REQUIRED_ENVIRONMENT = ["MONDO_IDP_DOMAIN_NAME", "MONDO_AUDIENCE"] as const;

/**
 * A `RustFunction` that builds the packaged Mondo authorizer with cargo-lambda.
 *
 * Set `manifestPath` (and `binaryName`, if needed) to build a custom handler crate instead.
 *
 * Synthesis fails if `MONDO_IDP_DOMAIN_NAME` or `MONDO_AUDIENCE` is not set, through `domainName`
 * and `audience`, `environment`, or `addEnvironment`.
 */
export class MondoAuthorizerHandler extends RustFunction {
  public constructor(scope: Construct, id: string, props: MondoAuthorizerHandlerProps = {}) {
    const usesPackagedHandler = props.manifestPath === undefined && props.gitRemote === undefined;

    super(scope, id, {
      architecture: props.bundling?.architecture ?? lambda.Architecture.ARM_64,
      loggingFormat: lambda.LoggingFormat.JSON,
      ...props,
      binaryName:
        props.binaryName ?? (usesPackagedHandler ? DEFAULT_AUTHORIZER_BINARY_NAME : undefined),
      environment: {
        ...buildMondoEnvironment(props),
        ...props.environment,
      },
      manifestPath: usesPackagedHandler ? defaultManifestPath() : props.manifestPath,
    });

    this.node.addValidation({ validate: () => this.validateEnvironment() });
  }

  private validateEnvironment(): string[] {
    const cfnFunction = this.node.defaultChild as lambda.CfnFunction;
    const environment = Stack.of(this).resolve(cfnFunction.environment) as
      | { variables?: Record<string, unknown> }
      | undefined;
    const variables = environment?.variables ?? {};

    return REQUIRED_ENVIRONMENT.filter((name) => !variables[name]).map(
      (name) =>
        `${name} is required: set ${name === "MONDO_AUDIENCE" ? "audience" : "domainName"} or the ${name} environment variable`,
    );
  }
}

export class MondoAuthorizer extends apigateway.TokenAuthorizer {
  public constructor(scope: Construct, id: string, props: MondoAuthorizerProps) {
    super(scope, id, {
      identitySource: apigateway.IdentitySource.header("Authorization"),
      resultsCacheTtl: Duration.minutes(5),
      ...props,
    });
  }
}

function buildMondoEnvironment(props: MondoAuthorizerHandlerProps): Record<string, string> {
  const environment: Record<string, string> = {};

  if (props.audience !== undefined) {
    if (props.audience.length === 0 || [props.audience].flat().some((value) => !value)) {
      throw new Error("audience must be a non-empty string or array of non-empty strings");
    }

    // The handler parses MONDO_AUDIENCE values starting with `[` as a JSON array.
    if (typeof props.audience === "string" && props.audience.trim().startsWith("[")) {
      throw new Error("audience strings must not start with '['; pass an array instead");
    }

    environment.MONDO_AUDIENCE =
      typeof props.audience === "string" ? props.audience : JSON.stringify(props.audience);
  }

  if (props.domainName) {
    environment.MONDO_IDP_DOMAIN_NAME = props.domainName;
  }

  if (props.requiredClaims) {
    environment.MONDO_REQUIRED_CLAIMS = JSON.stringify(props.requiredClaims);
  }

  if (props.additionalContextClaims) {
    environment.MONDO_CONTEXT_CLAIMS = JSON.stringify(props.additionalContextClaims);
  }

  if (props.policyStatement) {
    environment.MONDO_POLICY_STATEMENT = JSON.stringify(props.policyStatement);
  }

  return environment;
}

function defaultManifestPath(): string {
  const currentDirectory = dirname(fileURLToPath(import.meta.url));

  // Resolves to the package root from both `cdk/cdk-rest-api` and `dist/cdk-rest-api`.
  return join(currentDirectory, "../../Cargo.toml");
}
