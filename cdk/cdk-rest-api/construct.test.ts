import { App, Stack } from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";
import { RestApi } from "aws-cdk-lib/aws-apigateway";
import { Architecture } from "aws-cdk-lib/aws-lambda";
import { describe, expect, it } from "vitest";
import { MondoAuthorizer, MondoAuthorizerHandler } from "./construct.js";

function createStack(): Stack {
  // Skip cargo-lambda bundling so tests don't compile the Rust handler.
  const app = new App({ context: { "aws:cdk:bundling-stacks": [] } });

  return new Stack(app, "TestStack");
}

describe("MondoAuthorizer", () => {
  it("creates a REST API token authorizer for an explicit Lambda handler", () => {
    const stack = createStack();

    const handler = new MondoAuthorizerHandler(stack, "MondoAuthorizerHandler", {
      additionalContextClaims: {
        scopes: "scope",
      },
      audience: "https://app.mondoidentity.com",
      environment: {
        EXPECTED_MONDO_APP_ID: "app_123",
      },
      domainName: "mondo.auth.mondoidentity.com",
      requiredClaims: {
        scope: ["openid", "email"],
      },
    });
    handler.addEnvironment("CUSTOM_VALIDATION_MODE", "strict");

    const authorizer = new MondoAuthorizer(stack, "MondoAuthorizer", {
      handler,
    });

    const api = new RestApi(stack, "Api");
    api.root.addMethod("GET", undefined, {
      authorizer,
    });

    const template = Template.fromStack(stack);

    template.hasResourceProperties("AWS::Lambda::Function", {
      Architectures: ["arm64"],
      Environment: {
        Variables: {
          MONDO_AUDIENCE: "https://app.mondoidentity.com",
          MONDO_CONTEXT_CLAIMS: '{"scopes":"scope"}',
          MONDO_IDP_DOMAIN_NAME: "mondo.auth.mondoidentity.com",
          MONDO_REQUIRED_CLAIMS: '{"scope":["openid","email"]}',
          CUSTOM_VALIDATION_MODE: "strict",
          EXPECTED_MONDO_APP_ID: "app_123",
        },
      },
      Handler: "bootstrap",
      LoggingConfig: {
        LogFormat: "JSON",
      },
      Runtime: "provided.al2023",
    });

    template.hasResourceProperties("AWS::ApiGateway::Authorizer", {
      AuthorizerResultTtlInSeconds: 300,
      IdentitySource: "method.request.header.Authorization",
      Type: "TOKEN",
    });
    template.resourceCountIs("AWS::ApiGateway::Authorizer", 1);
    expect(authorizer.authorizerId).toBeDefined();
  });

  it("fails synthesis when the IdP domain or audience is missing", () => {
    const stack = createStack();

    new MondoAuthorizerHandler(stack, "MondoAuthorizerHandler", {
      domainName: "mondo.auth.mondoidentity.com",
    });

    expect(() => App.of(stack)?.synth()).toThrow(/MONDO_AUDIENCE is required/);
  });

  it("accepts required settings added through addEnvironment", () => {
    const stack = createStack();

    const handler = new MondoAuthorizerHandler(stack, "MondoAuthorizerHandler", {
      environment: { MONDO_IDP_DOMAIN_NAME: "mondo.auth.mondoidentity.com" },
    });
    handler.addEnvironment("MONDO_AUDIENCE", "https://app.mondoidentity.com");

    expect(() => App.of(stack)?.synth()).not.toThrow();
  });

  it("rejects empty audiences", () => {
    const stack = createStack();

    expect(
      () =>
        new MondoAuthorizerHandler(stack, "MondoAuthorizerHandler", {
          audience: [],
          domainName: "mondo.auth.mondoidentity.com",
        }),
    ).toThrow(/audience must be/);
    expect(
      () =>
        new MondoAuthorizerHandler(stack, "BracketAudienceHandler", {
          audience: "[prod] api",
          domainName: "mondo.auth.mondoidentity.com",
        }),
    ).toThrow(/must not start with '\['/);
  });

  it("serializes audience arrays and policy statements, and allows architecture overrides", () => {
    const stack = createStack();

    new MondoAuthorizerHandler(stack, "MondoAuthorizerHandler", {
      architecture: Architecture.X86_64,
      audience: ["https://app.mondoidentity.com", "https://admin.mondoidentity.com"],
      domainName: "mondo.auth.mondoidentity.com",
      policyStatement: {
        effect: "Deny",
      },
    });

    Template.fromStack(stack).hasResourceProperties("AWS::Lambda::Function", {
      Architectures: ["x86_64"],
      Environment: {
        Variables: {
          MONDO_AUDIENCE: '["https://app.mondoidentity.com","https://admin.mondoidentity.com"]',
          MONDO_POLICY_STATEMENT: '{"effect":"Deny"}',
        },
      },
    });
  });
});
