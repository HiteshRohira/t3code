/**
 * Oidc - OpenID Connect relying party: authorization code flow with PKCE against the org's IdP.
 *
 * @module Oidc
 */
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Schema from "effect/Schema";
import * as Base64 from "effect/encoding/Base64";
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/http";
import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from "jose";

import { ControlPlaneConfig, type OidcConfig } from "./Config.ts";
import * as Crypto from "./Crypto.ts";

export class OidcError extends Schema.TaggedError<OidcError>()("OidcError", {
  reason: Schema.String,
}) {
  override get message(): string {
    return this.reason;
  }
}

/** Who signed in, whichever protocol carried it. */
export interface Identity {
  readonly subject: string;
  readonly email: string;
  readonly name: string | null;
  readonly groups: ReadonlyArray<string>;
}

const Discovery = Schema.Struct({
  issuer: Schema.String,
  authorization_endpoint: Schema.String,
  token_endpoint: Schema.String,
  jwks_uri: Schema.String,
});
const TokenResponse = Schema.Struct({ id_token: Schema.String });
const Jwks = Schema.Struct({ keys: Schema.Array(Schema.Record(Schema.String, Schema.Unknown)) });

const IdTokenClaims = Schema.Struct({
  sub: Schema.String,
  email: Schema.String,
  email_verified: Schema.optional(Schema.Boolean),
  name: Schema.optional(Schema.String),
  nonce: Schema.optional(Schema.String),
});

const decodeIdTokenClaims = Schema.decodeUnknownEffect(IdTokenClaims);

export const identityOf = Effect.fn("Oidc.identityOf")(function* (
  payload: Record<string, unknown>,
  groupsClaim: string,
) {
  const claims = yield* decodeIdTokenClaims(payload).pipe(
    Effect.mapError(() => new OidcError({ reason: "id_token has no subject or email" })),
  );
  if (claims.email_verified === false) {
    return yield* new OidcError({ reason: "IdP has not verified this email" });
  }
  const groups = payload[groupsClaim];
  return {
    subject: claims.sub,
    email: claims.email.toLowerCase(),
    name: claims.name ?? null,
    groups: Array.isArray(groups)
      ? groups.filter((group): group is string => typeof group === "string")
      : [],
  } satisfies Identity;
});

export class Oidc extends Context.Service<
  Oidc,
  {
    readonly authorizationUrl: (input: {
      redirectUri: string;
      state: string;
      nonce: string;
      codeVerifier: string;
    }) => Effect.Effect<string, OidcError>;
    readonly exchange: (input: {
      code: string;
      redirectUri: string;
      codeVerifier: string;
      nonce: string;
    }) => Effect.Effect<Identity, OidcError>;
  }
>()("@t3tools/enterprise-control-plane/Oidc") {}

const failWith = (reason: string) => () => new OidcError({ reason });

export const make = Effect.fn("Oidc.make")(function* (config: OidcConfig) {
  const client = (yield* HttpClient.HttpClient).pipe(HttpClient.filterStatusOk);

  // Sign-ins are rare; reading discovery each time keeps IdP key rotation simple.
  const discover = client.get(`${config.issuer}/.well-known/openid-configuration`).pipe(
    Effect.flatMap(HttpClientResponse.schemaBodyJson(Discovery)),
    Effect.mapError(failWith("OIDC discovery failed")),
    Effect.filterOrFail(
      (discovery) => discovery.issuer.replace(/\/$/, "") === config.issuer,
      failWith("OIDC discovery issuer does not match the configured issuer"),
    ),
  );

  return Oidc.of({
    authorizationUrl: Effect.fn("Oidc.authorizationUrl")(function* (input) {
      const discovery = yield* discover;
      const url = new URL(discovery.authorization_endpoint);
      url.searchParams.set("response_type", "code");
      url.searchParams.set("client_id", config.clientId);
      url.searchParams.set("redirect_uri", input.redirectUri);
      url.searchParams.set("scope", config.scopes.join(" "));
      url.searchParams.set("state", input.state);
      url.searchParams.set("nonce", input.nonce);
      url.searchParams.set("code_challenge", Crypto.pkceChallenge(input.codeVerifier));
      url.searchParams.set("code_challenge_method", "S256");
      return url.toString();
    }),
    exchange: Effect.fn("Oidc.exchange")(function* (input) {
      const discovery = yield* discover;
      const basic = Base64.encode(
        `${encodeURIComponent(config.clientId)}:${encodeURIComponent(config.clientSecret)}`,
      );
      const tokens = yield* HttpClientRequest.post(discovery.token_endpoint).pipe(
        HttpClientRequest.setHeader("authorization", `Basic ${basic}`),
        HttpClientRequest.bodyUrlParams({
          grant_type: "authorization_code",
          code: input.code,
          redirect_uri: input.redirectUri,
          code_verifier: input.codeVerifier,
        }),
        client.execute,
        Effect.flatMap(HttpClientResponse.schemaBodyJson(TokenResponse)),
        Effect.mapError(failWith("OIDC token exchange failed")),
      );
      const jwks = yield* client
        .get(discovery.jwks_uri)
        .pipe(
          Effect.flatMap(HttpClientResponse.schemaBodyJson(Jwks)),
          Effect.mapError(failWith("cannot read the IdP's signing keys")),
        );
      const { payload } = yield* Effect.tryPromise({
        try: () =>
          jwtVerify(tokens.id_token, createLocalJWKSet(jwks as unknown as JSONWebKeySet), {
            issuer: discovery.issuer,
            audience: config.clientId,
          }),
        catch: (cause) =>
          new OidcError({ reason: cause instanceof Error ? cause.message : "invalid id_token" }),
      });
      if (payload["nonce"] !== input.nonce) {
        return yield* new OidcError({ reason: "id_token nonce mismatch" });
      }
      return yield* identityOf(payload, config.groupsClaim);
    }),
  });
});

/** Absent when the control plane signs in with SAML or the development login only. */
export const layer = Layer.effect(
  Oidc,
  Effect.gen(function* () {
    const config = yield* ControlPlaneConfig;
    if (config.oidc === undefined) {
      const missing = () => Effect.fail(new OidcError({ reason: "OIDC is not configured" }));
      return Oidc.of({ authorizationUrl: missing, exchange: missing });
    }
    return yield* make(config.oidc);
  }),
);
