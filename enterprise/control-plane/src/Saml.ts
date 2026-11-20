/**
 * Saml - SAML 2.0 service provider (SP-initiated, HTTP-Redirect request, HTTP-POST response) for
 * IdPs that do not speak OIDC, such as ADFS. Signature and replay checks are node-saml's; the
 * assertion must be signed and must answer a request this process sent.
 *
 * @module Saml
 */
import { SAML, ValidateInResponseTo, type Profile } from "@node-saml/node-saml";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Schema from "effect/Schema";

import { ControlPlaneConfig, type SamlConfig } from "./Config.ts";
import type { Identity } from "./Oidc.ts";

export class SamlError extends Schema.TaggedError<SamlError>()("SamlError", {
  reason: Schema.String,
}) {
  override get message(): string {
    return this.reason;
  }
}

export const SAML_CALLBACK_PATH = "/saml/acs";

const strings = (value: unknown): ReadonlyArray<string> =>
  typeof value === "string"
    ? [value]
    : Array.isArray(value)
      ? value.filter((item): item is string => typeof item === "string")
      : [];

export const identityOf = (profile: Profile, config: SamlConfig): Identity | undefined => {
  const email = [
    ...(config.emailAttribute === undefined ? [] : strings(profile[config.emailAttribute])),
    ...strings(profile.email),
    ...strings(profile.mail),
    ...strings(profile["urn:oid:0.9.2342.19200300.100.1.3"]),
    ...(profile.nameID.includes("@") ? [profile.nameID] : []),
  ][0];
  if (email === undefined) return undefined;
  const name =
    config.nameAttribute === undefined ? undefined : strings(profile[config.nameAttribute])[0];
  return {
    subject: profile.nameID,
    email: email.toLowerCase(),
    name: name ?? null,
    groups: strings(profile[config.groupsAttribute]),
  };
};

export class Saml extends Context.Service<
  Saml,
  {
    readonly configured: boolean;
    readonly authorizationUrl: (relayState: string) => Effect.Effect<string, SamlError>;
    readonly validate: (samlResponse: string) => Effect.Effect<Identity, SamlError>;
    readonly metadata: Effect.Effect<string, SamlError>;
  }
>()("@t3tools/enterprise-control-plane/Saml") {}

const fail = (reason: string) => Effect.fail(new SamlError({ reason }));

const make = Effect.gen(function* () {
  const settings = yield* ControlPlaneConfig;
  const config = settings.saml;
  if (config === undefined) {
    const notConfigured = Effect.fn("Saml.notConfigured")(function* () {
      return yield* new SamlError({ reason: "SAML is not configured" });
    });
    return Saml.of({
      configured: false,
      authorizationUrl: notConfigured,
      validate: notConfigured,
      metadata: notConfigured(),
    });
  }
  const saml = new SAML({
    entryPoint: config.entryPoint,
    idpCert: config.idpCertificate,
    issuer: config.issuer,
    audience: config.issuer,
    callbackUrl: `${settings.publicUrl}${SAML_CALLBACK_PATH}`,
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: false,
    validateInResponseTo: ValidateInResponseTo.always,
    acceptedClockSkewMs: 60_000,
    identifierFormat: null,
    disableRequestedAuthnContext: true,
  });

  return Saml.of({
    configured: true,
    authorizationUrl: Effect.fn("Saml.authorizationUrl")(function* (relayState) {
      return yield* Effect.tryPromise({
        try: () => saml.getAuthorizeUrlAsync(relayState, undefined, {}),
        catch: () => new SamlError({ reason: "cannot build the SAML request" }),
      });
    }),
    validate: Effect.fn("Saml.validate")(function* (samlResponse) {
      const { profile } = yield* Effect.tryPromise({
        try: () => saml.validatePostResponseAsync({ SAMLResponse: samlResponse }),
        catch: (cause) =>
          new SamlError({
            reason: `the IdP's SAML response was refused: ${cause instanceof Error ? cause.message : "invalid"}`,
          }),
      });
      if (profile === null) return yield* fail("the IdP sent a logout, not a sign-in");
      const identity = identityOf(profile, config);
      if (identity === undefined) {
        return yield* fail("the SAML assertion carries no email; map one in the IdP");
      }
      return identity;
    }),
    metadata: Effect.try({
      try: () => saml.generateServiceProviderMetadata(null),
      catch: () => new SamlError({ reason: "cannot build SP metadata" }),
    }),
  });
});

export const layer = Layer.effect(Saml, make);
