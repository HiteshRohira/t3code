/**
 * EnterprisePolicy - on an enterprise machine the managed policy comes from the control plane,
 * signed with a key the enterprise config pins. A missing, expired, or forged copy falls back to
 * the config's bootstrap policy, never to no policy.
 *
 * @module EnterprisePolicy
 */
import { ManagedPolicyDocument } from "@t3tools/contracts";
import { verifyPolicy } from "@t3tools/enterprise-protocol/tokens";
import type * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";

import type { EnterpriseConfigDocument } from "./EnterpriseConfig.ts";
import * as EnterpriseDevice from "./EnterpriseDevice.ts";

export class EnterprisePolicyRejected extends Schema.TaggedError<EnterprisePolicyRejected>()(
  "EnterprisePolicyRejected",
  { reason: Schema.String },
) {
  override get message(): string {
    return `The organization's signed policy was refused: ${this.reason}`;
  }
}

const decodeDocument = Schema.decodeUnknownEffect(ManagedPolicyDocument, {
  onExcessProperty: "error",
});

export interface VerifiedPolicy {
  readonly version: number;
  readonly document: ManagedPolicyDocument;
  readonly expiresAt: DateTime.Utc;
}

/** Checks a policy token against the pinned keys and the policy schema this build enforces. */
export const verifyPolicyToken = Effect.fn("EnterprisePolicy.verifyPolicyToken")(function* (
  config: EnterpriseConfigDocument,
  token: string,
) {
  const claims = yield* verifyPolicy(token.trim(), config.policyKeys, {
    issuer: config.controlPlaneUrl,
  }).pipe(Effect.mapError((cause) => new EnterprisePolicyRejected({ reason: cause.message })));
  const document = yield* decodeDocument(claims.policy).pipe(
    Effect.mapError(
      (cause) =>
        new EnterprisePolicyRejected({
          reason: `this version cannot enforce it (${cause.message.replace(/\s*\n\s*/g, " ")})`,
        }),
    ),
  );
  if (document.organization !== config.organization) {
    return yield* new EnterprisePolicyRejected({
      reason: `it names ${document.organization}, not ${config.organization}`,
    });
  }
  return {
    version: claims.version,
    document,
    expiresAt: claims.expiresAt,
  } satisfies VerifiedPolicy;
});

export interface ResolvedEnterprisePolicy {
  readonly source: string;
  readonly document: ManagedPolicyDocument;
  readonly version: number | undefined;
}

/** A bootstrap policy that only names the organization still keeps T3 Connect off. */
const fallbackDocument = (config: EnterpriseConfigDocument): ManagedPolicyDocument =>
  config.bootstrapPolicy ?? {
    schemaVersion: 1,
    organization: config.organization,
    ...(config.supportUrl === undefined ? {} : { supportUrl: config.supportUrl }),
    limits: { connect: false },
  };

export const resolve = Effect.fn("EnterprisePolicy.resolve")(function* (
  config: EnterpriseConfigDocument,
  configPath: string,
) {
  const paths = yield* EnterpriseDevice.statePaths;
  const token = yield* EnterpriseDevice.readText(paths.policy);
  if (Option.isSome(token)) {
    const verified = yield* verifyPolicyToken(config, token.value).pipe(
      Effect.tapError((error) => Effect.logWarning(error.message)),
      Effect.option,
    );
    if (Option.isSome(verified)) {
      return {
        source: `${config.controlPlaneUrl} (version ${verified.value.version})`,
        document: verified.value.document,
        version: verified.value.version,
      } satisfies ResolvedEnterprisePolicy;
    }
  }
  return {
    source: `${configPath} (bootstrap policy)`,
    document: fallbackDocument(config),
    version: undefined,
  } satisfies ResolvedEnterprisePolicy;
});
