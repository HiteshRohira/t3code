import * as Schema from "effect/Schema";

/** An enterprise environment's link to its organization, as its Settings page shows it. */
export const EnterpriseStatus = Schema.Struct({
  organization: Schema.String,
  controlPlaneUrl: Schema.String,
  gatewayUrl: Schema.String,
  supportUrl: Schema.NullOr(Schema.String),
  enrolled: Schema.Boolean,
  email: Schema.NullOr(Schema.String),
  deviceId: Schema.NullOr(Schema.String),
  certificateExpiresAt: Schema.NullOr(Schema.String),
  lease: Schema.Struct({
    active: Schema.Boolean,
    expiresAt: Schema.NullOr(Schema.String),
    problem: Schema.NullOr(Schema.String),
  }),
  policy: Schema.Struct({
    loadedVersion: Schema.NullOr(Schema.Number),
    availableVersion: Schema.NullOr(Schema.Number),
    restartRequired: Schema.Boolean,
  }),
  /** `self`: the server can restart itself to apply a policy; `manual`: whoever runs it must. */
  restart: Schema.Literals(["self", "manual"]),
  /** An enrollment started from a client and waiting for the user to sign in. */
  enrollment: Schema.NullOr(
    Schema.Struct({ signInUrl: Schema.String, error: Schema.NullOr(Schema.String) }),
  ),
  whenUnreachable: Schema.Literals(["use-cached-until-expiry", "deny"]),
  updatedAt: Schema.String,
});
export type EnterpriseStatus = typeof EnterpriseStatus.Type;

export class EnterpriseActionError extends Schema.TaggedError<EnterpriseActionError>()(
  "EnterpriseActionError",
  { message: Schema.String },
) {}

export const EnterpriseEnrollResult = Schema.Struct({ signInUrl: Schema.String });
export type EnterpriseEnrollResult = typeof EnterpriseEnrollResult.Type;

export const EnterpriseShareThreadInput = Schema.Struct({
  threadId: Schema.String,
  audience: Schema.Literals(["team", "org"]),
  note: Schema.String.check(Schema.isMaxLength(2000)),
});
export type EnterpriseShareThreadInput = typeof EnterpriseShareThreadInput.Type;

export const EnterpriseSharedThreadSummary = Schema.Struct({
  id: Schema.String,
  title: Schema.String,
  repository: Schema.NullOr(Schema.String),
  branch: Schema.NullOr(Schema.String),
  provider: Schema.NullOr(Schema.String),
  audience: Schema.Literals(["team", "org"]),
  note: Schema.String,
  sharedBy: Schema.String,
  team: Schema.NullOr(Schema.String),
  createdAt: Schema.String,
  patchBytes: Schema.Number,
});
export type EnterpriseSharedThreadSummary = typeof EnterpriseSharedThreadSummary.Type;

/** A new-thread prompt that picks the shared work up, with its files written locally. */
export const EnterpriseContinueSharedThreadResult = Schema.Struct({
  prompt: Schema.String,
  /** `owner/name` when the shared thread's repository is on a known host. */
  repository: Schema.NullOr(Schema.String),
  provider: Schema.NullOr(Schema.String),
});
export type EnterpriseContinueSharedThreadResult = typeof EnterpriseContinueSharedThreadResult.Type;
