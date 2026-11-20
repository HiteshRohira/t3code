// Shapes exchanged between enrolled devices, the control plane, and the gateway. Every side
// decodes with these schemas, so a malformed body fails the same way everywhere.
import * as DateTime from "effect/DateTime";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";

export const ROLES = ["admin", "maintainer", "developer", "viewer", "auditor"] as const;
export const Role = Schema.Literals(ROLES);
export type Role = typeof Role.Type;
export const isRole = Schema.is(Role);

/** Roles that may spend model credits. Viewers and auditors can sign in but get no lease. */
export const LEASE_ROLES: ReadonlyArray<Role> = ["admin", "maintainer", "developer"];

export const paths = {
  enrollStart: "/enroll/start",
  enroll: "/v1/enroll",
  lease: "/v1/lease",
  policy: "/v1/policy",
  audit: "/v1/audit",
  heartbeat: "/v1/heartbeat",
  library: "/v1/library",
  sharedThreads: "/v1/shared-threads",
  pairingStart: "/pair/start",
  pairingExchange: "/v1/pairing/exchange",
  gatewayState: "/v1/gateway/state",
  gatewayUsage: "/v1/gateway/usage",
  jwks: "/.well-known/jwks.json",
  health: "/healthz",
} as const;

/** Proof of possession signs this string with the device key (RSA-SHA256, base64url). */
export const enrollmentProofMessage = (code: string) => `t3-enterprise-enroll:${code}`;

const Text = (max: number) => Schema.String.check(Schema.isMaxLength(max));
const Id = Schema.NonEmptyString.check(Schema.isMaxLength(512));
const IsoDate = Schema.String.check(
  Schema.makeFilter((value: string) =>
    Option.isNone(DateTime.make(value)) ? "must be a date" : true,
  ),
);
const Count = Schema.Int.check(Schema.isGreaterThanOrEqualTo(0));

export const EnrollRequest = Schema.Struct({
  code: Text(256),
  publicKeyPem: Text(16 * 1024),
  proof: Text(4096),
  hostname: Text(255),
  platform: Text(64),
  clientVersion: Schema.optional(Text(64)),
});
export type EnrollRequest = typeof EnrollRequest.Type;

export const EnrollResponse = Schema.Struct({
  deviceId: Schema.String,
  certificatePem: Schema.String,
  caPem: Schema.String,
  expiresAt: Schema.String,
  user: Schema.Struct({ email: Schema.String, roles: Schema.Array(Role) }),
});
export type EnrollResponse = typeof EnrollResponse.Type;

export const LEASE_DENIALS = [
  "device_unknown",
  "device_revoked",
  "device_expired",
  "user_inactive",
  "role_denied",
  "over_budget",
] as const;
export const LeaseDenial = Schema.Literals(LEASE_DENIALS);
export type LeaseDenial = typeof LeaseDenial.Type;

export const LeaseResponse = Schema.Struct({
  lease: Schema.String,
  expiresAt: Schema.String,
  user: Schema.Struct({ id: Schema.String, email: Schema.String, roles: Schema.Array(Role) }),
});
export type LeaseResponse = typeof LeaseResponse.Type;

export const ErrorResponse = Schema.Struct({ error: Schema.String, message: Schema.String });
export type ErrorResponse = typeof ErrorResponse.Type;

/** `policy` is a compact JWS whose payload is the signed policy claims. */
export const PolicyResponse = Schema.Struct({ policy: Schema.String });

export const AuditEvent = Schema.Struct({
  /** Unique per device, so a resent batch is stored once. */
  id: Id,
  occurredAt: IsoDate,
  type: Schema.NonEmptyString.check(Schema.isMaxLength(128)),
  threadId: Schema.optional(Text(512)),
  projectId: Schema.optional(Text(512)),
  provider: Schema.optional(Text(128)),
  runtimeMode: Schema.optional(Text(64)),
  detail: Schema.optional(Schema.Record(Schema.String, Schema.Unknown)),
});
export type AuditEvent = typeof AuditEvent.Type;

/** Events are decoded one by one, so one bad event is counted as rejected, not the batch. */
export const AuditBatch = Schema.Struct({
  events: Schema.Array(Schema.Unknown).check(Schema.isMaxLength(1000)),
});
export type AuditBatch = { readonly events: ReadonlyArray<AuditEvent> };

export const AuditResult = Schema.Struct({ accepted: Count, rejected: Count });

export const GatewayState = Schema.Struct({
  generatedAt: Schema.String,
  revokedDevices: Schema.Array(Schema.String),
  inactiveUsers: Schema.Array(Schema.String),
  overBudgetUsers: Schema.Array(Schema.String),
});
export type GatewayState = typeof GatewayState.Type;

export const UsageRecord = Schema.Struct({
  id: Id,
  userId: Schema.String,
  deviceId: Schema.String,
  provider: Text(64),
  model: Text(256),
  inputTokens: Count,
  outputTokens: Count,
  status: Schema.Int,
  occurredAt: IsoDate,
  /** Secrets the gateway removed from this request before it left the organization. */
  redactions: Schema.optional(Count),
  region: Schema.optional(Text(64)),
});
export type UsageRecord = typeof UsageRecord.Type;

export const UsageBatch = Schema.Struct({ records: Schema.Array(Schema.Unknown) });
export type UsageBatch = { readonly records: ReadonlyArray<UsageRecord> };

export const UsageResult = Schema.Struct({ accepted: Count, state: GatewayState });

/** What an enrolled environment reports about itself for the fleet view. */
export const Heartbeat = Schema.Struct({
  clientVersion: Text(64),
  platform: Text(64),
  hostname: Text(255),
  policyVersion: Schema.NullOr(Schema.Int),
  restartRequired: Schema.Boolean,
  activeTurns: Count,
  projects: Count,
  modelAccess: Schema.Literals(["ok", "denied", "unreachable", "pending"]),
});
export type Heartbeat = typeof Heartbeat.Type;
