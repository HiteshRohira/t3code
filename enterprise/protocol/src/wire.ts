// JSON shapes exchanged between enrolled devices, the control plane, and the gateway.

export const ROLES = ["admin", "maintainer", "developer", "viewer", "auditor"] as const;
export type Role = (typeof ROLES)[number];

export const isRole = (value: unknown): value is Role =>
  typeof value === "string" && (ROLES as ReadonlyArray<string>).includes(value);

/** Roles that may spend model credits. Viewers and auditors can sign in but get no lease. */
export const LEASE_ROLES: ReadonlyArray<Role> = ["admin", "maintainer", "developer"];

export const paths = {
  enrollStart: "/enroll/start",
  enroll: "/v1/enroll",
  lease: "/v1/lease",
  policy: "/v1/policy",
  audit: "/v1/audit",
  gatewayState: "/v1/gateway/state",
  gatewayUsage: "/v1/gateway/usage",
  jwks: "/.well-known/jwks.json",
  health: "/healthz",
} as const;

/** Proof of possession signs this string with the device key (RSA-SHA256, base64url). */
export const enrollmentProofMessage = (code: string) => `t3-enterprise-enroll:${code}`;

export interface EnrollRequest {
  readonly code: string;
  readonly publicKeyPem: string;
  readonly proof: string;
  readonly hostname: string;
  readonly platform: string;
  readonly clientVersion?: string;
}

export interface EnrollResponse {
  readonly deviceId: string;
  readonly certificatePem: string;
  readonly caPem: string;
  readonly expiresAt: string;
  readonly user: { readonly email: string; readonly roles: ReadonlyArray<Role> };
}

export const LEASE_DENIALS = [
  "device_unknown",
  "device_revoked",
  "device_expired",
  "user_inactive",
  "role_denied",
  "over_budget",
] as const;
export type LeaseDenial = (typeof LEASE_DENIALS)[number];

export interface LeaseResponse {
  readonly lease: string;
  readonly expiresAt: string;
  readonly user: {
    readonly id: string;
    readonly email: string;
    readonly roles: ReadonlyArray<Role>;
  };
}

export interface ErrorResponse {
  readonly error: string;
  readonly message: string;
}

export interface PolicyResponse {
  /** A compact JWS whose payload is `PolicyClaims`. */
  readonly policy: string;
}

export interface AuditEvent {
  /** Unique per device, so a resent batch is stored once. */
  readonly id: string;
  readonly occurredAt: string;
  readonly type: string;
  readonly threadId?: string;
  readonly projectId?: string;
  readonly provider?: string;
  readonly runtimeMode?: string;
  readonly detail?: Readonly<Record<string, unknown>>;
}

export interface AuditBatch {
  readonly events: ReadonlyArray<AuditEvent>;
}

export interface GatewayState {
  readonly generatedAt: string;
  readonly revokedDevices: ReadonlyArray<string>;
  readonly inactiveUsers: ReadonlyArray<string>;
  readonly overBudgetUsers: ReadonlyArray<string>;
}

export interface UsageRecord {
  readonly id: string;
  readonly userId: string;
  readonly deviceId: string;
  readonly provider: string;
  readonly model: string;
  readonly inputTokens: number;
  readonly outputTokens: number;
  readonly status: number;
  readonly occurredAt: string;
}

export interface UsageBatch {
  readonly records: ReadonlyArray<UsageRecord>;
}
