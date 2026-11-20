/**
 * ControlPlane - the org's directory and device authority: who may sign in, which devices are
 * enrolled, what each lease allows, and what happened.
 *
 * @module ControlPlane
 */
import { certificateThumbprint } from "@t3tools/enterprise-protocol/thumbprint";
import { signLease, signPolicy, type SigningError } from "@t3tools/enterprise-protocol/tokens";
import {
  AuditEvent,
  enrollmentProofMessage,
  LEASE_ROLES,
  UsageRecord,
  type EnrollRequest,
  type EnrollResponse,
  type GatewayState,
  type Heartbeat,
  type LeaseDenial,
  type LeaseResponse,
  type Role,
} from "@t3tools/enterprise-protocol/wire";
import * as Context from "effect/Context";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Schema from "effect/Schema";
import type { SqlError } from "effect/sql/SqlError";

import * as AuditSinks from "./AuditSinks.ts";
import * as CertificateAuthority from "./CertificateAuthority.ts";
import { ControlPlaneConfig } from "./Config.ts";
import * as Crypto from "./Crypto.ts";
import type { Identity } from "./Oidc.ts";
import * as SigningKeys from "./SigningKeys.ts";
import { monthOf, Store, type Device, type User } from "./Store.ts";

const ENROLLMENT_CODE_TTL_SECONDS = 5 * 60;

/** A request the control plane turns down, with the HTTP status and code the wire uses. */
export class Refusal extends Schema.TaggedError<Refusal>()("Refusal", {
  status: Schema.Number,
  code: Schema.String,
  reason: Schema.String,
}) {
  override get message(): string {
    return this.reason;
  }
}

const refuse = (status: number, code: string, reason: string) =>
  new Refusal({ status, code, reason });

export const denialMessage = (denial: LeaseDenial): string => {
  switch (denial) {
    case "device_unknown":
      return "this device is not enrolled";
    case "device_revoked":
      return "this device was revoked by your organization; enroll it again";
    case "device_expired":
      return "this device's certificate expired; enroll it again";
    case "user_inactive":
      return "your account is deactivated";
    case "role_denied":
      return "your role cannot use model credits";
    case "over_budget":
      return "you have used this month's model budget";
  }
};

export interface Actor {
  readonly id: string;
  readonly email: string;
}

export interface Budget {
  readonly month: string;
  readonly used: number;
  readonly limit: number | null;
  readonly team: string | null;
  readonly teamUsed: number | null;
  readonly teamLimit: number | null;
  readonly over: boolean;
}

const decodeAuditEvent = Schema.decodeUnknownOption(AuditEvent);
const decodeUsageRecord = Schema.decodeUnknownOption(UsageRecord);
const nowIso = Effect.map(DateTime.now, DateTime.formatIso);
const isoIn = (seconds: number) =>
  Effect.map(DateTime.now, (now) => DateTime.formatIso(DateTime.add(now, { seconds })));

export class ControlPlane extends Context.Service<
  ControlPlane,
  {
    readonly resolveLogin: (identity: Identity) => Effect.Effect<User, Refusal | SqlError>;
    readonly issueEnrollmentCode: (user: User) => Effect.Effect<string, SqlError>;
    readonly enroll: (request: EnrollRequest) => Effect.Effect<EnrollResponse, Refusal | SqlError>;
    /** The device presenting `certificate`, refused unless it may act; `allowRevoked` serves audit uploads. */
    readonly authenticateDevice: (
      certificate: Uint8Array | undefined,
      options?: { readonly allowRevoked?: boolean },
    ) => Effect.Effect<{ readonly device: Device; readonly user: User }, Refusal | SqlError>;
    readonly lease: (
      device: Device,
      user: User,
    ) => Effect.Effect<LeaseResponse, Refusal | SigningError | SqlError>;
    readonly policyToken: Effect.Effect<string, Refusal | SigningError | SqlError>;
    readonly ingestAudit: (
      device: Device,
      user: User,
      events: ReadonlyArray<unknown>,
    ) => Effect.Effect<{ accepted: number; rejected: number }, SqlError>;
    readonly heartbeat: (device: Device, heartbeat: Heartbeat) => Effect.Effect<void, SqlError>;
    readonly recordAdminEvent: (
      actor: Actor,
      type: string,
      detail: Record<string, unknown>,
    ) => Effect.Effect<void, SqlError>;
    readonly gatewayState: Effect.Effect<GatewayState, SqlError>;
    readonly ingestUsage: (
      records: ReadonlyArray<unknown>,
    ) => Effect.Effect<{ accepted: number; state: GatewayState }, SqlError>;
    readonly budgetOf: (user: User) => Effect.Effect<Budget, SqlError>;
    readonly deviceDenial: (device: Device) => Effect.Effect<LeaseDenial | undefined, SqlError>;
    /** Deactivates or reactivates a user, revoking devices on deactivation. */
    readonly setActive: (
      actor: Actor,
      user: User,
      active: boolean,
    ) => Effect.Effect<User, SqlError>;
    /** Recomputes roles from IdP groups when the org maps groups to roles. */
    readonly applyGroupRoles: (userIds: ReadonlyArray<string>) => Effect.Effect<void, SqlError>;
  }
>()("@t3tools/enterprise-control-plane/ControlPlane") {}

const make = Effect.gen(function* () {
  const config = yield* ControlPlaneConfig;
  const store = yield* Store;
  const ca = yield* CertificateAuthority.CertificateAuthority;
  const keys = yield* SigningKeys.SigningKeys;
  const sinks = yield* AuditSinks.AuditSinks;
  const mapsGroups = Object.keys(config.groupRoles).length > 0;

  const rolesFromGroups = (groups: ReadonlyArray<string>): ReadonlyArray<Role> => {
    const roles = [
      ...new Set(groups.flatMap((group) => config.groupRoles[group] ?? [])),
    ] as ReadonlyArray<Role>;
    return roles.length === 0 ? [config.defaultRole] : roles;
  };

  const recordAdminEvent = Effect.fn("ControlPlane.recordAdminEvent")(function* (
    actor: Actor,
    type: string,
    detail: Record<string, unknown>,
  ) {
    const stored = yield* store.appendAudit({ id: "control-plane", userId: actor.id }, [
      { id: yield* Crypto.uuid, occurredAt: yield* nowIso, type, detail },
    ]);
    yield* sinks.publish(stored.map((event) => ({ ...event, email: actor.email })));
  });

  const team = (user: User) => (user.team === null ? Effect.undefined : store.team(user.team));

  const budgetOf = Effect.fn("ControlPlane.budgetOf")(function* (user: User) {
    const month = monthOf(yield* nowIso);
    const userTeam = yield* team(user);
    const limit = user.monthlyTokens ?? config.defaultMonthlyTokens ?? null;
    const used = yield* store.tokensUsed(user.id, month);
    const teamLimit = userTeam?.monthlyTokens ?? null;
    const teamUsed =
      userTeam === undefined || teamLimit === null
        ? null
        : yield* store.teamTokensUsed(userTeam.name, month);
    const over =
      (limit !== null && used >= limit) ||
      (teamLimit !== null && teamUsed !== null && teamUsed >= teamLimit);
    return {
      month,
      used,
      limit,
      team: userTeam?.name ?? null,
      teamUsed,
      teamLimit,
      over,
    } satisfies Budget;
  });

  const deviceDenial = Effect.fn("ControlPlane.deviceDenial")(function* (device: Device) {
    if (device.revokedAt !== null) return "device_revoked" as const;
    if (device.expiresAt < (yield* nowIso)) return "device_expired" as const;
    const user = yield* store.userById(device.userId);
    if (user === undefined || !user.active) return "user_inactive" as const;
    return undefined;
  });

  const gatewayState = Effect.gen(function* () {
    const users = yield* store.listUsers;
    const overBudgetUsers: Array<string> = [];
    for (const user of users) {
      if (user.active && (yield* budgetOf(user)).over) overBudgetUsers.push(user.id);
    }
    return {
      generatedAt: yield* nowIso,
      revokedDevices: yield* store.revokedDeviceIds,
      inactiveUsers: yield* store.inactiveUserIds,
      overBudgetUsers,
    } satisfies GatewayState;
  }).pipe(Effect.withSpan("ControlPlane.gatewayState"));

  return ControlPlane.of({
    resolveLogin: Effect.fn("ControlPlane.resolveLogin")(function* (identity) {
      const existing = yield* store.userByEmail(identity.email);
      // SCIM-pushed groups count when the IdP's token carries none.
      const groups =
        identity.groups.length > 0 || existing === undefined
          ? identity.groups
          : yield* store.groupsOf(existing.id);
      const allowed = config.allowedGroups;
      if (allowed !== undefined && !groups.some((group) => allowed.includes(group))) {
        return yield* refuse(
          403,
          "not_allowed",
          "your account is not in a group allowed to use T3 Enterprise",
        );
      }
      if (existing === undefined) {
        if (config.provisioning === "scim") {
          return yield* refuse(
            403,
            "not_provisioned",
            "your account has not been provisioned for T3 Enterprise",
          );
        }
        return yield* store.createUser({
          id: yield* Crypto.uuid,
          email: identity.email,
          name: identity.name,
          roles: mapsGroups ? rolesFromGroups(groups) : [config.defaultRole],
          region: config.defaultRegion ?? null,
        });
      }
      if (!existing.active) {
        return yield* refuse(403, "user_inactive", "your account is deactivated");
      }
      if (!mapsGroups) return existing;
      return (yield* store.updateUser(existing.id, { roles: rolesFromGroups(groups) })) ?? existing;
    }),

    issueEnrollmentCode: Effect.fn("ControlPlane.issueEnrollmentCode")(function* (user) {
      const code = yield* Crypto.randomToken();
      yield* store.createEnrollmentCode(
        user.id,
        Crypto.sha256Hex(code),
        yield* isoIn(ENROLLMENT_CODE_TTL_SECONDS),
      );
      return code;
    }),

    enroll: Effect.fn("ControlPlane.enroll")(function* (request) {
      if (
        !Crypto.verifyRsaProof(
          request.publicKeyPem,
          enrollmentProofMessage(request.code),
          request.proof,
        )
      ) {
        return yield* refuse(400, "invalid_proof", "proof does not match the device key");
      }
      const userId = yield* store.redeemEnrollmentCode(Crypto.sha256Hex(request.code));
      const user = userId === undefined ? undefined : yield* store.userById(userId);
      if (user === undefined) {
        return yield* refuse(400, "invalid_code", "enrollment code is unknown, used, or expired");
      }
      if (!user.active) return yield* refuse(403, "user_inactive", "this account is deactivated");

      const deviceId = yield* Crypto.uuid;
      const issued = yield* ca
        .issueDevice({ publicKeyPem: request.publicKeyPem, deviceId, userId: user.id })
        .pipe(Effect.mapError((error) => refuse(400, "invalid_key", error.reason)));
      const expiresAt = DateTime.formatIso(issued.expiresAt);
      yield* store.createDevice({
        id: deviceId,
        userId: user.id,
        thumbprint: certificateThumbprint(issued.certPem),
        hostname: request.hostname,
        platform: request.platform,
        clientVersion: request.clientVersion ?? null,
        expiresAt,
      });
      yield* recordAdminEvent(user, "device.enrolled", {
        deviceId,
        hostname: request.hostname,
        platform: request.platform,
      });
      return {
        deviceId,
        certificatePem: issued.certPem,
        caPem: ca.certPem,
        expiresAt,
        user: { email: user.email, roles: user.roles },
      } satisfies EnrollResponse;
    }),

    authenticateDevice: Effect.fn("ControlPlane.authenticateDevice")(
      function* (certificate, options) {
        if (certificate === undefined) {
          return yield* refuse(401, "device_unknown", "present an enrolled device certificate");
        }
        const device = yield* store.deviceByThumbprint(
          certificateThumbprint(Buffer.from(certificate)),
        );
        if (device === undefined) {
          return yield* refuse(401, "device_unknown", "this device is not enrolled");
        }
        const denial = yield* deviceDenial(device);
        if (denial !== undefined && options?.allowRevoked !== true) {
          return yield* refuse(403, denial, denialMessage(denial));
        }
        const user = yield* store.userById(device.userId);
        if (user === undefined) {
          return yield* refuse(401, "device_unknown", "this device's user no longer exists");
        }
        yield* store.touchDevice(device.id);
        return { device, user };
      },
    ),

    lease: Effect.fn("ControlPlane.lease")(function* (device, user) {
      if (!user.roles.some((role) => LEASE_ROLES.includes(role))) {
        return yield* refuse(403, "role_denied", denialMessage("role_denied"));
      }
      if ((yield* budgetOf(user)).over) {
        return yield* refuse(403, "over_budget", denialMessage("over_budget"));
      }
      const userTeam = yield* team(user);
      const models = user.models ?? userTeam?.models ?? config.defaultModels;
      const region = user.region ?? userTeam?.region ?? config.defaultRegion;
      const leaseId = yield* Crypto.uuid;
      const lease = yield* signLease(
        keys.active,
        {
          userId: user.id,
          email: user.email,
          deviceId: device.id,
          roles: user.roles,
          thumbprint: device.thumbprint,
          leaseId,
          models: models ?? undefined,
          region: region ?? undefined,
        },
        { issuer: config.publicUrl, ttlSeconds: config.leaseTtlSeconds },
      );
      const expiresAt = yield* isoIn(config.leaseTtlSeconds);
      yield* store.recordLease({ id: leaseId, userId: user.id, deviceId: device.id, expiresAt });
      return {
        lease,
        expiresAt,
        user: { id: user.id, email: user.email, roles: user.roles },
      } satisfies LeaseResponse;
    }),

    policyToken: Effect.gen(function* () {
      const current = yield* store.currentPolicy;
      if (current === undefined) {
        return yield* refuse(404, "no_policy", "no policy has been published");
      }
      return yield* signPolicy(
        keys.active,
        { version: current.version, document: current.document },
        { issuer: config.publicUrl, ttlSeconds: config.policyTtlSeconds },
      );
    }).pipe(Effect.withSpan("ControlPlane.policyToken")),

    ingestAudit: Effect.fn("ControlPlane.ingestAudit")(function* (device, user, raw) {
      const events = raw.flatMap((event) => {
        const decoded = decodeAuditEvent(event);
        return decoded._tag === "Some" ? [decoded.value] : [];
      });
      const stored = yield* store.appendAudit({ id: device.id, userId: user.id }, events);
      yield* sinks.publish(stored.map((event) => ({ ...event, email: user.email })));
      // Reported, not silently dropped, so a device can tell its events are not landing.
      return { accepted: events.length, rejected: raw.length - events.length };
    }),

    heartbeat: Effect.fn("ControlPlane.heartbeat")(function* (device, heartbeat) {
      yield* store.recordHeartbeat(device.id, heartbeat);
    }),

    recordAdminEvent,
    gatewayState,

    ingestUsage: Effect.fn("ControlPlane.ingestUsage")(function* (raw) {
      const records = raw.flatMap((record) => {
        const decoded = decodeUsageRecord(record);
        return decoded._tag === "Some" ? [decoded.value] : [];
      });
      yield* store.recordUsage(records);
      return { accepted: records.length, state: yield* gatewayState };
    }),

    budgetOf,
    deviceDenial,

    setActive: Effect.fn("ControlPlane.setActive")(function* (actor, user, active) {
      if (active === user.active) return user;
      const updated = active
        ? yield* store.updateUser(user.id, { active: true })
        : yield* store.deactivateUser(user.id);
      yield* recordAdminEvent(actor, active ? "user.reactivated" : "user.deactivated", {
        userId: user.id,
        email: user.email,
      });
      return updated ?? user;
    }),

    applyGroupRoles: Effect.fn("ControlPlane.applyGroupRoles")(function* (userIds) {
      if (!mapsGroups) return;
      for (const userId of new Set(userIds)) {
        yield* store.updateUser(userId, { roles: rolesFromGroups(yield* store.groupsOf(userId)) });
      }
    }),
  });
});

export const layer = Layer.effect(ControlPlane, make);
