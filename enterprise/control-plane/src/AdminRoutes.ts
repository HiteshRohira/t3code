/**
 * AdminRoutes - the admin console and its JSON API. Browsers use a session cookie and must send
 * the CSRF header on writes; automation uses `T3E_ADMIN_API_TOKEN` as a bearer token.
 *
 * @module AdminRoutes
 */
import { Role } from "@t3tools/enterprise-protocol/wire";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";
import * as Path from "effect/Path";
import * as Schema from "effect/Schema";
import { HttpRouter, HttpServerRequest } from "effect/http";

import { ControlPlaneConfig } from "./Config.ts";
import { ControlPlane, Refusal } from "./ControlPlane.ts";
import * as Crypto from "./Crypto.ts";
import { asset, bearer, html, json, readJson, redirect, respond, searchParams } from "./Http.ts";
import { SESSION_COOKIE } from "./Routes.ts";
import { Sessions } from "./Sessions.ts";
import { monthOf, Store } from "./Store.ts";

export interface AdminActor {
  readonly id: string;
  readonly email: string;
  readonly roles: ReadonlyArray<Role>;
  /** Cookie sessions must send the CSRF header on writes; the API token need not. */
  readonly viaCookie: boolean;
}

export type Permission =
  | "read:directory"
  | "write:users"
  | "revoke:devices"
  | "write:teams"
  | "read:policy"
  | "write:policy"
  | "read:audit"
  | "read:usage"
  | "write:holds"
  | "write:library"
  | "watch:team";

const GRANTS: Readonly<Record<Role, ReadonlyArray<Permission>>> = {
  admin: [
    "read:directory",
    "write:users",
    "revoke:devices",
    "write:teams",
    "read:policy",
    "write:policy",
    "read:audit",
    "read:usage",
    "write:holds",
    "write:library",
    "watch:team",
  ],
  maintainer: [
    "read:directory",
    "revoke:devices",
    "write:teams",
    "read:policy",
    "read:usage",
    "write:library",
    "watch:team",
  ],
  auditor: ["read:directory", "read:policy", "read:audit", "read:usage", "write:holds"],
  developer: [],
  viewer: [],
};

export const permissionsOf = (roles: ReadonlyArray<Role>) => [
  ...new Set(roles.flatMap((role) => GRANTS[role])),
];

const CSRF_HEADER = "x-t3e-admin";

const refuse = (status: number, code: string, reason: string) =>
  Effect.fail(new Refusal({ status, code, reason }));

/** The signed-in admin, or the automation token acting as one. */
export const adminActor = Effect.gen(function* () {
  const config = yield* ControlPlaneConfig;
  const request = yield* HttpServerRequest.HttpServerRequest;
  const token = bearer(request);
  const apiToken = config.secrets.adminApiToken;
  if (token !== undefined && apiToken !== undefined && Crypto.constantTimeEqual(token, apiToken)) {
    return { id: "api", email: "api", roles: ["admin"], viaCookie: false } satisfies AdminActor;
  }
  const userId = yield* (yield* Sessions).userOf(request.cookies[SESSION_COOKIE]);
  if (userId === undefined) return undefined;
  const user = yield* (yield* Store).userById(userId);
  if (user === undefined || !user.active) return undefined;
  return {
    id: user.id,
    email: user.email,
    roles: user.roles,
    viaCookie: true,
  } satisfies AdminActor;
});

/** The actor, if they hold `permission`; writes from a browser also need the CSRF header. */
export const authorize = Effect.fn("AdminRoutes.authorize")(function* (permission?: Permission) {
  const request = yield* HttpServerRequest.HttpServerRequest;
  const actor = yield* adminActor;
  if (actor === undefined) return yield* refuse(401, "unauthorized", "sign in at /admin");
  if (request.method !== "GET" && actor.viaCookie && request.headers[CSRF_HEADER] !== "1") {
    return yield* refuse(403, "csrf", `send the ${CSRF_HEADER} header`);
  }
  if (permission !== undefined && !permissionsOf(actor.roles).includes(permission)) {
    return yield* refuse(403, "forbidden", `requires ${permission}`);
  }
  return actor;
});

const param = (name: string) =>
  Effect.map(HttpRouter.params, (params) => decodeURIComponent(params[name] ?? ""));

const NullableCount = Schema.NullOr(Schema.Int.check(Schema.isGreaterThanOrEqualTo(0)));
const NullableModels = Schema.NullOr(Schema.Array(Schema.NonEmptyString));
const NullableRegion = Schema.NullOr(Schema.NonEmptyString);

const UserPatchBody = Schema.Struct({
  roles: Schema.optional(Schema.Array(Role)),
  team: Schema.optional(Schema.NullOr(Schema.String)),
  models: Schema.optional(NullableModels),
  monthlyTokens: Schema.optional(NullableCount),
  region: Schema.optional(NullableRegion),
  active: Schema.optional(Schema.Boolean),
});

const TeamBody = Schema.Struct({
  monthlyTokens: Schema.optional(NullableCount),
  models: Schema.optional(NullableModels),
  region: Schema.optional(NullableRegion),
});

/** Devices validate the full document; here it only has to name its schema and organization. */
const PolicyBody = Schema.Struct({
  document: Schema.Record(Schema.String, Schema.Unknown).check(
    Schema.makeFilter((document) =>
      document["schemaVersion"] === 1 &&
      typeof document["organization"] === "string" &&
      document["organization"].length > 0
        ? true
        : "needs schemaVersion 1 and an organization",
    ),
  ),
});

const LegalHoldBody = Schema.Struct({ reason: Schema.NonEmptyString });

const checkRegion = Effect.fn("AdminRoutes.checkRegion")(function* (
  region: string | null | undefined,
) {
  const config = yield* ControlPlaneConfig;
  if (region !== undefined && region !== null && !config.regions.includes(region)) {
    return yield* refuse(
      400,
      "invalid_region",
      `region must be one of: ${config.regions.join(", ") || "(none configured)"}`,
    );
  }
});

const readAsset = Effect.fn("AdminRoutes.readAsset")(function* (name: string) {
  const fs = yield* FileSystem.FileSystem;
  const path = yield* Path.Path;
  const directory = yield* path.fromFileUrl(new URL("./admin-ui/", import.meta.url));
  return yield* fs.readFileString(path.join(directory, name));
});

const ASSETS: Readonly<Record<string, string>> = {
  "admin.css": "text/css; charset=utf-8",
  "admin.js": "text/javascript; charset=utf-8",
};

const consoleRoutes = Layer.mergeAll(
  HttpRouter.add(
    "GET",
    "/admin/assets/:name",
    respond(
      Effect.gen(function* () {
        const name = yield* param("name");
        const type = ASSETS[name];
        if (type === undefined) return yield* refuse(404, "not_found", "no such asset");
        return asset(yield* readAsset(name), type);
      }),
    ),
  ),
  HttpRouter.add(
    "GET",
    "/admin",
    respond(
      Effect.gen(function* () {
        if ((yield* adminActor) === undefined) return redirect("/admin/login");
        return html(yield* readAsset("index.html"));
      }),
    ),
  ),
  HttpRouter.add(
    "GET",
    "/v1/admin/me",
    respond(
      Effect.gen(function* () {
        const config = yield* ControlPlaneConfig;
        const actor = yield* authorize();
        return json({
          email: actor.email,
          roles: actor.roles,
          permissions: permissionsOf(actor.roles),
          organization: config.organization,
          regions: config.regions,
          retention: config.retention,
          signIn:
            config.oidc !== undefined ? "oidc" : config.saml !== undefined ? "saml" : "development",
          provisioning: config.provisioning,
        });
      }),
    ),
  ),
);

const directoryRoutes = Layer.mergeAll(
  HttpRouter.add(
    "GET",
    "/v1/admin/users",
    respond(
      Effect.gen(function* () {
        yield* authorize("read:directory");
        const store = yield* Store;
        const plane = yield* ControlPlane;
        const users = yield* store.listUsers;
        const holds = new Set((yield* store.legalHolds).map((hold) => hold.userId));
        const rows = yield* Effect.forEach(users, (user) =>
          Effect.gen(function* () {
            return {
              ...user,
              groups: yield* store.groupsOf(user.id),
              budget: yield* plane.budgetOf(user),
              legalHold: holds.has(user.id),
            };
          }),
        );
        return json({ users: rows });
      }),
    ),
  ),
  HttpRouter.add(
    "PATCH",
    "/v1/admin/users/:id",
    respond(
      Effect.gen(function* () {
        const actor = yield* authorize("write:users");
        const store = yield* Store;
        const plane = yield* ControlPlane;
        const user = yield* store.userById(yield* param("id"));
        if (user === undefined) return yield* refuse(404, "not_found", "no such user");
        const body = yield* readJson(UserPatchBody);
        yield* checkRegion(body.region);
        const { active, team, roles, models, monthlyTokens, region } = body;
        yield* store.updateUser(user.id, {
          ...(roles === undefined ? {} : { roles }),
          ...(models === undefined ? {} : { models }),
          ...(monthlyTokens === undefined ? {} : { monthlyTokens }),
          ...(region === undefined ? {} : { region }),
          ...(team === undefined ? {} : { team: team === "" ? null : team }),
        });
        if (active !== undefined) yield* plane.setActive(actor, user, active);
        yield* plane.recordAdminEvent(actor, "user.updated", {
          userId: user.id,
          email: user.email,
          changes: body,
        });
        return json({ user: yield* store.userById(user.id) });
      }),
    ),
  ),
  HttpRouter.add(
    "GET",
    "/v1/admin/devices",
    respond(
      Effect.gen(function* () {
        yield* authorize("read:directory");
        const store = yield* Store;
        const plane = yield* ControlPlane;
        const emails = new Map((yield* store.listUsers).map((user) => [user.id, user.email]));
        const devices = yield* store.listDevices(
          searchParams(yield* HttpServerRequest.HttpServerRequest).get("user") ?? undefined,
        );
        const rows = yield* Effect.forEach(devices, (device) =>
          Effect.map(plane.deviceDenial(device), (denial) => ({
            ...device,
            email: emails.get(device.userId) ?? null,
            status: denial ?? "active",
          })),
        );
        return json({ devices: rows });
      }),
    ),
  ),
  HttpRouter.add(
    "POST",
    "/v1/admin/devices/:id/revoke",
    respond(
      Effect.gen(function* () {
        const actor = yield* authorize("revoke:devices");
        const store = yield* Store;
        const device = yield* store.deviceById(yield* param("id"));
        if (device === undefined) return yield* refuse(404, "not_found", "no such device");
        yield* store.revokeDevice(device.id);
        yield* (yield* ControlPlane).recordAdminEvent(actor, "device.revoked", {
          deviceId: device.id,
          userId: device.userId,
        });
        return json({ device: yield* store.deviceById(device.id) });
      }),
    ),
  ),
  HttpRouter.add(
    "GET",
    "/v1/admin/teams",
    respond(
      Effect.gen(function* () {
        yield* authorize("read:directory");
        const store = yield* Store;
        const month = monthOf(DateTime.formatIso(yield* DateTime.now));
        const teams = yield* store.listTeams;
        const rows = yield* Effect.forEach(teams, (team) =>
          Effect.map(store.teamTokensUsed(team.name, month), (used) => ({ ...team, used })),
        );
        return json({ teams: rows });
      }),
    ),
  ),
  HttpRouter.add(
    "PUT",
    "/v1/admin/teams/:name",
    respond(
      Effect.gen(function* () {
        const actor = yield* authorize("write:teams");
        const body = yield* readJson(TeamBody);
        yield* checkRegion(body.region);
        const team = {
          name: yield* param("name"),
          monthlyTokens: body.monthlyTokens ?? null,
          models: body.models ?? null,
          region: body.region ?? null,
        };
        yield* (yield* Store).upsertTeam(team);
        yield* (yield* ControlPlane).recordAdminEvent(actor, "team.updated", team);
        return json({ team });
      }),
    ),
  ),
  HttpRouter.add(
    "DELETE",
    "/v1/admin/teams/:name",
    respond(
      Effect.gen(function* () {
        const actor = yield* authorize("write:teams");
        const name = yield* param("name");
        yield* (yield* Store).deleteTeam(name);
        yield* (yield* ControlPlane).recordAdminEvent(actor, "team.deleted", { name });
        return json({ deleted: name });
      }),
    ),
  ),
  HttpRouter.add(
    "GET",
    "/v1/admin/groups",
    respond(
      Effect.gen(function* () {
        yield* authorize("read:directory");
        const config = yield* ControlPlaneConfig;
        const groups = yield* (yield* Store).listGroups;
        return json({
          groups: groups.map((group) => ({
            ...group,
            role: config.groupRoles[group.displayName] ?? null,
          })),
        });
      }),
    ),
  ),
);

const governanceRoutes = Layer.mergeAll(
  HttpRouter.add(
    "GET",
    "/v1/admin/policy",
    respond(
      Effect.gen(function* () {
        yield* authorize("read:policy");
        return json({ policy: (yield* (yield* Store).currentPolicy) ?? null });
      }),
    ),
  ),
  HttpRouter.add(
    "PUT",
    "/v1/admin/policy",
    respond(
      Effect.gen(function* () {
        const actor = yield* authorize("write:policy");
        const body = yield* readJson(PolicyBody).pipe(
          Effect.mapError(
            () =>
              new Refusal({
                status: 400,
                code: "invalid_policy",
                reason:
                  "document must be a T3 managed policy with schemaVersion 1 and organization; check it with `t3 policy check` first",
              }),
          ),
        );
        const version = yield* (yield* Store).publishPolicy(body.document, actor.email);
        yield* (yield* ControlPlane).recordAdminEvent(actor, "policy.published", { version });
        return json({ version });
      }),
    ),
  ),
  HttpRouter.add(
    "GET",
    "/v1/admin/usage",
    respond(
      Effect.gen(function* () {
        yield* authorize("read:usage");
        const params = searchParams(yield* HttpServerRequest.HttpServerRequest);
        const month = params.get("month") ?? monthOf(DateTime.formatIso(yield* DateTime.now));
        if (!/^\d{4}-\d{2}$/.test(month)) {
          return yield* refuse(400, "invalid_request", "month is YYYY-MM");
        }
        return json({ month, rows: yield* (yield* Store).usageReport(month) });
      }),
    ),
  ),
  HttpRouter.add(
    "GET",
    "/v1/admin/legal-holds",
    respond(
      Effect.gen(function* () {
        yield* authorize("read:audit");
        return json({ holds: yield* (yield* Store).legalHolds });
      }),
    ),
  ),
  HttpRouter.add(
    "PUT",
    "/v1/admin/legal-holds/:userId",
    respond(
      Effect.gen(function* () {
        const actor = yield* authorize("write:holds");
        const store = yield* Store;
        const user = yield* store.userById(yield* param("userId"));
        if (user === undefined) return yield* refuse(404, "not_found", "no such user");
        const body = yield* readJson(LegalHoldBody);
        yield* store.placeLegalHold(user.id, body.reason, actor.email);
        yield* (yield* ControlPlane).recordAdminEvent(actor, "legal_hold.placed", {
          userId: user.id,
          email: user.email,
          reason: body.reason,
        });
        return json({ held: user.id });
      }),
    ),
  ),
  HttpRouter.add(
    "DELETE",
    "/v1/admin/legal-holds/:userId",
    respond(
      Effect.gen(function* () {
        const actor = yield* authorize("write:holds");
        const userId = yield* param("userId");
        yield* (yield* Store).releaseLegalHold(userId);
        yield* (yield* ControlPlane).recordAdminEvent(actor, "legal_hold.released", { userId });
        return json({ released: userId });
      }),
    ),
  ),
);

const AUDIT_LIMIT_MAX = 5000;
const encodeLine = Schema.encodeEffect(Schema.fromJsonString(Schema.Unknown));

const auditQuery = Effect.gen(function* () {
  const params = searchParams(yield* HttpServerRequest.HttpServerRequest);
  const after = Number(params.get("after") ?? 0) || 0;
  const limit = Math.min(AUDIT_LIMIT_MAX, Math.max(1, Number(params.get("limit") ?? 200) || 200));
  const user = params.get("user");
  return yield* (yield* Store).listAudit({
    afterSeq: after,
    limit,
    ...(user === null ? {} : { userIds: [user] }),
  });
});

const auditRoutes = Layer.mergeAll(
  HttpRouter.add(
    "GET",
    "/v1/admin/audit",
    respond(
      Effect.gen(function* () {
        yield* authorize("read:audit");
        const after =
          Number(searchParams(yield* HttpServerRequest.HttpServerRequest).get("after") ?? 0) || 0;
        const events = yield* auditQuery;
        return json({ events, next: events.at(-1)?.seq ?? after });
      }),
    ),
  ),
  HttpRouter.add(
    "GET",
    "/v1/admin/audit.jsonl",
    respond(
      Effect.gen(function* () {
        yield* authorize("read:audit");
        const events = yield* auditQuery;
        const lines = yield* Effect.forEach(events, (event) => encodeLine(event)).pipe(
          Effect.orDie,
        );
        return asset(lines.map((line) => `${line}\n`).join(""), "application/x-ndjson");
      }),
    ),
  ),
);

export const layer = Layer.mergeAll(consoleRoutes, directoryRoutes, governanceRoutes, auditRoutes);
