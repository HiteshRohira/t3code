import * as NodeFS from "node:fs";
import type * as NodeHttp from "node:http";

import { isRole, type Role } from "@t3tools/enterprise-protocol/wire";

import type { ControlPlane } from "./app.ts";
import { HttpError, readJson, sendHtml, sendJson, sendText } from "./http.ts";
import { monthOf } from "./store.ts";

export interface AdminActor {
  readonly id: string;
  readonly email: string;
  readonly roles: ReadonlyArray<Role>;
  /** Cookie sessions must send the CSRF header on writes; the API token need not. */
  readonly viaCookie: boolean;
}

type Permission =
  | "read:directory"
  | "write:users"
  | "revoke:devices"
  | "write:teams"
  | "read:policy"
  | "write:policy"
  | "read:audit"
  | "read:usage";

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
  ],
  maintainer: ["read:directory", "revoke:devices", "write:teams", "read:policy", "read:usage"],
  auditor: ["read:directory", "read:policy", "read:audit", "read:usage"],
  developer: [],
  viewer: [],
};

export const permissionsOf = (roles: ReadonlyArray<Role>) => [
  ...new Set(roles.flatMap((role) => GRANTS[role])),
];

const asset = (name: string) =>
  NodeFS.readFileSync(new URL(`./admin-ui/${name}`, import.meta.url), "utf8");

const CSRF_HEADER = "x-t3e-admin";

const nullableNumber = (value: unknown, field: string): number | null => {
  if (value === null) return null;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new HttpError(400, "invalid_request", `${field} must be a non-negative integer or null`);
  }
  return value;
};

const nullableStrings = (value: unknown, field: string): ReadonlyArray<string> | null => {
  if (value === null) return null;
  if (
    !Array.isArray(value) ||
    !value.every((item) => typeof item === "string" && item.length > 0)
  ) {
    throw new HttpError(400, "invalid_request", `${field} must be a list of model ids or null`);
  }
  return value;
};

export async function handleAdmin(
  plane: ControlPlane,
  request: NodeHttp.IncomingMessage,
  response: NodeHttp.ServerResponse,
  url: URL,
) {
  const method = request.method ?? "GET";

  if (method === "GET" && url.pathname.startsWith("/admin/assets/")) {
    const name = url.pathname.slice("/admin/assets/".length);
    if (name === "admin.css")
      return sendText(response, 200, asset("admin.css"), "text/css; charset=utf-8");
    if (name === "admin.js")
      return sendText(response, 200, asset("admin.js"), "text/javascript; charset=utf-8");
    throw new HttpError(404, "not_found", "no such asset");
  }

  const actor = plane.adminActor(request);
  if (url.pathname === "/admin" && method === "GET") {
    if (actor === undefined) {
      response.writeHead(302, { location: "/admin/login", "cache-control": "no-store" });
      response.end();
      return;
    }
    return sendHtml(response, 200, asset("index.html"));
  }
  if (actor === undefined) throw new HttpError(401, "unauthorized", "sign in at /admin");
  if (method !== "GET" && actor.viaCookie && request.headers[CSRF_HEADER] !== "1") {
    throw new HttpError(403, "csrf", `send the ${CSRF_HEADER} header`);
  }
  const permissions = permissionsOf(actor.roles);
  const need = (permission: Permission) => {
    if (!permissions.includes(permission))
      throw new HttpError(403, "forbidden", `requires ${permission}`);
  };
  const path = url.pathname.replace(/^\/v1\/admin/, "");
  const segments = path
    .split("/")
    .filter((part) => part.length > 0)
    .map(decodeURIComponent);

  if (method === "GET" && path === "/me") {
    return sendJson(response, 200, {
      email: actor.email,
      roles: actor.roles,
      permissions,
      organization: plane.config.organization,
    });
  }

  if (segments[0] === "users") {
    if (method === "GET" && segments.length === 1) {
      need("read:directory");
      const month = monthOf(new Date());
      return sendJson(response, 200, {
        users: plane.store
          .listUsers()
          .map((user) => ({ ...user, budget: plane.budgetOf(user, month) })),
      });
    }
    if (method === "PATCH" && segments.length === 2) {
      need("write:users");
      const user = plane.store.userById(segments[1]!);
      if (user === undefined) throw new HttpError(404, "not_found", "no such user");
      const body = (await readJson(request)) as Record<string, unknown>;
      const patch: Parameters<typeof plane.store.updateUser>[1] = {};
      if ("roles" in body) {
        if (!Array.isArray(body["roles"]) || !body["roles"].every(isRole)) {
          throw new HttpError(400, "invalid_request", "roles must be a list of roles");
        }
        patch.roles = body["roles"];
      }
      if ("team" in body) {
        if (body["team"] !== null && typeof body["team"] !== "string") {
          throw new HttpError(400, "invalid_request", "team must be a string or null");
        }
        patch.team = body["team"] === "" ? null : body["team"];
      }
      if ("models" in body) patch.models = nullableStrings(body["models"], "models");
      if ("monthlyTokens" in body)
        patch.monthlyTokens = nullableNumber(body["monthlyTokens"], "monthlyTokens");
      let updated = plane.store.updateUser(user.id, patch);
      if (body["active"] === false && user.active) updated = plane.store.deactivateUser(user.id);
      if (body["active"] === true && !user.active)
        updated = plane.store.updateUser(user.id, { active: true });
      await plane.recordAdminEvent(actor, "user.updated", {
        userId: user.id,
        email: user.email,
        changes: body,
      });
      return sendJson(response, 200, { user: updated });
    }
  }

  if (segments[0] === "devices") {
    if (method === "GET" && segments.length === 1) {
      need("read:directory");
      const users = new Map(plane.store.listUsers().map((user) => [user.id, user]));
      const userFilter = url.searchParams.get("user") ?? undefined;
      return sendJson(response, 200, {
        devices: plane.store.listDevices(userFilter).map((device) => ({
          ...device,
          email: users.get(device.userId)?.email ?? null,
          status: plane.deviceDenial(device) ?? "active",
        })),
      });
    }
    if (method === "POST" && segments.length === 3 && segments[2] === "revoke") {
      need("revoke:devices");
      const device = plane.store.deviceById(segments[1]!);
      if (device === undefined) throw new HttpError(404, "not_found", "no such device");
      plane.store.revokeDevice(device.id);
      await plane.recordAdminEvent(actor, "device.revoked", {
        deviceId: device.id,
        userId: device.userId,
      });
      return sendJson(response, 200, { device: plane.store.deviceById(device.id) });
    }
  }

  if (segments[0] === "teams") {
    if (method === "GET" && segments.length === 1) {
      need("read:directory");
      const month = monthOf(new Date());
      return sendJson(response, 200, {
        teams: plane.store
          .listTeams()
          .map((team) => ({ ...team, used: plane.store.teamTokensUsed(team.name, month) })),
      });
    }
    if (method === "PUT" && segments.length === 2) {
      need("write:teams");
      const body = (await readJson(request)) as Record<string, unknown>;
      const team = {
        name: segments[1]!,
        monthlyTokens: nullableNumber(body["monthlyTokens"] ?? null, "monthlyTokens"),
        models: nullableStrings(body["models"] ?? null, "models"),
      };
      plane.store.upsertTeam(team);
      await plane.recordAdminEvent(actor, "team.updated", team);
      return sendJson(response, 200, { team });
    }
    if (method === "DELETE" && segments.length === 2) {
      need("write:teams");
      plane.store.deleteTeam(segments[1]!);
      await plane.recordAdminEvent(actor, "team.deleted", { name: segments[1] });
      return sendJson(response, 200, { deleted: segments[1] });
    }
  }

  if (path === "/policy") {
    if (method === "GET") {
      need("read:policy");
      return sendJson(response, 200, { policy: plane.store.currentPolicy() ?? null });
    }
    if (method === "PUT") {
      need("write:policy");
      const body = (await readJson(request)) as Record<string, unknown>;
      const document = body["document"] as Record<string, unknown> | undefined;
      if (
        typeof document !== "object" ||
        document === null ||
        Array.isArray(document) ||
        document["schemaVersion"] !== 1 ||
        typeof document["organization"] !== "string"
      ) {
        throw new HttpError(
          400,
          "invalid_policy",
          "document must be a T3 managed policy with schemaVersion 1 and organization; check it with `t3 policy check` first",
        );
      }
      const version = plane.store.publishPolicy(document, actor.email);
      await plane.recordAdminEvent(actor, "policy.published", { version });
      return sendJson(response, 200, { version });
    }
  }

  if (method === "GET" && path === "/usage") {
    need("read:usage");
    const month = url.searchParams.get("month") ?? monthOf(new Date());
    if (!/^\d{4}-\d{2}$/.test(month))
      throw new HttpError(400, "invalid_request", "month is YYYY-MM");
    return sendJson(response, 200, { month, rows: plane.store.usageReport(month) });
  }

  if (method === "GET" && (path === "/audit" || path === "/audit.jsonl")) {
    need("read:audit");
    const after = Number(url.searchParams.get("after") ?? 0) || 0;
    const limit = Math.min(5000, Math.max(1, Number(url.searchParams.get("limit") ?? 200) || 200));
    const userId = url.searchParams.get("user") ?? undefined;
    const events = plane.store.listAudit({
      afterSeq: after,
      limit,
      ...(userId === undefined ? {} : { userId }),
    });
    if (path === "/audit.jsonl") {
      return sendText(
        response,
        200,
        events.map((event) => JSON.stringify(event)).join("\n") + (events.length > 0 ? "\n" : ""),
        "application/x-ndjson",
      );
    }
    return sendJson(response, 200, { events, next: events.at(-1)?.seq ?? after });
  }

  throw new HttpError(404, "not_found", "no such admin route");
}
