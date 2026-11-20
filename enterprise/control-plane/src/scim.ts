// SCIM 2.0 Users (RFC 7643/7644), the subset Okta and Microsoft Entra provision with.
// Deleting a user deactivates it, so audit history keeps its owner.
import type * as NodeHttp from "node:http";

import { isRole, type Role } from "@t3tools/enterprise-protocol/wire";

import type { ControlPlane } from "./app.ts";
import { bearer, constantTimeEqual, HttpError, readJson, sendJson } from "./http.ts";
import type { User } from "./store.ts";

const USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
const ENTERPRISE_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
const LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";
const SCIM_TYPE = "application/scim+json";

class ScimError extends HttpError {
  readonly scimType: string | undefined;
  constructor(status: number, detail: string, scimType?: string) {
    super(status, scimType ?? "scim_error", detail);
    this.scimType = scimType;
  }
}

function toScim(plane: ControlPlane, user: User) {
  return {
    schemas: [USER_SCHEMA, ENTERPRISE_SCHEMA],
    id: user.id,
    ...(user.externalId === null ? {} : { externalId: user.externalId }),
    userName: user.email,
    ...(user.name === null ? {} : { displayName: user.name, name: { formatted: user.name } }),
    emails: [{ value: user.email, primary: true, type: "work" }],
    active: user.active,
    roles: user.roles.map((role) => ({ value: role })),
    [ENTERPRISE_SCHEMA]: user.team === null ? {} : { department: user.team },
    meta: {
      resourceType: "User",
      created: user.createdAt,
      lastModified: user.updatedAt,
      location: `${plane.config.publicUrl}/scim/v2/Users/${user.id}`,
    },
  };
}

const bool = (value: unknown): boolean | undefined => {
  if (typeof value === "boolean") return value;
  if (typeof value === "string" && /^(true|false)$/i.test(value))
    return value.toLowerCase() === "true";
  return undefined;
};

const rolesOf = (value: unknown): ReadonlyArray<Role> | undefined => {
  if (!Array.isArray(value)) return undefined;
  return value
    .map((item) =>
      typeof item === "object" && item !== null ? (item as Record<string, unknown>)["value"] : item,
    )
    .filter(isRole);
};

interface UserFields {
  email?: string;
  name?: string | null;
  externalId?: string | null;
  active?: boolean;
  roles?: ReadonlyArray<Role>;
  team?: string | null;
}

/** Reads the attributes this control plane keeps from a full SCIM User resource. */
function fieldsOf(resource: Record<string, unknown>): UserFields {
  const fields: UserFields = {};
  const emails = resource["emails"];
  const primary = Array.isArray(emails)
    ? (emails.find((email) => (email as Record<string, unknown>)?.["primary"] === true) ??
      emails[0])
    : undefined;
  const email = resource["userName"] ?? (primary as Record<string, unknown> | undefined)?.["value"];
  if (typeof email === "string") fields.email = email.toLowerCase();
  const name =
    resource["displayName"] ??
    (resource["name"] as Record<string, unknown> | undefined)?.["formatted"];
  if (typeof name === "string") fields.name = name;
  if (typeof resource["externalId"] === "string") fields.externalId = resource["externalId"];
  const active = bool(resource["active"]);
  if (active !== undefined) fields.active = active;
  const roles = rolesOf(resource["roles"]);
  if (roles !== undefined) fields.roles = roles;
  const department = (resource[ENTERPRISE_SCHEMA] as Record<string, unknown> | undefined)?.[
    "department"
  ];
  if (typeof department === "string") fields.team = department.length === 0 ? null : department;
  return fields;
}

/** One PATCH operation as fields; paths are matched without regard to case, as Entra sends them. */
function patchFields(operation: Record<string, unknown>): UserFields {
  const op = String(operation["op"] ?? "").toLowerCase();
  if (op !== "replace" && op !== "add" && op !== "remove") {
    throw new ScimError(400, `unsupported op ${String(operation["op"])}`, "invalidSyntax");
  }
  const path = typeof operation["path"] === "string" ? operation["path"] : undefined;
  const value = op === "remove" ? null : operation["value"];
  if (path === undefined) {
    if (typeof value !== "object" || value === null) {
      throw new ScimError(400, "a PATCH without a path needs an object value", "invalidValue");
    }
    return fieldsOf(value as Record<string, unknown>);
  }
  const key = path.toLowerCase();
  if (key === "active") {
    const active = bool(value);
    if (active === undefined) throw new ScimError(400, "active must be a boolean", "invalidValue");
    return { active };
  }
  if (key === "username" || key.startsWith("emails")) {
    return typeof value === "string" ? { email: value.toLowerCase() } : {};
  }
  if (key === "displayname" || key === "name.formatted") {
    return { name: typeof value === "string" ? value : null };
  }
  if (key === "externalid") return { externalId: typeof value === "string" ? value : null };
  if (key === "roles") return { roles: rolesOf(value) ?? [] };
  if (key === `${ENTERPRISE_SCHEMA}:department`.toLowerCase()) {
    return { team: typeof value === "string" && value.length > 0 ? value : null };
  }
  // Attributes this control plane does not keep are accepted and ignored, as RFC 7644 allows.
  return {};
}

function parseFilter(
  filter: string | null,
): { attribute: "userName" | "externalId"; value: string } | undefined {
  if (filter === null) return undefined;
  const match = /^\s*(userName|externalId)\s+eq\s+"([^"]*)"\s*$/i.exec(filter);
  if (match === null)
    throw new ScimError(
      400,
      "only userName eq and externalId eq filters are supported",
      "invalidFilter",
    );
  return {
    attribute: match[1]!.toLowerCase() === "username" ? "userName" : "externalId",
    value: match[2]!,
  };
}

async function apply(plane: ControlPlane, user: User, fields: UserFields): Promise<User> {
  if (fields.email !== undefined && fields.email !== user.email) {
    const other = plane.store.userByEmail(fields.email);
    if (other !== undefined && other.id !== user.id)
      throw new ScimError(409, "userName is taken", "uniqueness");
  }
  const { active, ...rest } = fields;
  let updated = plane.store.updateUser(user.id, rest) ?? user;
  if (active === false && user.active) {
    updated = plane.store.deactivateUser(user.id) ?? updated;
    await plane.recordAdminEvent({ id: "scim", email: "scim" }, "user.deactivated", {
      userId: user.id,
      email: user.email,
    });
  } else if (active === true && !user.active) {
    updated = plane.store.updateUser(user.id, { active: true }) ?? updated;
    await plane.recordAdminEvent({ id: "scim", email: "scim" }, "user.reactivated", {
      userId: user.id,
      email: user.email,
    });
  }
  return updated;
}

export async function handleScim(
  plane: ControlPlane,
  request: NodeHttp.IncomingMessage,
  response: NodeHttp.ServerResponse,
  url: URL,
) {
  try {
    const token = bearer(request);
    const expected = plane.config.secrets.scimToken;
    if (expected === undefined) throw new ScimError(404, "SCIM is not enabled");
    if (token === undefined || !constantTimeEqual(token, expected))
      throw new ScimError(401, "invalid SCIM token");
    await route(plane, request, response, url);
  } catch (error) {
    if (!(error instanceof HttpError)) throw error;
    sendJson(
      response,
      error.status,
      {
        schemas: [ERROR_SCHEMA],
        status: String(error.status),
        detail: error.message,
        ...(error instanceof ScimError && error.scimType !== undefined
          ? { scimType: error.scimType }
          : {}),
      },
      SCIM_TYPE,
    );
  }
}

async function route(
  plane: ControlPlane,
  request: NodeHttp.IncomingMessage,
  response: NodeHttp.ServerResponse,
  url: URL,
) {
  const method = request.method ?? "GET";
  const path = url.pathname.replace(/^\/scim\/v2/, "");

  if (path === "/ServiceProviderConfig" && method === "GET") {
    return sendJson(
      response,
      200,
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        patch: { supported: true },
        bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
        filter: { supported: true, maxResults: 200 },
        changePassword: { supported: false },
        sort: { supported: false },
        etag: { supported: false },
        authenticationSchemes: [
          { type: "oauthbearertoken", name: "Bearer token", description: "Static bearer token" },
        ],
      },
      SCIM_TYPE,
    );
  }

  if (path === "/Users" && method === "GET") {
    const filter = parseFilter(url.searchParams.get("filter"));
    const all =
      filter === undefined
        ? plane.store.listUsers()
        : [
            filter.attribute === "userName"
              ? plane.store.userByEmail(filter.value.toLowerCase())
              : plane.store.userByExternalId(filter.value),
          ].filter((user): user is User => user !== undefined);
    const startIndex = Math.max(1, Number(url.searchParams.get("startIndex") ?? 1) || 1);
    const count = Math.min(200, Math.max(0, Number(url.searchParams.get("count") ?? 100) || 100));
    const page = all.slice(startIndex - 1, startIndex - 1 + count);
    return sendJson(
      response,
      200,
      {
        schemas: [LIST_SCHEMA],
        totalResults: all.length,
        startIndex,
        itemsPerPage: page.length,
        Resources: page.map((user) => toScim(plane, user)),
      },
      SCIM_TYPE,
    );
  }

  if (path === "/Users" && method === "POST") {
    const fields = fieldsOf((await readJson(request)) as Record<string, unknown>);
    if (fields.email === undefined)
      throw new ScimError(400, "userName is required", "invalidValue");
    if (plane.store.userByEmail(fields.email) !== undefined)
      throw new ScimError(409, "userName is taken", "uniqueness");
    const user = plane.store.createUser({
      email: fields.email,
      name: fields.name ?? null,
      externalId: fields.externalId ?? null,
      active: fields.active ?? true,
      roles:
        fields.roles === undefined || fields.roles.length === 0
          ? [plane.config.defaultRole]
          : fields.roles,
      team: fields.team ?? null,
    });
    await plane.recordAdminEvent({ id: "scim", email: "scim" }, "user.provisioned", {
      userId: user.id,
      email: user.email,
    });
    return sendJson(response, 201, toScim(plane, user), SCIM_TYPE);
  }

  const match = /^\/Users\/([^/]+)$/.exec(path);
  if (match === null) throw new ScimError(404, "unknown SCIM resource");
  const user = plane.store.userById(decodeURIComponent(match[1]!));
  if (user === undefined) throw new ScimError(404, "user not found");

  switch (method) {
    case "GET":
      return sendJson(response, 200, toScim(plane, user), SCIM_TYPE);
    case "PUT": {
      const fields = fieldsOf((await readJson(request)) as Record<string, unknown>);
      return sendJson(response, 200, toScim(plane, await apply(plane, user, fields)), SCIM_TYPE);
    }
    case "PATCH": {
      const body = (await readJson(request)) as Record<string, unknown>;
      const schemas = body["schemas"];
      const operations = body["Operations"];
      if (
        !Array.isArray(schemas) ||
        !schemas.includes(PATCH_SCHEMA) ||
        !Array.isArray(operations)
      ) {
        throw new ScimError(400, "expected a PatchOp", "invalidSyntax");
      }
      const fields: UserFields = {};
      for (const operation of operations) {
        Object.assign(fields, patchFields(operation as Record<string, unknown>));
      }
      return sendJson(response, 200, toScim(plane, await apply(plane, user, fields)), SCIM_TYPE);
    }
    case "DELETE":
      await apply(plane, user, { active: false });
      response.writeHead(204);
      response.end();
      return;
  }
  throw new ScimError(405, "method not allowed");
}
