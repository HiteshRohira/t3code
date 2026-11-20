/**
 * ScimRoutes - SCIM 2.0 Users and Groups (RFC 7643/7644), the subset Okta and Microsoft Entra
 * provision with. Deleting a user deactivates it, so audit history keeps its owner. Group
 * membership maps to roles through `groupRoles`, the same mapping sign-in uses.
 *
 * @module ScimRoutes
 */
import { isRole, type Role } from "@t3tools/enterprise-protocol/wire";
import * as Cause from "effect/Cause";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import { HttpRouter, HttpServerRequest, HttpServerResponse } from "effect/http";

import { ControlPlaneConfig } from "./Config.ts";
import { ControlPlane, Refusal } from "./ControlPlane.ts";
import * as Crypto from "./Crypto.ts";
import { bearer, json, readJson, searchParams } from "./Http.ts";
import { Store, type Group, type User } from "./Store.ts";

const USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group";
const ENTERPRISE_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
const LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";
const SCIM_TYPE = "application/scim+json";
const SCIM_ACTOR = { id: "scim", email: "scim" };

class ScimError extends Schema.TaggedError<ScimError>()("ScimError", {
  status: Schema.Number,
  detail: Schema.String,
  scimType: Schema.optional(Schema.String),
}) {}

const fail = (status: number, detail: string, scimType?: string) =>
  Effect.fail(new ScimError({ status, detail, ...(scimType === undefined ? {} : { scimType }) }));

const scim = (body: unknown, status = 200) => json(body, status, SCIM_TYPE);

type Json = Record<string, unknown>;
const Resource = Schema.Record(Schema.String, Schema.Unknown);

const bool = (value: unknown): boolean | undefined => {
  if (typeof value === "boolean") return value;
  if (typeof value === "string" && /^(true|false)$/i.test(value)) {
    return value.toLowerCase() === "true";
  }
  return undefined;
};

const values = (value: unknown): ReadonlyArray<unknown> =>
  Array.isArray(value)
    ? value.map((item) =>
        typeof item === "object" && item !== null ? (item as Json)["value"] : item,
      )
    : [];

const rolesOf = (value: unknown): ReadonlyArray<Role> | undefined =>
  Array.isArray(value) ? values(value).filter(isRole) : undefined;

const memberIds = (value: unknown): ReadonlyArray<string> =>
  values(value).filter((item): item is string => typeof item === "string");

// Users

interface UserFields {
  email?: string;
  name?: string | null;
  externalId?: string | null;
  active?: boolean;
  roles?: ReadonlyArray<Role>;
  team?: string | null;
}

const toScimUser = (publicUrl: string, user: User, groups: ReadonlyArray<Group> = []) => ({
  schemas: [USER_SCHEMA, ENTERPRISE_SCHEMA],
  id: user.id,
  ...(user.externalId === null ? {} : { externalId: user.externalId }),
  userName: user.email,
  ...(user.name === null ? {} : { displayName: user.name, name: { formatted: user.name } }),
  emails: [{ value: user.email, primary: true, type: "work" }],
  active: user.active,
  roles: user.roles.map((role) => ({ value: role })),
  groups: groups.map((group) => ({ value: group.id, display: group.displayName })),
  [ENTERPRISE_SCHEMA]: user.team === null ? {} : { department: user.team },
  meta: {
    resourceType: "User",
    created: user.createdAt,
    lastModified: user.updatedAt,
    location: `${publicUrl}/scim/v2/Users/${user.id}`,
  },
});

/** Reads the attributes this control plane keeps from a full SCIM User resource. */
function userFieldsOf(resource: Json): UserFields {
  const fields: UserFields = {};
  const emails = resource["emails"];
  const primary = Array.isArray(emails)
    ? (emails.find((email) => (email as Json | null)?.["primary"] === true) ?? emails[0])
    : undefined;
  const email = resource["userName"] ?? (primary as Json | undefined)?.["value"];
  if (typeof email === "string") fields.email = email.toLowerCase();
  const name = resource["displayName"] ?? (resource["name"] as Json | undefined)?.["formatted"];
  if (typeof name === "string") fields.name = name;
  if (typeof resource["externalId"] === "string") fields.externalId = resource["externalId"];
  const active = bool(resource["active"]);
  if (active !== undefined) fields.active = active;
  const roles = rolesOf(resource["roles"]);
  if (roles !== undefined) fields.roles = roles;
  const department = (resource[ENTERPRISE_SCHEMA] as Json | undefined)?.["department"];
  if (typeof department === "string") fields.team = department.length === 0 ? null : department;
  return fields;
}

/** One PATCH operation as fields; paths are matched without regard to case, as Entra sends them. */
const userPatchFields = Effect.fn("Scim.userPatchFields")(function* (operation: Json) {
  const op = String(operation["op"] ?? "").toLowerCase();
  if (op !== "replace" && op !== "add" && op !== "remove") {
    return yield* fail(400, `unsupported op ${String(operation["op"])}`, "invalidSyntax");
  }
  const path = typeof operation["path"] === "string" ? operation["path"] : undefined;
  const value = op === "remove" ? null : operation["value"];
  if (path === undefined) {
    if (typeof value !== "object" || value === null) {
      return yield* fail(400, "a PATCH without a path needs an object value", "invalidValue");
    }
    return userFieldsOf(value as Json);
  }
  const key = path.toLowerCase();
  if (key === "active") {
    const active = bool(value);
    if (active === undefined) return yield* fail(400, "active must be a boolean", "invalidValue");
    return { active } satisfies UserFields;
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
  return {} satisfies UserFields;
});

const parseFilter = Effect.fn("Scim.parseFilter")(function* (
  filter: string | null,
  attributes: ReadonlyArray<string>,
) {
  if (filter === null) return undefined;
  const match = /^\s*(\w+)\s+eq\s+"([^"]*)"\s*$/i.exec(filter);
  const attribute = attributes.find(
    (candidate) => candidate.toLowerCase() === match?.[1]?.toLowerCase(),
  );
  if (match === null || attribute === undefined) {
    return yield* fail(
      400,
      `only ${attributes.map((name) => `${name} eq`).join(" and ")} filters are supported`,
      "invalidFilter",
    );
  }
  return { attribute, value: match[2]! };
});

const page = <A>(all: ReadonlyArray<A>, params: URLSearchParams, toResource: (a: A) => unknown) => {
  const startIndex = Math.max(1, Number(params.get("startIndex") ?? 1) || 1);
  const count = Math.min(200, Math.max(0, Number(params.get("count") ?? 100) || 100));
  const slice = all.slice(startIndex - 1, startIndex - 1 + count);
  return scim({
    schemas: [LIST_SCHEMA],
    totalResults: all.length,
    startIndex,
    itemsPerPage: slice.length,
    Resources: slice.map(toResource),
  });
};

const applyUser = Effect.fn("Scim.applyUser")(function* (user: User, fields: UserFields) {
  const store = yield* Store;
  const plane = yield* ControlPlane;
  if (fields.email !== undefined && fields.email !== user.email) {
    const other = yield* store.userByEmail(fields.email);
    if (other !== undefined && other.id !== user.id) {
      return yield* fail(409, "userName is taken", "uniqueness");
    }
  }
  const { active, ...rest } = fields;
  yield* store.updateUser(user.id, rest);
  if (active !== undefined) yield* plane.setActive(SCIM_ACTOR, user, active);
  return (yield* store.userById(user.id)) ?? user;
});

const userResponse = Effect.fn("Scim.userResponse")(function* (user: User, status = 200) {
  const config = yield* ControlPlaneConfig;
  const store = yield* Store;
  const groupNames = new Set(yield* store.groupsOf(user.id));
  const groups = (yield* store.listGroups).filter((group) => groupNames.has(group.displayName));
  return scim(toScimUser(config.publicUrl, user, groups), status);
});

const findUser = Effect.gen(function* () {
  const id = decodeURIComponent((yield* HttpRouter.params)["id"] ?? "");
  const user = yield* (yield* Store).userById(id);
  if (user === undefined) return yield* fail(404, "user not found");
  return user;
});

// Groups

const toScimGroup = (publicUrl: string, group: Group, emails: ReadonlyMap<string, string>) => ({
  schemas: [GROUP_SCHEMA],
  id: group.id,
  ...(group.externalId === null ? {} : { externalId: group.externalId }),
  displayName: group.displayName,
  members: group.members.map((id) => ({ value: id, display: emails.get(id) ?? id })),
  meta: { resourceType: "Group", location: `${publicUrl}/scim/v2/Groups/${group.id}` },
});

const groupResponse = Effect.fn("Scim.groupResponse")(function* (groupId: string, status = 200) {
  const config = yield* ControlPlaneConfig;
  const store = yield* Store;
  const group = yield* store.groupById(groupId);
  if (group === undefined) return yield* fail(404, "group not found");
  const emails = new Map((yield* store.listUsers).map((user) => [user.id, user.email]));
  return scim(toScimGroup(config.publicUrl, group, emails), status);
});

const findGroup = Effect.gen(function* () {
  const id = decodeURIComponent((yield* HttpRouter.params)["id"] ?? "");
  const group = yield* (yield* Store).groupById(id);
  if (group === undefined) return yield* fail(404, "group not found");
  return group;
});

/** Renames, member changes, and role recomputation for everyone whose membership changed. */
const changeGroup = Effect.fn("Scim.changeGroup")(function* (
  group: Group,
  change: {
    displayName?: string;
    set?: ReadonlyArray<string>;
    add?: ReadonlyArray<string>;
    remove?: ReadonlyArray<string>;
  },
) {
  const store = yield* Store;
  const plane = yield* ControlPlane;
  if (change.displayName !== undefined && change.displayName !== group.displayName) {
    const other = yield* store.groupByName(change.displayName);
    if (other !== undefined && other.id !== group.id) {
      return yield* fail(409, "displayName is taken", "uniqueness");
    }
    yield* store.renameGroup(group.id, change.displayName);
  }
  if (change.set !== undefined) yield* store.setGroupMembers(group.id, change.set);
  if (change.add !== undefined) yield* store.addGroupMembers(group.id, change.add);
  if (change.remove !== undefined) yield* store.removeGroupMembers(group.id, change.remove);
  const after = yield* store.groupById(group.id);
  yield* plane.applyGroupRoles([...group.members, ...(after?.members ?? [])]);
  yield* plane.recordAdminEvent(SCIM_ACTOR, "group.updated", {
    groupId: group.id,
    displayName: after?.displayName ?? group.displayName,
    members: after?.members.length ?? 0,
  });
});

/** `members[value eq "id"]`, the path Entra uses to remove one member. */
const memberFilter = /^members\[value eq "([^"]+)"\]$/i;

const groupPatch = Effect.fn("Scim.groupPatch")(function* (
  group: Group,
  operations: ReadonlyArray<unknown>,
) {
  for (const raw of operations) {
    const operation = (typeof raw === "object" && raw !== null ? raw : {}) as Json;
    const op = String(operation["op"] ?? "").toLowerCase();
    const path = typeof operation["path"] === "string" ? operation["path"] : undefined;
    const value = operation["value"];
    const current = (yield* (yield* Store).groupById(group.id)) ?? group;
    if (path === undefined) {
      if (op !== "replace" && op !== "add") {
        return yield* fail(400, "a PATCH without a path must replace or add", "invalidSyntax");
      }
      const resource = (typeof value === "object" && value !== null ? value : {}) as Json;
      yield* changeGroup(current, {
        ...(typeof resource["displayName"] === "string"
          ? { displayName: resource["displayName"] }
          : {}),
        ...(resource["members"] === undefined
          ? {}
          : op === "add"
            ? { add: memberIds(resource["members"]) }
            : { set: memberIds(resource["members"]) }),
      });
      continue;
    }
    const key = path.toLowerCase();
    const single = memberFilter.exec(path);
    if (key === "displayname" && op !== "remove" && typeof value === "string") {
      yield* changeGroup(current, { displayName: value });
    } else if (key === "members" && op === "add") {
      yield* changeGroup(current, { add: memberIds(value) });
    } else if (key === "members" && op === "replace") {
      yield* changeGroup(current, { set: memberIds(value) });
    } else if (key === "members" && op === "remove") {
      yield* changeGroup(current, value === undefined ? { set: [] } : { remove: memberIds(value) });
    } else if (single !== null && op === "remove") {
      yield* changeGroup(current, { remove: [single[1]!] });
    } else if (key !== "externalid") {
      return yield* fail(400, `unsupported group PATCH ${op} ${path}`, "invalidPath");
    }
  }
});

const readPatchOperations = Effect.gen(function* () {
  const body = yield* readJson(Resource);
  const schemas = body["schemas"];
  const operations = body["Operations"];
  if (!Array.isArray(schemas) || !schemas.includes(PATCH_SCHEMA) || !Array.isArray(operations)) {
    return yield* fail(400, "expected a PatchOp", "invalidSyntax");
  }
  return operations as ReadonlyArray<unknown>;
});

const isScimError = Schema.is(ScimError);
const isRefusal = Schema.is(Refusal);

const scimError = (status: number, detail: string, scimType?: string) =>
  scim(
    {
      schemas: [ERROR_SCHEMA],
      status: String(status),
      detail,
      ...(scimType === undefined ? {} : { scimType }),
    },
    status,
  );

const authorizeScim = Effect.gen(function* () {
  const config = yield* ControlPlaneConfig;
  const expected = config.secrets.scimToken;
  if (expected === undefined) return yield* fail(404, "SCIM is not enabled");
  const token = bearer(yield* HttpServerRequest.HttpServerRequest);
  if (token === undefined || !Crypto.constantTimeEqual(token, expected)) {
    return yield* fail(401, "invalid SCIM token");
  }
});

/** Bearer-token check, then the handler; every failure answers in SCIM's error shape. */
const scimRoute = <E, R>(handler: Effect.Effect<HttpServerResponse.HttpServerResponse, E, R>) =>
  Effect.andThen(authorizeScim, handler).pipe(
    Effect.catchCause((cause) => {
      const error = Cause.findErrorOption(cause);
      if (Option.isSome(error) && isScimError(error.value)) {
        return Effect.succeed(
          scimError(error.value.status, error.value.detail, error.value.scimType),
        );
      }
      if (Option.isSome(error) && isRefusal(error.value)) {
        return Effect.succeed(scimError(error.value.status, error.value.reason));
      }
      return Effect.logError("SCIM request failed", { cause }).pipe(
        Effect.as(scimError(500, "internal error")),
      );
    }),
  );

const userRoutes = Layer.mergeAll(
  HttpRouter.add(
    "GET",
    "/scim/v2/ServiceProviderConfig",
    scimRoute(
      Effect.succeed(
        scim({
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
        }),
      ),
    ),
  ),
  HttpRouter.add(
    "GET",
    "/scim/v2/Users",
    scimRoute(
      Effect.gen(function* () {
        const config = yield* ControlPlaneConfig;
        const store = yield* Store;
        const params = searchParams(yield* HttpServerRequest.HttpServerRequest);
        const filter = yield* parseFilter(params.get("filter"), ["userName", "externalId"]);
        const all =
          filter === undefined
            ? yield* store.listUsers
            : [
                filter.attribute === "userName"
                  ? yield* store.userByEmail(filter.value.toLowerCase())
                  : yield* store.userByExternalId(filter.value),
              ].filter((user): user is User => user !== undefined);
        return page(all, params, (user) => toScimUser(config.publicUrl, user));
      }),
    ),
  ),
  HttpRouter.add(
    "POST",
    "/scim/v2/Users",
    scimRoute(
      Effect.gen(function* () {
        const config = yield* ControlPlaneConfig;
        const store = yield* Store;
        const fields = userFieldsOf(yield* readJson(Resource));
        if (fields.email === undefined)
          return yield* fail(400, "userName is required", "invalidValue");
        if ((yield* store.userByEmail(fields.email)) !== undefined) {
          return yield* fail(409, "userName is taken", "uniqueness");
        }
        const user = yield* store.createUser({
          id: yield* Crypto.uuid,
          email: fields.email,
          name: fields.name ?? null,
          externalId: fields.externalId ?? null,
          active: fields.active ?? true,
          roles:
            fields.roles === undefined || fields.roles.length === 0
              ? [config.defaultRole]
              : fields.roles,
          team: fields.team ?? null,
          region: config.defaultRegion ?? null,
        });
        yield* (yield* ControlPlane).recordAdminEvent(SCIM_ACTOR, "user.provisioned", {
          userId: user.id,
          email: user.email,
        });
        return yield* userResponse(user, 201);
      }),
    ),
  ),
  HttpRouter.add(
    "GET",
    "/scim/v2/Users/:id",
    scimRoute(Effect.flatMap(findUser, (user) => userResponse(user))),
  ),
  HttpRouter.add(
    "PUT",
    "/scim/v2/Users/:id",
    scimRoute(
      Effect.gen(function* () {
        const user = yield* findUser;
        const fields = userFieldsOf(yield* readJson(Resource));
        return yield* userResponse(yield* applyUser(user, fields));
      }),
    ),
  ),
  HttpRouter.add(
    "PATCH",
    "/scim/v2/Users/:id",
    scimRoute(
      Effect.gen(function* () {
        const user = yield* findUser;
        const operations = yield* readPatchOperations;
        const fields: UserFields = {};
        for (const operation of operations) {
          Object.assign(fields, yield* userPatchFields((operation ?? {}) as Json));
        }
        return yield* userResponse(yield* applyUser(user, fields));
      }),
    ),
  ),
  HttpRouter.add(
    "DELETE",
    "/scim/v2/Users/:id",
    scimRoute(
      Effect.gen(function* () {
        yield* applyUser(yield* findUser, { active: false });
        return HttpServerResponse.empty({ status: 204 });
      }),
    ),
  ),
);

const groupRoutes = Layer.mergeAll(
  HttpRouter.add(
    "GET",
    "/scim/v2/Groups",
    scimRoute(
      Effect.gen(function* () {
        const config = yield* ControlPlaneConfig;
        const store = yield* Store;
        const params = searchParams(yield* HttpServerRequest.HttpServerRequest);
        const filter = yield* parseFilter(params.get("filter"), ["displayName", "externalId"]);
        const groups = (yield* store.listGroups).filter(
          (group) =>
            filter === undefined ||
            (filter.attribute === "displayName"
              ? group.displayName === filter.value
              : group.externalId === filter.value),
        );
        const emails = new Map((yield* store.listUsers).map((user) => [user.id, user.email]));
        // Okta pages groups without members when asked to; members are cheap here, so always send them.
        return page(groups, params, (group) => toScimGroup(config.publicUrl, group, emails));
      }),
    ),
  ),
  HttpRouter.add(
    "POST",
    "/scim/v2/Groups",
    scimRoute(
      Effect.gen(function* () {
        const store = yield* Store;
        const plane = yield* ControlPlane;
        const body = yield* readJson(Resource);
        const displayName = body["displayName"];
        if (typeof displayName !== "string" || displayName.length === 0) {
          return yield* fail(400, "displayName is required", "invalidValue");
        }
        if ((yield* store.groupByName(displayName)) !== undefined) {
          return yield* fail(409, "displayName is taken", "uniqueness");
        }
        const id = yield* Crypto.uuid;
        yield* store.createGroup({
          id,
          displayName,
          externalId: typeof body["externalId"] === "string" ? body["externalId"] : null,
        });
        const members = memberIds(body["members"]);
        yield* store.setGroupMembers(id, members);
        yield* plane.applyGroupRoles(members);
        yield* plane.recordAdminEvent(SCIM_ACTOR, "group.provisioned", {
          groupId: id,
          displayName,
        });
        return yield* groupResponse(id, 201);
      }),
    ),
  ),
  HttpRouter.add(
    "GET",
    "/scim/v2/Groups/:id",
    scimRoute(Effect.flatMap(findGroup, (group) => groupResponse(group.id))),
  ),
  HttpRouter.add(
    "PUT",
    "/scim/v2/Groups/:id",
    scimRoute(
      Effect.gen(function* () {
        const group = yield* findGroup;
        const body = yield* readJson(Resource);
        yield* changeGroup(group, {
          ...(typeof body["displayName"] === "string" ? { displayName: body["displayName"] } : {}),
          set: memberIds(body["members"]),
        });
        return yield* groupResponse(group.id);
      }),
    ),
  ),
  HttpRouter.add(
    "PATCH",
    "/scim/v2/Groups/:id",
    scimRoute(
      Effect.gen(function* () {
        const group = yield* findGroup;
        yield* groupPatch(group, yield* readPatchOperations);
        return yield* groupResponse(group.id);
      }),
    ),
  ),
  HttpRouter.add(
    "DELETE",
    "/scim/v2/Groups/:id",
    scimRoute(
      Effect.gen(function* () {
        const group = yield* findGroup;
        const store = yield* Store;
        yield* store.deleteGroup(group.id);
        yield* (yield* ControlPlane).applyGroupRoles(group.members);
        yield* (yield* ControlPlane).recordAdminEvent(SCIM_ACTOR, "group.deleted", {
          groupId: group.id,
          displayName: group.displayName,
        });
        return HttpServerResponse.empty({ status: 204 });
      }),
    ),
  ),
);

export const layer = Layer.mergeAll(userRoutes, groupRoutes);
