/**
 * TeamRoutes - what enrolled machines share: the organization's library (skills, prompts,
 * instructions, MCP servers) and threads handed between colleagues, plus the admin side of both
 * and the activity feed leads watch.
 *
 * @module TeamRoutes
 */
import { LibraryItemInput, paths, SharedThreadInput } from "@t3tools/enterprise-protocol/wire";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Schema from "effect/Schema";
import { HttpRouter, HttpServerRequest } from "effect/http";

import { authorize } from "./AdminRoutes.ts";
import { ControlPlane, Refusal } from "./ControlPlane.ts";
import * as Crypto from "./Crypto.ts";
import { clientCertificate, json, readJson, respond, searchParams } from "./Http.ts";
import { Store } from "./Store.ts";

/** What Claude Code and Codex both accept for one server: a command, or a URL. */
const McpServerEntry = Schema.Union([
  Schema.Struct({
    command: Schema.NonEmptyString,
    args: Schema.optional(Schema.Array(Schema.String)),
    env: Schema.optional(Schema.Record(Schema.String, Schema.String)),
  }),
  Schema.Struct({ url: Schema.NonEmptyString }),
]);
const decodeMcpServer = Schema.decodeUnknownEffect(Schema.fromJsonString(McpServerEntry));

const refuse = (status: number, code: string, reason: string) =>
  Effect.fail(new Refusal({ status, code, reason }));

const param = (name: string) =>
  Effect.map(HttpRouter.params, (params) => decodeURIComponent(params[name] ?? ""));

const device = Effect.gen(function* () {
  const request = yield* HttpServerRequest.HttpServerRequest;
  return yield* (yield* ControlPlane).authenticateDevice(clientCertificate(request));
});

const deviceRoutes = Layer.mergeAll(
  HttpRouter.add(
    "GET",
    paths.library,
    respond(
      Effect.gen(function* () {
        const { user } = yield* device;
        return json({ items: yield* (yield* Store).libraryFor(user.team) });
      }),
    ),
  ),
  HttpRouter.add(
    "POST",
    paths.sharedThreads,
    respond(
      Effect.gen(function* () {
        const { user } = yield* device;
        const input = yield* readJson(SharedThreadInput, 8 * 1024 * 1024);
        if (input.audience === "team" && user.team === null) {
          return yield* refuse(
            400,
            "no_team",
            "you are not in a team; share with everyone instead",
          );
        }
        const id = yield* Crypto.uuid;
        yield* (yield* Store).createSharedThread(id, user, input);
        yield* (yield* ControlPlane).recordAdminEvent(user, "thread.shared", {
          sharedThreadId: id,
          title: input.title,
          audience: input.audience,
          repository: input.repository,
        });
        return json({ id }, 201);
      }),
    ),
  ),
  HttpRouter.add(
    "GET",
    paths.sharedThreads,
    respond(
      Effect.gen(function* () {
        const { user } = yield* device;
        return json({ threads: yield* (yield* Store).sharedThreadsFor(user) });
      }),
    ),
  ),
  HttpRouter.add(
    "GET",
    `${paths.sharedThreads}/:id`,
    respond(
      Effect.gen(function* () {
        const { user } = yield* device;
        const store = yield* Store;
        const id = yield* param("id");
        const visible = (yield* store.sharedThreadsFor(user)).some((thread) => thread.id === id);
        const thread = visible ? yield* store.sharedThread(id) : undefined;
        if (thread === undefined) return yield* refuse(404, "not_found", "no such shared thread");
        const { ownerId: _owner, ...shared } = thread;
        yield* (yield* ControlPlane).recordAdminEvent(user, "thread.imported", {
          sharedThreadId: id,
          title: thread.title,
        });
        return json(shared);
      }),
    ),
  ),
);

const adminRoutes = Layer.mergeAll(
  HttpRouter.add(
    "GET",
    "/v1/admin/library",
    respond(
      Effect.gen(function* () {
        yield* authorize("read:directory");
        return json({ items: yield* (yield* Store).listLibrary });
      }),
    ),
  ),
  HttpRouter.add(
    "PUT",
    "/v1/admin/library",
    respond(
      Effect.gen(function* () {
        const actor = yield* authorize("write:library");
        const input = yield* readJson(LibraryItemInput, 512 * 1024);
        if (input.kind === "mcp-server") {
          const parsed = yield* decodeMcpServer(input.content).pipe(Effect.option);
          if (parsed._tag === "None") {
            return yield* refuse(
              400,
              "invalid_request",
              'an MCP server entry is an object such as {"command": "npx", "args": [...]} or {"url": "https://..."}',
            );
          }
        }
        const item = yield* (yield* Store).upsertLibraryItem(
          yield* Crypto.uuid,
          input,
          actor.email,
        );
        yield* (yield* ControlPlane).recordAdminEvent(actor, "library.updated", {
          kind: item.kind,
          name: item.name,
          team: item.team,
        });
        return json({ item });
      }),
    ),
  ),
  HttpRouter.add(
    "DELETE",
    "/v1/admin/library/:id",
    respond(
      Effect.gen(function* () {
        const actor = yield* authorize("write:library");
        const id = yield* param("id");
        yield* (yield* Store).deleteLibraryItem(id);
        yield* (yield* ControlPlane).recordAdminEvent(actor, "library.deleted", { id });
        return json({ deleted: id });
      }),
    ),
  ),
  HttpRouter.add(
    "GET",
    "/v1/admin/shared-threads",
    respond(
      Effect.gen(function* () {
        yield* authorize("watch:team");
        return json({ threads: yield* (yield* Store).sharedThreadsFor(null) });
      }),
    ),
  ),
  HttpRouter.add(
    "DELETE",
    "/v1/admin/shared-threads/:id",
    respond(
      Effect.gen(function* () {
        const actor = yield* authorize("write:library");
        const id = yield* param("id");
        yield* (yield* Store).deleteSharedThread(id);
        yield* (yield* ControlPlane).recordAdminEvent(actor, "thread.unshared", {
          sharedThreadId: id,
        });
        return json({ deleted: id });
      }),
    ),
  ),
  HttpRouter.add(
    "GET",
    "/v1/admin/activity",
    respond(
      Effect.gen(function* () {
        yield* authorize("watch:team");
        const store = yield* Store;
        const params = searchParams(yield* HttpServerRequest.HttpServerRequest);
        const team = params.get("team");
        const users = (yield* store.listUsers).filter(
          (user) => team === null || team === "" || user.team === team,
        );
        const byId = new Map(users.map((user) => [user.id, user]));
        const events =
          users.length === 0
            ? []
            : yield* store.latestAudit({
                userIds: users.map((user) => user.id),
                limit: Math.min(500, Math.max(1, Number(params.get("limit") ?? 100) || 100)),
              });
        return json({
          events: events.map((event) => ({
            ...event,
            email: byId.get(event.userId)?.email ?? null,
            team: byId.get(event.userId)?.team ?? null,
          })),
        });
      }),
    ),
  ),
);

export const layer = Layer.mergeAll(deviceRoutes, adminRoutes);
