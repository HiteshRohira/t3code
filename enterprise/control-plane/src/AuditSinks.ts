/**
 * AuditSinks - copies stored audit events to SIEM sinks. The database stays the source of truth:
 * a sink that misses events can backfill from `GET /v1/admin/audit.jsonl?after=<seq>`.
 *
 * @module AuditSinks
 */
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";
import * as Path from "effect/Path";
import * as Schema from "effect/Schema";
import { HttpClient, HttpClientRequest } from "effect/http";

import { ControlPlaneConfig, type AuditSinkConfig } from "./Config.ts";
import type { StoredAuditEvent } from "./Store.ts";

export type PublishedAuditEvent = StoredAuditEvent & { readonly email: string };

const encodeLine = Schema.encodeEffect(Schema.fromJsonString(Schema.Unknown));

export class AuditSinks extends Context.Service<
  AuditSinks,
  { readonly publish: (events: ReadonlyArray<PublishedAuditEvent>) => Effect.Effect<void> }
>()("@t3tools/enterprise-control-plane/AuditSinks") {}

const make = Effect.gen(function* () {
  const config = yield* ControlPlaneConfig;
  const fs = yield* FileSystem.FileSystem;
  const path = yield* Path.Path;
  const client = (yield* HttpClient.HttpClient).pipe(HttpClient.filterStatusOk);

  return AuditSinks.of({
    publish: Effect.fn("AuditSinks.publish")(function* (events) {
      if (events.length === 0 || config.auditSinks.length === 0) return;
      const lines = yield* Effect.forEach(events, (event) =>
        encodeLine({ source: "t3-enterprise", ...event }),
      ).pipe(Effect.orDie);
      const body = `${lines.join("\n")}\n`;
      const logFailure = (target: string) =>
        Effect.catchCause((cause) => Effect.logWarning("Audit sink failed", { target, cause }));
      const send = (sink: AuditSinkConfig): Effect.Effect<void> =>
        sink.type === "jsonl"
          ? fs
              .makeDirectory(path.dirname(sink.path), { recursive: true })
              .pipe(
                Effect.andThen(fs.writeFileString(sink.path, body, { flag: "a", mode: 0o600 })),
                logFailure(sink.path),
              )
          : HttpClientRequest.post(sink.url).pipe(
              HttpClientRequest.setHeaders(sink.headers),
              HttpClientRequest.bodyText(body, "application/x-ndjson"),
              client.execute,
              Effect.timeout("10 seconds"),
              Effect.asVoid,
              logFailure(sink.url),
            );
      yield* Effect.forEach(config.auditSinks, send, {
        concurrency: "unbounded",
        discard: true,
      });
    }),
  });
});

export const layer = Layer.effect(AuditSinks, make);
