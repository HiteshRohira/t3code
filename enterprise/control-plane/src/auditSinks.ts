// Copies stored audit events to SIEM sinks. The database stays the source of truth: a sink that
// misses events can backfill from `GET /v1/admin/audit?after=<seq>`.
import * as NodeFSP from "node:fs/promises";
import * as NodePath from "node:path";

import type { AuditSinkConfig } from "./config.ts";
import type { StoredAuditEvent } from "./store.ts";

export type PublishedAuditEvent = StoredAuditEvent & { readonly email: string };

export class AuditFanout {
  readonly #sinks: ReadonlyArray<AuditSinkConfig>;
  readonly #fetch: typeof fetch;

  constructor(sinks: ReadonlyArray<AuditSinkConfig>, fetchImpl: typeof fetch) {
    this.#sinks = sinks;
    this.#fetch = fetchImpl;
  }

  async publish(events: ReadonlyArray<PublishedAuditEvent>) {
    if (events.length === 0) return;
    const lines = events
      .map((event) => JSON.stringify({ source: "t3-enterprise", ...event }))
      .join("\n");
    await Promise.all(
      this.#sinks.map(async (sink) => {
        try {
          if (sink.type === "jsonl") {
            await NodeFSP.mkdir(NodePath.dirname(sink.path), { recursive: true });
            await NodeFSP.appendFile(sink.path, `${lines}\n`, { mode: 0o600 });
            return;
          }
          const response = await this.#fetch(sink.url, {
            method: "POST",
            headers: { "content-type": "application/x-ndjson", ...sink.headers },
            body: `${lines}\n`,
            signal: AbortSignal.timeout(10_000),
          });
          if (!response.ok)
            console.warn(`[control-plane] audit sink ${sink.url} answered ${response.status}`);
        } catch (error) {
          console.warn(`[control-plane] audit sink ${sink.type} failed`, error);
        }
      }),
    );
  }
}
