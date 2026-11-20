/**
 * EnterpriseAudit - ships what agents did (turns started, commands run, files changed, approvals,
 * pull requests) from the event store to the control plane. The cursor advances only after the
 * control plane accepts a batch, and event ids are stable, so an outage resends instead of losing.
 *
 * @module EnterpriseAudit
 */
import type { OrchestrationV2StoredEvent } from "@t3tools/contracts";
import type { AuditEvent } from "@t3tools/enterprise-protocol/wire";
import * as DateTime from "effect/DateTime";
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Schedule from "effect/Schedule";
import * as Schema from "effect/Schema";
import * as Stream from "effect/Stream";

import * as EventSink from "../orchestration-v2/EventSink.ts";
import * as EnterpriseAgent from "./EnterpriseAgent.ts";
import * as EnterpriseDevice from "./EnterpriseDevice.ts";

const MAX_COMMAND_CHARS = 4000;
const truncate = (text: string) =>
  text.length <= MAX_COMMAND_CHARS ? text : `${text.slice(0, MAX_COMMAND_CHARS)}…`;
const iso = (value: DateTime.Utc) => DateTime.formatIso(value);

/** The audit record for one stored event, or none for events the audit trail does not keep. */
function toAuditEvent(stored: OrchestrationV2StoredEvent): AuditEvent | undefined {
  const { event } = stored;
  const base = {
    occurredAt: iso(event.occurredAt),
    threadId: event.threadId,
    ...(event.providerInstanceId === undefined ? {} : { provider: event.providerInstanceId }),
  };
  switch (event.type) {
    case "thread.created":
      return {
        ...base,
        id: event.id,
        type: "thread.created",
        projectId: event.payload.projectId,
        provider: event.payload.providerInstanceId,
        runtimeMode: event.payload.runtimeMode,
        detail: { title: event.payload.title, model: event.payload.modelSelection.model },
      };
    case "run.created":
      return {
        ...base,
        id: event.id,
        type: "turn.started",
        provider: event.payload.providerInstanceId,
        detail: { runId: event.payload.id, model: event.payload.modelSelection.model },
      };
    case "runtime-request.updated":
      if (event.payload.status !== "resolved") return undefined;
      return {
        ...base,
        // Ids name the request, not the event, so repeated updates are stored once.
        id: `approval:${event.payload.id}`,
        type: "approval.resolved",
        detail: { kind: event.payload.kind, decision: event.payload.decision ?? null },
      };
    case "turn-item.updated": {
      const item = event.payload;
      const finished = item.status === "completed" || item.status === "failed";
      if (!finished) return undefined;
      if (item.type === "command_execution") {
        return {
          ...base,
          id: `command:${item.id}`,
          type: "command.executed",
          detail: {
            command: truncate(item.input),
            status: item.status,
            ...(item.exitCode === undefined ? {} : { exitCode: item.exitCode }),
          },
        };
      }
      if (item.type === "file_change") {
        return {
          ...base,
          id: `file:${item.id}`,
          type: "file.changed",
          detail: {
            fileName: item.fileName,
            status: item.status,
            ...(item.additions === undefined ? {} : { additions: item.additions }),
            ...(item.deletions === undefined ? {} : { deletions: item.deletions }),
            ...(item.changes === undefined
              ? {}
              : { changes: item.changes.map(({ operation, path }) => ({ operation, path })) }),
          },
        };
      }
      return undefined;
    }
    case "thread.pull-request-link-updated":
      return {
        ...base,
        id: `pull-request:${event.threadId}:${event.payload.url}`,
        type: "pull_request.linked",
        detail: { url: event.payload.url, source: event.payload.source },
      };
    default:
      return undefined;
  }
}

class EnterpriseAuditRejected extends Schema.TaggedError<EnterpriseAuditRejected>()(
  "EnterpriseAuditRejected",
  {},
) {
  override get message(): string {
    return "The control plane did not accept the audit batch.";
  }
}

const BATCH_SIZE = 200;
const BATCH_WINDOW = Duration.seconds(5);

const make = Effect.gen(function* () {
  const agent = yield* EnterpriseAgent.EnterpriseAgent;
  if (agent.config === undefined) return;
  const eventSink = yield* EventSink.EventSinkV2;
  const paths = yield* EnterpriseDevice.statePaths;

  const saved = yield* EnterpriseDevice.readText(paths.auditCursor);
  const parsed = Option.flatMap(saved, (text) => {
    const value = Number.parseInt(text.trim(), 10);
    return Number.isSafeInteger(value) && value >= 0 ? Option.some(value) : Option.none();
  });
  // A first start audits from now on; history from before enrollment is not the org's to collect.
  const cursor = Option.isSome(parsed)
    ? parsed.value
    : yield* eventSink.latestSequence().pipe(Effect.orElseSucceed(() => 0));

  const ship = Effect.fn("EnterpriseAudit.ship")(
    function* (batch: ReadonlyArray<{ sequence: number; audit: AuditEvent | undefined }>) {
      const last = batch.at(-1);
      if (last === undefined) return;
      const events = batch.flatMap(({ audit }) => (audit === undefined ? [] : [audit]));
      if (events.length > 0) {
        const accepted = yield* agent.sendAudit(events);
        if (!accepted) return yield* new EnterpriseAuditRejected();
      }
      yield* EnterpriseDevice.writeTextAtomically(paths.auditCursor, `${last.sequence}\n`);
    },
    Effect.retry(
      Schedule.min([
        Schedule.exponential(Duration.seconds(5)),
        Schedule.spaced(Duration.minutes(5)),
      ]),
    ),
  );

  yield* eventSink.stream({ afterSequence: cursor }).pipe(
    Stream.map((stored) => ({ sequence: stored.sequence, audit: toAuditEvent(stored) })),
    Stream.groupedWithin(BATCH_SIZE, BATCH_WINDOW),
    Stream.runForEach(ship),
    Effect.catch((error) => Effect.logError("Enterprise audit stream stopped.", { error })),
    Effect.forkScoped,
  );
});

export const layer = Layer.effectDiscard(make);
