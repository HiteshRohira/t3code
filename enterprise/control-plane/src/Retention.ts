/**
 * Retention - deletes audit, usage, and lease rows older than the configured windows, once at
 * start and then daily. Users on legal hold keep everything.
 *
 * @module Retention
 */
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Schedule from "effect/Schedule";

import { ControlPlaneConfig } from "./Config.ts";
import { Store } from "./Store.ts";

const cutoff = (now: DateTime.Utc, days: number | undefined) =>
  days === undefined ? undefined : DateTime.formatIso(DateTime.subtract(now, { days }));

export const purgeOnce = Effect.gen(function* () {
  const config = yield* ControlPlaneConfig;
  const store = yield* Store;
  const now = yield* DateTime.now;
  const audit = cutoff(now, config.retention.auditDays);
  const usage = cutoff(now, config.retention.usageDays);
  const leases = cutoff(now, config.retention.leaseDays);
  const deleted = yield* store.purge({
    ...(audit === undefined ? {} : { audit }),
    ...(usage === undefined ? {} : { usage }),
    ...(leases === undefined ? {} : { leases }),
  });
  if (deleted > 0) yield* Effect.logInfo("Retention removed expired rows", { deleted });
  return deleted;
}).pipe(Effect.withSpan("Retention.purge"));

export const layer = Layer.effectDiscard(
  purgeOnce.pipe(
    Effect.catchCause((cause) => Effect.logWarning("Retention purge failed", { cause })),
    Effect.repeat(Schedule.spaced("1 day")),
    Effect.forkScoped,
  ),
);
