/**
 * EnterpriseAgent - keeps an enterprise machine connected to its organization: renews the
 * device's model lease, refreshes the signed policy, and runs the loopback proxy that provider
 * CLIs use in place of their vendors' APIs. On an unmanaged machine it does nothing.
 *
 * @module EnterpriseAgent
 */
import { EnterpriseActionError, type EnterpriseStatus } from "@t3tools/contracts";
import type { AuditEvent, LeaseResponse } from "@t3tools/enterprise-protocol/wire";
import { paths as wirePaths } from "@t3tools/enterprise-protocol/wire";
import * as HostProcess from "@t3tools/shared/HostProcess";
import * as Clock from "effect/Clock";
import * as Context from "effect/Context";
import * as DateTime from "effect/DateTime";
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";
import * as Path from "effect/Path";
import * as Scope from "effect/Scope";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import * as Stream from "effect/Stream";
import * as SubscriptionRef from "effect/SubscriptionRef";
import * as Deferred from "effect/Deferred";

import * as EnterpriseConfig from "./EnterpriseConfig.ts";
import * as EnterpriseDevice from "./EnterpriseDevice.ts";
import * as EnterpriseEnrollment from "./EnterpriseEnrollment.ts";
import * as EnterprisePolicy from "./EnterprisePolicy.ts";
import * as Transport from "./enterpriseTransport.ts";
import { pullRequestShim } from "./pullRequestShim.ts";
import * as ServerConfig from "../config.ts";
import packageJson from "../../package.json" with { type: "json" };

export class EnterpriseRequestError extends Schema.TaggedError<EnterpriseRequestError>()(
  "EnterpriseRequestError",
  { url: Schema.String, cause: Schema.Defect() },
) {
  override get message(): string {
    return `Cannot reach ${this.url}.`;
  }
}

export class EnterpriseAgent extends Context.Service<
  EnterpriseAgent,
  {
    /** Undefined on a machine without an enterprise config. */
    readonly config: EnterpriseConfig.LoadedEnterpriseConfig | undefined;
    readonly status: Effect.Effect<EnterpriseStatus | undefined>;
    /** The current status, then every change. */
    readonly statusChanges: Stream.Stream<EnterpriseStatus | null>;
    /** Exits so the supervising desktop app starts the server again with the new policy. */
    readonly restart: Effect.Effect<void, EnterpriseActionError>;
    /** Starts enrollment and returns the sign-in link; status reports how it ends. */
    readonly enroll: Effect.Effect<{ readonly signInUrl: string }, EnterpriseActionError>;
    /** A JSON request to the control plane as this device; none while it is not enrolled. */
    readonly call: (
      path: string,
      options?: { readonly method?: string; readonly body?: unknown },
    ) => Effect.Effect<Option.Option<Transport.JsonReply>, EnterpriseRequestError>;
    /** Tracks runs for the fleet heartbeat; terminal statuses remove the run. */
    readonly noteRun: (runId: string, active: boolean) => Effect.Effect<void>;
    /** Sends audit events; fails while the device cannot reach the control plane. */
    readonly sendAudit: (
      events: ReadonlyArray<AuditEvent>,
    ) => Effect.Effect<boolean, EnterpriseRequestError>;
  }
>()("t3/enterprise/EnterpriseAgent") {}

export const request = Effect.fn("EnterpriseAgent.request")(function* (
  url: string,
  options: Omit<Parameters<typeof Transport.requestJson>[1], "timeoutMs">,
) {
  return yield* Effect.tryPromise({
    try: () => Transport.requestJson(url, options),
    catch: (cause) => new EnterpriseRequestError({ url, cause }),
  });
});

const errorMessage = (body: unknown, fallback: string) => {
  if (typeof body === "object" && body !== null) {
    const message = (body as Record<string, unknown>)["message"];
    if (typeof message === "string") return message;
  }
  return fallback;
};

/** What provider CLIs see: the local proxy as their API, and its token as their key. */
const providerEnvironment = (port: number, token: string) => ({
  ANTHROPIC_BASE_URL: `http://127.0.0.1:${port}/anthropic`,
  ANTHROPIC_API_KEY: token,
  OPENAI_BASE_URL: `http://127.0.0.1:${port}/openai/v1`,
  OPENAI_API_KEY: token,
  T3E_CODEX_GATEWAY_URL: `http://127.0.0.1:${port}/openai/v1`,
});

/** Credentials that would send a provider somewhere other than the gateway. */
const BYPASS_VARIABLES = [
  "ANTHROPIC_AUTH_TOKEN",
  "CLAUDE_CODE_OAUTH_TOKEN",
  "CLAUDE_CODE_USE_BEDROCK",
  "CLAUDE_CODE_USE_VERTEX",
  "AWS_BEARER_TOKEN_BEDROCK",
  "OPENAI_ORG_ID",
];

const notManaged = new EnterpriseActionError({
  message: "This computer is not managed by an organization.",
});

const unmanaged = EnterpriseAgent.of({
  config: undefined,
  status: Effect.undefined,
  statusChanges: Stream.make(null),
  restart: Effect.fail(notManaged),
  enroll: Effect.fail(notManaged),
  call: Effect.fn("EnterpriseAgent.call.unmanaged")(() => Effect.succeedNone),
  noteRun: Effect.fn("EnterpriseAgent.noteRun.unmanaged")(() => Effect.void),
  sendAudit: Effect.fn("EnterpriseAgent.sendAudit.unmanaged")(function* () {
    return yield* Effect.succeed(false);
  }),
});

const make = Effect.gen(function* () {
  const loaded = yield* EnterpriseConfig.readEnterpriseConfig.pipe(
    // The policy layer already refused a broken config; here it only decides whether to run.
    Effect.orElseSucceed(() => undefined),
  );
  if (loaded === undefined) return unmanaged;
  const config = loaded.document;
  const paths = yield* EnterpriseDevice.statePaths;
  const whenUnreachable = config.whenUnreachable ?? "use-cached-until-expiry";
  const serverCa = config.serverCaPem === undefined ? {} : { serverCaPem: config.serverCaPem };
  const loadedPolicy = yield* EnterprisePolicy.resolve(config, loaded.path);

  // Read by the proxy's request callback, which runs outside Effect; the loops below own writes.
  const state: {
    identity: EnterpriseDevice.DeviceIdentity | undefined;
    lease: { token: string; expiresAt: number } | undefined;
    problem: string | null;
    availableVersion: number | null;
    enrollment: { signInUrl: string; error: string | null } | null;
  } = {
    identity: undefined,
    lease: undefined,
    problem: null,
    availableVersion: null,
    enrollment: null,
  };
  const serverMode = (yield* ServerConfig.ServerConfig).mode;
  // Only the desktop app supervises its server and starts it again after it exits.
  const restartMode = serverMode === "desktop" ? ("self" as const) : ("manual" as const);

  const credentials = (): Transport.ProxyCredentials => {
    if (state.identity === undefined) {
      return {
        ok: false,
        status: 401,
        message: `This computer is not enrolled with ${config.organization}. Run \`t3 enterprise enroll\`, then try again.`,
      };
    }
    // @effect-diagnostics-next-line globalDate:off -- runs in the proxy's node callback.
    if (state.lease === undefined || state.lease.expiresAt <= Date.now()) {
      return {
        ok: false,
        status: 403,
        message:
          state.problem ??
          `No model access from ${config.organization} right now. Reconnect to your organization's network, then try again.`,
      };
    }
    return {
      ok: true,
      lease: state.lease.token,
      keyPem: state.identity.keyPem,
      certificatePem: state.identity.certificatePem,
    };
  };

  const token = Transport.randomToken();
  const proxy = yield* Effect.acquireRelease(
    Effect.promise(() =>
      Transport.startLocalProxy({ token, gatewayUrl: config.gatewayUrl, credentials, ...serverCa }),
    ),
    (running) => Effect.promise(() => running.close()),
  );
  // Every provider process and terminal inherits the server's environment, so pointing it at the
  // proxy covers every provider adapter without touching them.
  const environment = yield* HostProcess.Environment;
  for (const name of BYPASS_VARIABLES) delete environment[name];
  Object.assign(environment, providerEnvironment(proxy.port, token));
  const pullRequests = loadedPolicy.document.limits?.agentPullRequests ?? "allowed";
  if (pullRequests !== "allowed" && (yield* HostProcess.Platform) !== "win32") {
    const fs = yield* FileSystem.FileSystem;
    const path = yield* Path.Path;
    const bin = path.join(paths.dir, "bin");
    yield* fs.makeDirectory(bin, { recursive: true });
    yield* EnterpriseDevice.writeTextAtomically(
      path.join(bin, "gh"),
      pullRequestShim(config.organization),
    );
    yield* fs.chmod(path.join(bin, "gh"), 0o755);
    // The shim is POSIX-only, so the separator is always ":".
    environment["PATH"] = `${bin}:${environment["PATH"] ?? ""}`;
    environment["T3E_AGENT_PULL_REQUESTS"] = pullRequests;
  }
  yield* Effect.logInfo("Enterprise model proxy is ready.", {
    organization: config.organization,
    port: proxy.port,
  });

  const status = Effect.gen(function* () {
    const now = yield* Clock.currentTimeMillis;
    const active = state.lease !== undefined && state.lease.expiresAt > now;
    return {
      organization: config.organization,
      controlPlaneUrl: config.controlPlaneUrl,
      gatewayUrl: config.gatewayUrl,
      supportUrl: config.supportUrl ?? null,
      enrolled: state.identity !== undefined,
      email: state.identity?.record.email ?? null,
      deviceId: state.identity?.record.deviceId ?? null,
      certificateExpiresAt: state.identity?.record.expiresAt ?? null,
      lease: {
        active,
        expiresAt:
          state.lease === undefined
            ? null
            : DateTime.formatIso(DateTime.makeUnsafe(state.lease.expiresAt)),
        problem: active ? null : state.problem,
      },
      policy: {
        loadedVersion: loadedPolicy.version ?? null,
        availableVersion: state.availableVersion,
        restartRequired:
          state.availableVersion !== null && state.availableVersion !== loadedPolicy.version,
      },
      restart: restartMode,
      enrollment: state.enrollment,
      whenUnreachable,
      updatedAt: DateTime.formatIso(DateTime.makeUnsafe(now)),
    } satisfies EnterpriseStatus;
  });

  const current = yield* SubscriptionRef.make<EnterpriseStatus>(yield* status);
  // Clients compare whole snapshots, so a tick that changed nothing but the clock is not sent.
  const publish = Effect.flatMap(status, (snapshot) =>
    SubscriptionRef.update(current, (previous) =>
      JSON.stringify({ ...previous, updatedAt: "" }) ===
      JSON.stringify({ ...snapshot, updatedAt: "" })
        ? previous
        : snapshot,
    ),
  );
  const writeStatus = status.pipe(
    Effect.flatMap((snapshot) =>
      EnterpriseDevice.writeTextAtomically(paths.status, `${JSON.stringify(snapshot, null, 2)}\n`),
    ),
    Effect.ignore,
    Effect.andThen(publish),
  );

  const deviceCall = Effect.fn("EnterpriseAgent.deviceCall")(function* (
    path: string,
    options: { method?: string; body?: unknown } = {},
  ) {
    const identity = state.identity;
    if (identity === undefined) return Option.none<Transport.JsonReply>();
    const reply = yield* request(`${config.controlPlaneUrl}${path}`, {
      ...options,
      credentials: {
        keyPem: identity.keyPem,
        certificatePem: identity.certificatePem,
        ...serverCa,
      },
    });
    return Option.some(reply);
  });

  const refreshIdentity = EnterpriseDevice.readIdentity(paths, config.controlPlaneUrl).pipe(
    Effect.tap((identity) =>
      Effect.sync(() => {
        state.identity = Option.getOrUndefined(identity);
      }),
    ),
  );

  /** Renews the lease and says how long to wait before the next attempt. */
  const renewLease = Effect.gen(function* () {
    yield* refreshIdentity;
    if (state.identity === undefined) {
      state.lease = undefined;
      state.problem = null;
      return Duration.seconds(30);
    }
    const reply = yield* deviceCall(wirePaths.lease, { method: "POST" }).pipe(Effect.result);
    const now = yield* Clock.currentTimeMillis;
    if (reply._tag === "Failure") {
      if (whenUnreachable === "deny") state.lease = undefined;
      state.problem = `Cannot reach ${config.organization}'s control plane. Model access continues until the current lease expires${whenUnreachable === "deny" ? " (this organization stops it immediately)" : ""}.`;
      yield* Effect.logWarning("Enterprise lease renewal failed.", {
        error: reply.failure.message,
      });
      return Duration.seconds(30);
    }
    if (Option.isNone(reply.success)) return Duration.seconds(30);
    const { status: code, body } = reply.success.value;
    if (code === 200) {
      const lease = body as LeaseResponse;
      const expiresAt = Date.parse(lease.expiresAt);
      state.lease = { token: lease.lease, expiresAt };
      state.problem = null;
      return Duration.millis(Math.max(60_000, (expiresAt - now) / 2));
    }
    state.lease = undefined;
    state.problem = `${config.organization} refused model access: ${errorMessage(body, `status ${code}`)}.`;
    yield* Effect.logWarning("Enterprise lease refused.", { status: code });
    return Duration.minutes(5);
  });

  const refreshPolicy = Effect.gen(function* () {
    const reply = yield* deviceCall(wirePaths.policy);
    if (Option.isNone(reply) || reply.value.status !== 200) return;
    const token = (reply.value.body as { policy?: unknown }).policy;
    if (typeof token !== "string") return;
    const verified = yield* EnterprisePolicy.verifyPolicyToken(config, token);
    yield* EnterpriseDevice.writeTextAtomically(paths.policy, `${token}\n`);
    if (state.availableVersion !== verified.version && verified.version !== loadedPolicy.version) {
      yield* Effect.logInfo("A new enterprise policy is ready; it applies when T3 Code restarts.", {
        version: verified.version,
      });
    }
    state.availableVersion = verified.version;
  }).pipe(
    Effect.catch((error) =>
      Effect.logWarning("Enterprise policy refresh failed.", { error: error.message }),
    ),
  );

  yield* renewLease.pipe(
    Effect.tap(() => writeStatus),
    Effect.flatMap((delay) => Effect.sleep(delay)),
    Effect.forever,
    Effect.forkScoped,
  );
  yield* refreshPolicy.pipe(
    Effect.tap(() => writeStatus),
    Effect.andThen(Effect.sleep(Duration.seconds(config.policyRefreshSeconds ?? 900))),
    Effect.forever,
    Effect.forkScoped,
  );

  const activeRuns = new Set<string>();
  const hostname = yield* HostProcess.Hostname;
  const platform = yield* HostProcess.Platform;
  const heartbeat = Effect.gen(function* () {
    const snapshot = yield* status;
    yield* deviceCall(wirePaths.heartbeat, {
      method: "POST",
      body: {
        clientVersion: packageJson.version,
        platform,
        hostname: hostname.slice(0, 255),
        policyVersion: snapshot.policy.loadedVersion,
        restartRequired: snapshot.policy.restartRequired,
        activeTurns: activeRuns.size,
        modelAccess: snapshot.lease.active
          ? "ok"
          : !snapshot.enrolled
            ? "pending"
            : snapshot.lease.problem?.startsWith("Cannot reach") === true
              ? "unreachable"
              : "denied",
      },
    });
  }).pipe(
    Effect.catch((error) =>
      Effect.logDebug("Enterprise heartbeat failed.", { error: error.message }),
    ),
    Effect.withSpan("EnterpriseAgent.heartbeat"),
  );
  yield* heartbeat.pipe(
    Effect.delay(Duration.seconds(5)),
    Effect.andThen(Effect.sleep(Duration.minutes(5))),
    Effect.forever,
    Effect.forkScoped,
  );

  const sendAudit = Effect.fn("EnterpriseAgent.sendAudit")(function* (
    events: ReadonlyArray<AuditEvent>,
  ) {
    const reply = yield* deviceCall(wirePaths.audit, { method: "POST", body: { events } });
    if (Option.isNone(reply) || reply.value.status !== 200) return false;
    const rejected = (reply.value.body as { rejected?: unknown } | null)?.rejected;
    if (typeof rejected === "number" && rejected > 0) {
      yield* Effect.logWarning("The control plane rejected audit events.", { rejected });
    }
    return true;
  });

  const restart = Effect.gen(function* () {
    if (restartMode === "manual") {
      return yield* new EnterpriseActionError({
        message: "Restart T3 Code where it runs to apply the new policy.",
      });
    }
    yield* Effect.logInfo("Restarting to apply the organization's policy.");
    // The desktop app starts its server again whenever it exits; SIGTERM runs every finalizer.
    yield* Effect.sync(() => process.kill(process.pid, "SIGTERM")).pipe(
      Effect.delay(Duration.millis(250)),
      Effect.forkDetach,
    );
  }).pipe(Effect.withSpan("EnterpriseAgent.restart"));

  const enrollmentRunning = yield* SubscriptionRef.make(false);
  const enrollContext = yield* Effect.context<FileSystem.FileSystem | Path.Path>();
  const scope = yield* Scope.Scope;
  const enroll = Effect.gen(function* () {
    if (yield* SubscriptionRef.getAndSet(enrollmentRunning, true)) {
      if (state.enrollment !== null) return { signInUrl: state.enrollment.signInUrl };
    }
    const signInUrl = yield* Deferred.make<string>();
    yield* EnterpriseEnrollment.enroll(config, {
      clientVersion: packageJson.version,
      showSignInUrl: (url) =>
        Effect.sync(() => {
          state.enrollment = { signInUrl: url, error: null };
        }).pipe(Effect.andThen(publish), Effect.andThen(Deferred.succeed(signInUrl, url))),
    }).pipe(
      Effect.tap(() =>
        Effect.sync(() => {
          state.enrollment = null;
        }),
      ),
      Effect.andThen(renewLease),
      Effect.andThen(refreshPolicy),
      Effect.catch((error) =>
        Effect.sync(() => {
          state.enrollment = {
            signInUrl: state.enrollment?.signInUrl ?? "",
            error: error.message,
          };
        }),
      ),
      Effect.ensuring(
        SubscriptionRef.set(enrollmentRunning, false).pipe(Effect.andThen(writeStatus)),
      ),
      Effect.provide(enrollContext),
      Effect.forkIn(scope),
    );
    return { signInUrl: yield* Deferred.await(signInUrl) };
  }).pipe(Effect.withSpan("EnterpriseAgent.enroll"));

  return EnterpriseAgent.of({
    config: loaded,
    status,
    statusChanges: SubscriptionRef.changes(current),
    restart,
    enroll,
    call: deviceCall,
    noteRun: Effect.fn("EnterpriseAgent.noteRun")((runId: string, active: boolean) =>
      Effect.sync(() => {
        if (active) activeRuns.add(runId);
        else activeRuns.delete(runId);
      }),
    ),
    sendAudit,
  });
});

export const layer = Layer.effect(EnterpriseAgent, make);
