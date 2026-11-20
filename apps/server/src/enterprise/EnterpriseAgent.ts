/**
 * EnterpriseAgent - keeps an enterprise machine connected to its organization: renews the
 * device's model lease, refreshes the signed policy, and runs the loopback proxy that provider
 * CLIs use in place of their vendors' APIs. On an unmanaged machine it does nothing.
 *
 * @module EnterpriseAgent
 */
import type { AuditEvent, LeaseResponse } from "@t3tools/enterprise-protocol/wire";
import { paths as wirePaths } from "@t3tools/enterprise-protocol/wire";
import * as HostProcess from "@t3tools/shared/HostProcess";
import * as Clock from "effect/Clock";
import * as Context from "effect/Context";
import * as DateTime from "effect/DateTime";
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";

import * as EnterpriseConfig from "./EnterpriseConfig.ts";
import * as EnterpriseDevice from "./EnterpriseDevice.ts";
import * as EnterprisePolicy from "./EnterprisePolicy.ts";
import * as Transport from "./enterpriseTransport.ts";

export class EnterpriseRequestError extends Schema.TaggedError<EnterpriseRequestError>()(
  "EnterpriseRequestError",
  { url: Schema.String, cause: Schema.Defect() },
) {
  override get message(): string {
    return `Cannot reach ${this.url}.`;
  }
}

export interface EnterpriseStatus {
  readonly organization: string;
  readonly controlPlaneUrl: string;
  readonly gatewayUrl: string;
  readonly enrolled: boolean;
  readonly email: string | null;
  readonly deviceId: string | null;
  readonly certificateExpiresAt: string | null;
  readonly lease: {
    readonly active: boolean;
    readonly expiresAt: string | null;
    readonly problem: string | null;
  };
  readonly policy: {
    readonly loadedVersion: number | null;
    readonly availableVersion: number | null;
    readonly restartRequired: boolean;
  };
  readonly whenUnreachable: "use-cached-until-expiry" | "deny";
  readonly updatedAt: string;
}

export class EnterpriseAgent extends Context.Service<
  EnterpriseAgent,
  {
    /** Undefined on a machine without an enterprise config. */
    readonly config: EnterpriseConfig.LoadedEnterpriseConfig | undefined;
    readonly status: Effect.Effect<EnterpriseStatus | undefined>;
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

const unmanaged = EnterpriseAgent.of({
  config: undefined,
  status: Effect.undefined,
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
  } = { identity: undefined, lease: undefined, problem: null, availableVersion: null };

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
      whenUnreachable,
      updatedAt: DateTime.formatIso(DateTime.makeUnsafe(now)),
    } satisfies EnterpriseStatus;
  });

  const writeStatus = status.pipe(
    Effect.flatMap((snapshot) =>
      EnterpriseDevice.writeTextAtomically(paths.status, `${JSON.stringify(snapshot, null, 2)}\n`),
    ),
    Effect.ignore,
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

  const sendAudit = Effect.fn("EnterpriseAgent.sendAudit")(function* (
    events: ReadonlyArray<AuditEvent>,
  ) {
    const reply = yield* deviceCall(wirePaths.audit, { method: "POST", body: { events } });
    return Option.isSome(reply) && reply.value.status === 200;
  });

  return EnterpriseAgent.of({ config: loaded, status, sendAudit });
});

export const layer = Layer.effect(EnterpriseAgent, make);
