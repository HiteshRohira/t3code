/**
 * Config - the gateway's JSON config. Provider keys come from the environment (or a secret
 * manager that sets it), never the file.
 *
 * @module Config
 */
import * as HostProcess from "@t3tools/shared/HostProcess";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Path from "effect/Path";
import * as Schema from "effect/Schema";

import { DETECTORS } from "./Redaction.ts";

export class ConfigError extends Schema.TaggedError<ConfigError>()("ConfigError", {
  reason: Schema.String,
}) {
  override get message(): string {
    return `Gateway config: ${this.reason}`;
  }
}

export type ProviderFamily = "anthropic" | "openai";

export interface Upstream {
  /** Path prefix devices call, such as `/anthropic`. */
  readonly prefix: string;
  readonly family: ProviderFamily;
  readonly baseUrl: string;
  readonly apiKey: string;
  /** Data region this upstream serves; leases bound to a region only use matching upstreams. */
  readonly region: string | undefined;
}

export type RedactionMode = "off" | "redact" | "block";

export interface GatewaySettings {
  readonly listen: { readonly host: string; readonly port: number };
  readonly tls: { readonly certPath: string; readonly keyPath: string };
  /** Org CA that signed device certificates; only its certificates complete a handshake. */
  readonly deviceCaPath: string;
  readonly controlPlaneUrl: string;
  /** Extra CA for the control plane's TLS certificate when it is not publicly trusted. */
  readonly controlPlaneCaPath: string | undefined;
  readonly gatewayToken: string;
  readonly upstreams: ReadonlyArray<Upstream>;
  readonly syncIntervalSeconds: number;
  /** With no fresh control-plane state for this long, the gateway refuses requests. */
  readonly maxStateAgeSeconds: number;
  readonly requestsPerMinute: number | undefined;
  readonly maxRequestBytes: number;
  /** Secrets found in prompts: replaced with a marker, refused, or passed through. */
  readonly redaction: { readonly mode: RedactionMode; readonly detectors: ReadonlyArray<string> };
}

export class GatewayConfig extends Context.Service<GatewayConfig, GatewaySettings>()(
  "@t3tools/enterprise-gateway/Config/GatewayConfig",
) {}

const NonEmpty = Schema.NonEmptyString;
const Positive = Schema.Number.check(Schema.isGreaterThan(0));

const ConfigFile = Schema.Struct({
  listen: Schema.optional(
    Schema.Struct({ host: Schema.optional(NonEmpty), port: Schema.optional(Positive) }),
  ),
  tls: Schema.Struct({ certPath: NonEmpty, keyPath: NonEmpty }),
  deviceCaPath: NonEmpty,
  controlPlaneUrl: NonEmpty,
  controlPlaneCaPath: Schema.optional(NonEmpty),
  upstreams: Schema.Array(
    Schema.Struct({
      family: Schema.Literals(["anthropic", "openai"]),
      prefix: Schema.optional(NonEmpty),
      baseUrl: Schema.optional(NonEmpty),
      apiKeyEnv: NonEmpty,
      region: Schema.optional(NonEmpty),
    }),
  ).check(Schema.isMinLength(1)),
  syncIntervalSeconds: Schema.optional(Positive),
  maxStateAgeSeconds: Schema.optional(Positive),
  requestsPerMinute: Schema.optional(Positive),
  maxRequestBytes: Schema.optional(Positive),
  redaction: Schema.optional(
    Schema.Struct({
      mode: Schema.Literals(["off", "redact", "block"]),
      detectors: Schema.optional(Schema.Array(NonEmpty)),
    }),
  ),
});

const DEFAULT_BASE_URLS: Readonly<Record<ProviderFamily, string>> = {
  anthropic: "https://api.anthropic.com",
  openai: "https://api.openai.com",
};

const decodeFile = Schema.decodeUnknownEffect(ConfigFile, { onExcessProperty: "error" });
const decodeJson = Schema.decodeUnknownEffect(Schema.fromJsonString(Schema.Unknown));

export const parseConfig = Effect.fn("GatewayConfig.parse")(function* (
  raw: unknown,
  options: { baseDir: string; env: Readonly<Record<string, string | undefined>> },
) {
  const path = yield* Path.Path;
  const file = yield* decodeFile(raw).pipe(
    Effect.mapError((cause) => new ConfigError({ reason: cause.message })),
  );
  const at = (value: string) =>
    path.isAbsolute(value) ? value : path.resolve(options.baseDir, value);

  const gatewayToken = options.env["T3E_GATEWAY_TOKEN"];
  if (gatewayToken === undefined || gatewayToken.length < 32) {
    return yield* new ConfigError({
      reason: "set T3E_GATEWAY_TOKEN to the control plane's gateway token",
    });
  }

  const upstreams: Array<Upstream> = [];
  for (const [index, upstream] of file.upstreams.entries()) {
    const apiKey = options.env[upstream.apiKeyEnv];
    if (apiKey === undefined || apiKey.length === 0) {
      return yield* new ConfigError({
        reason: `set ${upstream.apiKeyEnv} for upstreams[${index}]`,
      });
    }
    const prefix = upstream.prefix ?? `/${upstream.family}`;
    if (!/^\/[a-z0-9-]+$/.test(prefix)) {
      return yield* new ConfigError({ reason: `upstreams[${index}].prefix must look like /name` });
    }
    upstreams.push({
      prefix,
      family: upstream.family,
      baseUrl: (upstream.baseUrl ?? DEFAULT_BASE_URLS[upstream.family]).replace(/\/$/, ""),
      apiKey,
      region: upstream.region,
    });
  }
  const routes = new Set(
    upstreams.map((upstream) => `${upstream.prefix}@${upstream.region ?? ""}`),
  );
  if (routes.size !== upstreams.length) {
    return yield* new ConfigError({ reason: "each prefix may appear once per region" });
  }

  const detectors = file.redaction?.detectors ?? DETECTORS.map((detector) => detector.id);
  const unknown = detectors.filter((id) => !DETECTORS.some((detector) => detector.id === id));
  if (unknown.length > 0) {
    return yield* new ConfigError({
      reason: `unknown redaction detectors ${unknown.join(", ")}; known: ${DETECTORS.map((detector) => detector.id).join(", ")}`,
    });
  }

  return {
    listen: { host: file.listen?.host ?? "0.0.0.0", port: file.listen?.port ?? 9443 },
    tls: { certPath: at(file.tls.certPath), keyPath: at(file.tls.keyPath) },
    deviceCaPath: at(file.deviceCaPath),
    controlPlaneUrl: file.controlPlaneUrl.replace(/\/$/, ""),
    controlPlaneCaPath:
      file.controlPlaneCaPath === undefined ? undefined : at(file.controlPlaneCaPath),
    gatewayToken,
    upstreams,
    syncIntervalSeconds: file.syncIntervalSeconds ?? 15,
    maxStateAgeSeconds: file.maxStateAgeSeconds ?? 900,
    requestsPerMinute: file.requestsPerMinute,
    maxRequestBytes: file.maxRequestBytes ?? 32 * 1024 * 1024,
    redaction: { mode: file.redaction?.mode ?? "redact", detectors },
  } satisfies GatewaySettings;
});

export const loadConfig = Effect.fn("GatewayConfig.load")(function* (file: string) {
  const fs = yield* FileSystem.FileSystem;
  const path = yield* Path.Path;
  const absolute = path.resolve(file);
  const text = yield* fs
    .readFileString(absolute)
    .pipe(Effect.mapError(() => new ConfigError({ reason: `cannot read ${absolute}` })));
  const raw = yield* decodeJson(text).pipe(
    Effect.mapError(() => new ConfigError({ reason: `${absolute} is not JSON` })),
  );
  return yield* parseConfig(raw, {
    baseDir: path.dirname(absolute),
    env: yield* HostProcess.Environment,
  });
});
