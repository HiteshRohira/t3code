import * as NodeFS from "node:fs";
import * as NodePath from "node:path";

export type ProviderFamily = "anthropic" | "openai";

export interface Upstream {
  /** Path prefix devices call, such as `/anthropic`. */
  readonly prefix: string;
  readonly family: ProviderFamily;
  readonly baseUrl: string;
  readonly apiKey: string;
}

export interface GatewayConfig {
  readonly listen: { readonly host: string; readonly port: number };
  readonly tls: { readonly certPath: string; readonly keyPath: string };
  /** Org CA that signed device certificates; only its certificates complete a handshake. */
  readonly deviceCaPath: string;
  readonly controlPlaneUrl: string;
  /** Extra CA for the control plane's TLS certificate when it is not publicly trusted. */
  readonly controlPlaneCaPath?: string;
  readonly gatewayToken: string;
  readonly upstreams: ReadonlyArray<Upstream>;
  readonly syncIntervalSeconds: number;
  /** With no fresh control-plane state for this long, the gateway refuses requests. */
  readonly maxStateAgeSeconds: number;
  readonly requestsPerMinute?: number;
  readonly maxRequestBytes: number;
}

export class ConfigError extends Error {
  override readonly name = "ConfigError";
}

type Json = Record<string, unknown>;

const str = (value: unknown, path: string) => {
  if (typeof value !== "string" || value.length === 0)
    throw new ConfigError(`${path} must be a non-empty string`);
  return value;
};
const num = (value: unknown, fallback: number, path: string) => {
  if (value === undefined) return fallback;
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    throw new ConfigError(`${path} must be a positive number`);
  }
  return value;
};

const DEFAULT_BASE_URLS: Readonly<Record<ProviderFamily, string>> = {
  anthropic: "https://api.anthropic.com",
  openai: "https://api.openai.com",
};

export function parseConfig(
  raw: unknown,
  options: { baseDir: string; env: NodeJS.ProcessEnv },
): GatewayConfig {
  if (typeof raw !== "object" || raw === null) throw new ConfigError("config must be an object");
  const root = raw as Json;
  const at = (path: string) =>
    NodePath.isAbsolute(path) ? path : NodePath.resolve(options.baseDir, path);
  const listen = (root["listen"] ?? {}) as Json;
  const tls = (root["tls"] ?? {}) as Json;

  const gatewayToken = options.env["T3E_GATEWAY_TOKEN"];
  if (gatewayToken === undefined || gatewayToken.length < 32) {
    throw new ConfigError("set T3E_GATEWAY_TOKEN to the control plane's gateway token");
  }

  const rawUpstreams = root["upstreams"];
  if (!Array.isArray(rawUpstreams) || rawUpstreams.length === 0) {
    throw new ConfigError("upstreams must list at least one provider");
  }
  const upstreams = rawUpstreams.map((value, index): Upstream => {
    const upstream = value as Json;
    const family = upstream["family"];
    if (family !== "anthropic" && family !== "openai") {
      throw new ConfigError(`upstreams[${index}].family must be "anthropic" or "openai"`);
    }
    // Keys come from the environment (or a secret manager that sets it), never the config file.
    const keyEnv = str(upstream["apiKeyEnv"], `upstreams[${index}].apiKeyEnv`);
    const apiKey = options.env[keyEnv];
    if (apiKey === undefined || apiKey.length === 0)
      throw new ConfigError(`set ${keyEnv} for upstreams[${index}]`);
    const prefix = typeof upstream["prefix"] === "string" ? upstream["prefix"] : `/${family}`;
    if (!/^\/[a-z0-9-]+$/.test(prefix))
      throw new ConfigError(`upstreams[${index}].prefix must look like /name`);
    return {
      prefix,
      family,
      baseUrl: (typeof upstream["baseUrl"] === "string"
        ? upstream["baseUrl"]
        : DEFAULT_BASE_URLS[family]
      ).replace(/\/$/, ""),
      apiKey,
    };
  });
  if (new Set(upstreams.map((upstream) => upstream.prefix)).size !== upstreams.length) {
    throw new ConfigError("upstream prefixes must be unique");
  }

  const requestsPerMinute =
    root["requestsPerMinute"] === undefined
      ? undefined
      : num(root["requestsPerMinute"], 0, "requestsPerMinute");

  return {
    listen: {
      host: typeof listen["host"] === "string" ? listen["host"] : "0.0.0.0",
      port: num(listen["port"], 9443, "listen.port"),
    },
    tls: {
      certPath: at(str(tls["certPath"], "tls.certPath")),
      keyPath: at(str(tls["keyPath"], "tls.keyPath")),
    },
    deviceCaPath: at(str(root["deviceCaPath"], "deviceCaPath")),
    controlPlaneUrl: str(root["controlPlaneUrl"], "controlPlaneUrl").replace(/\/$/, ""),
    ...(typeof root["controlPlaneCaPath"] === "string"
      ? { controlPlaneCaPath: at(root["controlPlaneCaPath"]) }
      : {}),
    gatewayToken,
    upstreams,
    syncIntervalSeconds: num(root["syncIntervalSeconds"], 15, "syncIntervalSeconds"),
    maxStateAgeSeconds: num(root["maxStateAgeSeconds"], 900, "maxStateAgeSeconds"),
    ...(requestsPerMinute === undefined ? {} : { requestsPerMinute }),
    maxRequestBytes: num(root["maxRequestBytes"], 32 * 1024 * 1024, "maxRequestBytes"),
  };
}

export function loadConfig(path: string, env: NodeJS.ProcessEnv = process.env): GatewayConfig {
  const absolute = NodePath.resolve(path);
  return parseConfig(JSON.parse(NodeFS.readFileSync(absolute, "utf8")), {
    baseDir: NodePath.resolve(absolute, ".."),
    env,
  });
}
