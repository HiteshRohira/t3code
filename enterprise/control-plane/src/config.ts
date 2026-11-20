import * as NodeFS from "node:fs";
import * as NodePath from "node:path";

import { isRole, type Role } from "@t3tools/enterprise-protocol/wire";

export interface OidcConfig {
  readonly issuer: string;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly scopes: ReadonlyArray<string>;
  /** ID token claim holding the user's groups. */
  readonly groupsClaim: string;
  /** When set, only members of one of these groups may sign in. */
  readonly allowedGroups?: ReadonlyArray<string>;
  /** IdP group to role. A user gets every mapped role; one with none gets `defaultRole`. */
  readonly groupRoles: Readonly<Record<string, Role>>;
}

export type AuditSinkConfig =
  | { readonly type: "jsonl"; readonly path: string }
  | {
      readonly type: "http";
      readonly url: string;
      readonly headers: Readonly<Record<string, string>>;
    };

export interface ControlPlaneConfig {
  /** Public HTTPS origin devices and browsers reach; also the token issuer. */
  readonly publicUrl: string;
  readonly organization: string;
  readonly listen: { readonly host: string; readonly port: number };
  readonly tls: { readonly certPath: string; readonly keyPath: string };
  readonly dataDir: string;
  /** Org CA that signs device certificates. Created in `dataDir` when absent. */
  readonly ca: { readonly certPath: string; readonly keyPath: string };
  readonly oidc?: OidcConfig;
  /** Sign in by typing an email, with no IdP. Refused unless `publicUrl` is loopback. */
  readonly insecureDevLogin: boolean;
  /** `scim`: only users the IdP provisioned may sign in. `jit`: first sign-in creates them. */
  readonly provisioning: "scim" | "jit";
  readonly defaultRole: Role;
  readonly leaseTtlSeconds: number;
  readonly policyTtlSeconds: number;
  readonly deviceCertDays: number;
  /** Monthly token budget for users and teams without their own. Absent is unlimited. */
  readonly defaultMonthlyTokens?: number;
  /** Models every lease may call when no team or user rule narrows it. Absent allows all. */
  readonly defaultModels?: ReadonlyArray<string>;
  readonly auditSinks: ReadonlyArray<AuditSinkConfig>;
  readonly secrets: {
    readonly gatewayToken: string;
    readonly scimToken?: string;
    readonly adminApiToken?: string;
  };
}

export class ConfigError extends Error {
  override readonly name = "ConfigError";
}

type Json = Record<string, unknown>;

const object = (value: unknown, path: string): Json => {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ConfigError(`${path} must be an object`);
  }
  return value as Json;
};
const string = (value: unknown, path: string): string => {
  if (typeof value !== "string" || value.length === 0) {
    throw new ConfigError(`${path} must be a non-empty string`);
  }
  return value;
};
const optionalString = (value: unknown, path: string) =>
  value === undefined ? undefined : string(value, path);
const positive = (value: unknown, fallback: number, path: string): number => {
  if (value === undefined) return fallback;
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    throw new ConfigError(`${path} must be a positive number`);
  }
  return value;
};
const strings = (value: unknown, path: string): ReadonlyArray<string> => {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new ConfigError(`${path} must be a list of strings`);
  }
  return value;
};
const role = (value: unknown, path: string): Role => {
  if (!isRole(value)) throw new ConfigError(`${path} must be a role`);
  return value;
};

/** Secrets come from the environment so the config file can live in version control. */
const secret = (env: NodeJS.ProcessEnv, name: string) => {
  const value = env[name];
  return value === undefined || value.length === 0 ? undefined : value;
};

const isLoopbackUrl = (url: string) => {
  const host = new URL(url).hostname;
  return host === "localhost" || host === "127.0.0.1" || host === "[::1]";
};

export function parseConfig(
  raw: unknown,
  options: { baseDir: string; env: NodeJS.ProcessEnv },
): ControlPlaneConfig {
  const root = object(raw, "config");
  const at = (path: string) =>
    NodePath.isAbsolute(path) ? path : NodePath.resolve(options.baseDir, path);
  const publicUrl = string(root["publicUrl"], "publicUrl").replace(/\/$/, "");
  if (new URL(publicUrl).protocol !== "https:") {
    throw new ConfigError("publicUrl must be https");
  }
  const listen = object(root["listen"] ?? {}, "listen");
  const tls = object(root["tls"], "tls");
  const dataDir = at(string(root["dataDir"], "dataDir"));
  const ca = object(root["ca"] ?? {}, "ca");

  let oidc: OidcConfig | undefined;
  if (root["oidc"] !== undefined) {
    const o = object(root["oidc"], "oidc");
    const groupRoles = object(o["groupRoles"] ?? {}, "oidc.groupRoles");
    const clientSecret =
      secret(options.env, "T3E_OIDC_CLIENT_SECRET") ??
      optionalString(o["clientSecret"], "oidc.clientSecret");
    if (clientSecret === undefined) {
      throw new ConfigError("set T3E_OIDC_CLIENT_SECRET for the OIDC client");
    }
    oidc = {
      issuer: string(o["issuer"], "oidc.issuer").replace(/\/$/, ""),
      clientId: string(o["clientId"], "oidc.clientId"),
      clientSecret,
      scopes:
        o["scopes"] === undefined
          ? ["openid", "email", "profile"]
          : strings(o["scopes"], "oidc.scopes"),
      groupsClaim: optionalString(o["groupsClaim"], "oidc.groupsClaim") ?? "groups",
      ...(o["allowedGroups"] === undefined
        ? {}
        : { allowedGroups: strings(o["allowedGroups"], "oidc.allowedGroups") }),
      groupRoles: Object.fromEntries(
        Object.entries(groupRoles).map(([group, value]) => [
          group,
          role(value, `oidc.groupRoles.${group}`),
        ]),
      ),
    };
  }

  const insecureDevLogin = root["insecureDevLogin"] === true;
  if (insecureDevLogin && !isLoopbackUrl(publicUrl)) {
    throw new ConfigError("insecureDevLogin is only allowed when publicUrl is loopback");
  }
  if (oidc === undefined && !insecureDevLogin) {
    throw new ConfigError("configure oidc (or insecureDevLogin for local development)");
  }

  const provisioning = root["provisioning"] ?? "jit";
  if (provisioning !== "scim" && provisioning !== "jit") {
    throw new ConfigError('provisioning must be "scim" or "jit"');
  }

  const gatewayToken = secret(options.env, "T3E_GATEWAY_TOKEN");
  if (gatewayToken === undefined || gatewayToken.length < 32) {
    throw new ConfigError("set T3E_GATEWAY_TOKEN to a random value of at least 32 characters");
  }
  const scimToken = secret(options.env, "T3E_SCIM_TOKEN");
  const adminApiToken = secret(options.env, "T3E_ADMIN_API_TOKEN");
  if (provisioning === "scim" && scimToken === undefined) {
    throw new ConfigError("provisioning is scim: set T3E_SCIM_TOKEN");
  }

  const sinks = root["auditSinks"] === undefined ? [] : root["auditSinks"];
  if (!Array.isArray(sinks)) throw new ConfigError("auditSinks must be a list");
  const auditSinks = sinks.map((value, index): AuditSinkConfig => {
    const sink = object(value, `auditSinks[${index}]`);
    if (sink["type"] === "jsonl") {
      return { type: "jsonl", path: at(string(sink["path"], `auditSinks[${index}].path`)) };
    }
    if (sink["type"] === "http") {
      const headers = object(sink["headers"] ?? {}, `auditSinks[${index}].headers`);
      return {
        type: "http",
        url: string(sink["url"], `auditSinks[${index}].url`),
        // `$NAME` reads the header value from the environment, for tokens such as Splunk HEC's.
        headers: Object.fromEntries(
          Object.entries(headers).map(([name, header]) => {
            const text = string(header, `auditSinks[${index}].headers.${name}`);
            return [name, text.startsWith("$") ? (options.env[text.slice(1)] ?? "") : text];
          }),
        ),
      };
    }
    throw new ConfigError(`auditSinks[${index}].type must be "jsonl" or "http"`);
  });

  const defaultMonthlyTokens =
    root["defaultMonthlyTokens"] === undefined
      ? undefined
      : positive(root["defaultMonthlyTokens"], 0, "defaultMonthlyTokens");

  return {
    publicUrl,
    organization: string(root["organization"], "organization"),
    listen: {
      host: optionalString(listen["host"], "listen.host") ?? "0.0.0.0",
      port: positive(listen["port"], 8443, "listen.port"),
    },
    tls: {
      certPath: at(string(tls["certPath"], "tls.certPath")),
      keyPath: at(string(tls["keyPath"], "tls.keyPath")),
    },
    dataDir,
    ca: {
      certPath: at(
        optionalString(ca["certPath"], "ca.certPath") ?? NodePath.resolve(dataDir, "ca.crt"),
      ),
      keyPath: at(
        optionalString(ca["keyPath"], "ca.keyPath") ?? NodePath.resolve(dataDir, "ca.key"),
      ),
    },
    ...(oidc === undefined ? {} : { oidc }),
    insecureDevLogin,
    provisioning,
    defaultRole:
      root["defaultRole"] === undefined ? "developer" : role(root["defaultRole"], "defaultRole"),
    leaseTtlSeconds: positive(root["leaseTtlSeconds"], 4 * 3600, "leaseTtlSeconds"),
    policyTtlSeconds: positive(root["policyTtlSeconds"], 24 * 3600, "policyTtlSeconds"),
    deviceCertDays: positive(root["deviceCertDays"], 30, "deviceCertDays"),
    ...(defaultMonthlyTokens === undefined ? {} : { defaultMonthlyTokens }),
    ...(root["defaultModels"] === undefined
      ? {}
      : { defaultModels: strings(root["defaultModels"], "defaultModels") }),
    auditSinks,
    secrets: {
      gatewayToken,
      ...(scimToken === undefined ? {} : { scimToken }),
      ...(adminApiToken === undefined ? {} : { adminApiToken }),
    },
  };
}

export function loadConfig(path: string, env: NodeJS.ProcessEnv = process.env): ControlPlaneConfig {
  const absolute = NodePath.resolve(path);
  const raw: unknown = JSON.parse(NodeFS.readFileSync(absolute, "utf8"));
  return parseConfig(raw, { baseDir: NodePath.resolve(absolute, ".."), env });
}
