/**
 * Config - the control plane's JSON config file, with secrets read from the environment so the
 * file itself can live in version control.
 *
 * @module Config
 */
import { Role } from "@t3tools/enterprise-protocol/wire";
import * as HostProcess from "@t3tools/shared/HostProcess";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Path from "effect/Path";
import * as Schema from "effect/Schema";

export class ConfigError extends Schema.TaggedError<ConfigError>()("ConfigError", {
  reason: Schema.String,
}) {
  override get message(): string {
    return `Control plane config: ${this.reason}`;
  }
}

const NonEmpty = Schema.NonEmptyString;
const Positive = Schema.Number.check(Schema.isGreaterThan(0));
const StringList = Schema.Array(NonEmpty);

/** IdP group to role. A user gets every mapped role; one with none gets `defaultRole`. */
const GroupRoles = Schema.Record(Schema.String, Role);

const OidcFile = Schema.Struct({
  issuer: NonEmpty,
  clientId: NonEmpty,
  clientSecret: Schema.optional(NonEmpty),
  scopes: Schema.optional(StringList),
  /** ID token claim holding the user's groups. */
  groupsClaim: Schema.optional(NonEmpty),
});

const SamlFile = Schema.Struct({
  /** The IdP's SSO URL (HTTP-Redirect binding). */
  entryPoint: NonEmpty,
  /** The IdP's signing certificate (PEM, or a path to one). */
  idpCertificate: NonEmpty,
  /** Our SP entity id; defaults to `<publicUrl>/saml/metadata`. */
  issuer: Schema.optional(NonEmpty),
  /** Assertion attribute holding the user's groups. */
  groupsAttribute: Schema.optional(NonEmpty),
  emailAttribute: Schema.optional(NonEmpty),
  nameAttribute: Schema.optional(NonEmpty),
});

const AuditSinkFile = Schema.Union([
  Schema.Struct({ type: Schema.Literal("jsonl"), path: NonEmpty }),
  Schema.Struct({
    type: Schema.Literal("http"),
    url: NonEmpty,
    headers: Schema.optional(Schema.Record(Schema.String, Schema.String)),
  }),
]);

const RetentionFile = Schema.Struct({
  auditDays: Schema.optional(Positive),
  usageDays: Schema.optional(Positive),
  leaseDays: Schema.optional(Positive),
});

const ConfigFile = Schema.Struct({
  publicUrl: NonEmpty,
  organization: NonEmpty,
  listen: Schema.optional(
    Schema.Struct({ host: Schema.optional(NonEmpty), port: Schema.optional(Positive) }),
  ),
  tls: Schema.Struct({ certPath: NonEmpty, keyPath: NonEmpty }),
  dataDir: NonEmpty,
  ca: Schema.optional(
    Schema.Struct({ certPath: Schema.optional(NonEmpty), keyPath: Schema.optional(NonEmpty) }),
  ),
  oidc: Schema.optional(OidcFile),
  saml: Schema.optional(SamlFile),
  /** IdP groups (from OIDC, SAML, or SCIM) to roles. */
  groupRoles: Schema.optional(GroupRoles),
  /** When set, only members of one of these groups may sign in. */
  allowedGroups: Schema.optional(StringList),
  insecureDevLogin: Schema.optional(Schema.Boolean),
  provisioning: Schema.optional(Schema.Literals(["scim", "jit"])),
  defaultRole: Schema.optional(Role),
  leaseTtlSeconds: Schema.optional(Positive),
  policyTtlSeconds: Schema.optional(Positive),
  deviceCertDays: Schema.optional(Positive),
  defaultMonthlyTokens: Schema.optional(Positive),
  defaultModels: Schema.optional(StringList),
  /** Data region new users and teams start in; upstreams in the gateway are labelled by region. */
  defaultRegion: Schema.optional(NonEmpty),
  regions: Schema.optional(StringList),
  auditSinks: Schema.optional(Schema.Array(AuditSinkFile)),
  retention: Schema.optional(RetentionFile),
});

export type AuditSinkConfig =
  | { readonly type: "jsonl"; readonly path: string }
  | {
      readonly type: "http";
      readonly url: string;
      readonly headers: Readonly<Record<string, string>>;
    };

export interface OidcConfig {
  readonly issuer: string;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly scopes: ReadonlyArray<string>;
  readonly groupsClaim: string;
}

export interface SamlConfig {
  readonly entryPoint: string;
  readonly idpCertificate: string;
  readonly issuer: string;
  readonly groupsAttribute: string;
  readonly emailAttribute: string | undefined;
  readonly nameAttribute: string | undefined;
}

export interface ControlPlaneSettings {
  /** Public HTTPS origin devices and browsers reach; also the token issuer. */
  readonly publicUrl: string;
  readonly organization: string;
  readonly listen: { readonly host: string; readonly port: number };
  readonly tls: { readonly certPath: string; readonly keyPath: string };
  readonly dataDir: string;
  /** Org CA that signs device certificates. Created in `dataDir` when absent. */
  readonly ca: { readonly certPath: string; readonly keyPath: string };
  readonly oidc: OidcConfig | undefined;
  readonly saml: SamlConfig | undefined;
  readonly groupRoles: Readonly<Record<string, Role>>;
  readonly allowedGroups: ReadonlyArray<string> | undefined;
  /** Sign in by typing an email, with no IdP. Refused unless `publicUrl` is loopback. */
  readonly insecureDevLogin: boolean;
  /** `scim`: only users the IdP provisioned may sign in. `jit`: first sign-in creates them. */
  readonly provisioning: "scim" | "jit";
  readonly defaultRole: Role;
  readonly leaseTtlSeconds: number;
  readonly policyTtlSeconds: number;
  readonly deviceCertDays: number;
  /** Monthly token budget for users and teams without their own. Absent is unlimited. */
  readonly defaultMonthlyTokens: number | undefined;
  /** Models every lease may call when no team or user rule narrows it. Absent allows all. */
  readonly defaultModels: ReadonlyArray<string> | undefined;
  readonly defaultRegion: string | undefined;
  /** Regions admins may assign; the gateway must have upstreams for each. */
  readonly regions: ReadonlyArray<string>;
  readonly auditSinks: ReadonlyArray<AuditSinkConfig>;
  /** Rows older than these are deleted daily. Absent keeps them forever. */
  readonly retention: {
    readonly auditDays: number | undefined;
    readonly usageDays: number | undefined;
    readonly leaseDays: number | undefined;
  };
  readonly secrets: {
    readonly gatewayToken: string;
    readonly scimToken: string | undefined;
    readonly adminApiToken: string | undefined;
  };
}

export class ControlPlaneConfig extends Context.Service<ControlPlaneConfig, ControlPlaneSettings>()(
  "@t3tools/enterprise-control-plane/Config/ControlPlaneConfig",
) {}

const decodeFile = Schema.decodeUnknownEffect(ConfigFile, { onExcessProperty: "error" });
const decodeJson = Schema.decodeUnknownEffect(Schema.fromJsonString(Schema.Unknown));

const isLoopbackUrl = (url: URL) =>
  url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";

const parseUrl = (value: string, field: string) =>
  Effect.try({
    try: () => new URL(value),
    catch: () => new ConfigError({ reason: `${field} must be a URL` }),
  });

/** `$NAME` reads a header value from the environment, for tokens such as Splunk HEC's. */
const fromEnv = (env: Readonly<Record<string, string | undefined>>, value: string) =>
  value.startsWith("$") ? (env[value.slice(1)] ?? "") : value;

export const parseConfig = Effect.fn("ControlPlaneConfig.parse")(function* (
  raw: unknown,
  options: { baseDir: string; env: Readonly<Record<string, string | undefined>> },
) {
  const path = yield* Path.Path;
  const fs = yield* FileSystem.FileSystem;
  const file = yield* decodeFile(raw).pipe(
    Effect.mapError((cause) => new ConfigError({ reason: cause.message })),
  );
  const at = (value: string) =>
    path.isAbsolute(value) ? value : path.resolve(options.baseDir, value);
  const secret = (name: string) => {
    const value = options.env[name];
    return value === undefined || value.length === 0 ? undefined : value;
  };

  const publicUrl = file.publicUrl.replace(/\/$/, "");
  const parsedPublicUrl = yield* parseUrl(publicUrl, "publicUrl");
  if (parsedPublicUrl.protocol !== "https:") {
    return yield* new ConfigError({ reason: "publicUrl must be https" });
  }
  const insecureDevLogin = file.insecureDevLogin === true;
  if (insecureDevLogin && !isLoopbackUrl(parsedPublicUrl)) {
    return yield* new ConfigError({
      reason: "insecureDevLogin is only allowed when publicUrl is loopback",
    });
  }

  let oidc: OidcConfig | undefined;
  if (file.oidc !== undefined) {
    const clientSecret = secret("T3E_OIDC_CLIENT_SECRET") ?? file.oidc.clientSecret;
    if (clientSecret === undefined) {
      return yield* new ConfigError({ reason: "set T3E_OIDC_CLIENT_SECRET for the OIDC client" });
    }
    oidc = {
      issuer: file.oidc.issuer.replace(/\/$/, ""),
      clientId: file.oidc.clientId,
      clientSecret,
      scopes: file.oidc.scopes ?? ["openid", "email", "profile"],
      groupsClaim: file.oidc.groupsClaim ?? "groups",
    };
  }

  let saml: SamlConfig | undefined;
  if (file.saml !== undefined) {
    const certificate = file.saml.idpCertificate.includes("BEGIN CERTIFICATE")
      ? file.saml.idpCertificate
      : yield* fs.readFileString(at(file.saml.idpCertificate)).pipe(
          Effect.mapError(
            () =>
              new ConfigError({
                reason: `cannot read saml.idpCertificate ${file.saml?.idpCertificate}`,
              }),
          ),
        );
    saml = {
      entryPoint: file.saml.entryPoint,
      idpCertificate: certificate,
      issuer: file.saml.issuer ?? `${publicUrl}/saml/metadata`,
      groupsAttribute: file.saml.groupsAttribute ?? "groups",
      emailAttribute: file.saml.emailAttribute,
      nameAttribute: file.saml.nameAttribute,
    };
  }

  if (oidc === undefined && saml === undefined && !insecureDevLogin) {
    return yield* new ConfigError({
      reason: "configure oidc or saml (or insecureDevLogin for local development)",
    });
  }

  const provisioning = file.provisioning ?? "jit";
  const gatewayToken = secret("T3E_GATEWAY_TOKEN");
  if (gatewayToken === undefined || gatewayToken.length < 32) {
    return yield* new ConfigError({
      reason: "set T3E_GATEWAY_TOKEN to a random value of at least 32 characters",
    });
  }
  const scimToken = secret("T3E_SCIM_TOKEN");
  if (provisioning === "scim" && scimToken === undefined) {
    return yield* new ConfigError({ reason: "provisioning is scim: set T3E_SCIM_TOKEN" });
  }

  const regions = file.regions ?? (file.defaultRegion === undefined ? [] : [file.defaultRegion]);
  if (file.defaultRegion !== undefined && !regions.includes(file.defaultRegion)) {
    return yield* new ConfigError({ reason: "defaultRegion must be one of regions" });
  }

  const dataDir = at(file.dataDir);
  return {
    publicUrl,
    organization: file.organization,
    listen: { host: file.listen?.host ?? "0.0.0.0", port: file.listen?.port ?? 8443 },
    tls: { certPath: at(file.tls.certPath), keyPath: at(file.tls.keyPath) },
    dataDir,
    ca: {
      certPath: at(file.ca?.certPath ?? path.join(dataDir, "ca.crt")),
      keyPath: at(file.ca?.keyPath ?? path.join(dataDir, "ca.key")),
    },
    oidc,
    saml,
    groupRoles: file.groupRoles ?? {},
    allowedGroups: file.allowedGroups,
    insecureDevLogin,
    provisioning,
    defaultRole: file.defaultRole ?? "developer",
    leaseTtlSeconds: file.leaseTtlSeconds ?? 4 * 3600,
    policyTtlSeconds: file.policyTtlSeconds ?? 24 * 3600,
    deviceCertDays: file.deviceCertDays ?? 30,
    defaultMonthlyTokens: file.defaultMonthlyTokens,
    defaultModels: file.defaultModels,
    defaultRegion: file.defaultRegion,
    regions,
    auditSinks: (file.auditSinks ?? []).map((sink): AuditSinkConfig =>
      sink.type === "jsonl"
        ? { type: "jsonl", path: at(sink.path) }
        : {
            type: "http",
            url: sink.url,
            headers: Object.fromEntries(
              Object.entries(sink.headers ?? {}).map(([name, value]) => [
                name,
                fromEnv(options.env, value),
              ]),
            ),
          },
    ),
    retention: {
      auditDays: file.retention?.auditDays,
      usageDays: file.retention?.usageDays,
      leaseDays: file.retention?.leaseDays,
    },
    secrets: { gatewayToken, scimToken, adminApiToken: secret("T3E_ADMIN_API_TOKEN") },
  } satisfies ControlPlaneSettings;
});

export const loadConfig = Effect.fn("ControlPlaneConfig.load")(function* (file: string) {
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
