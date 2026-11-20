/**
 * EnterpriseConfig - the machine-wide `enterprise.json` an organization deploys beside its policy
 * file. It is the device's trust anchor: which control plane and gateway to use and which keys
 * sign the organization's policy. Its absence means this is an ordinary T3 Code install.
 *
 * @module EnterpriseConfig
 */
import { ManagedPolicyDocument, TrimmedNonEmptyString } from "@t3tools/contracts";
import * as HostProcess from "@t3tools/shared/HostProcess";
import { managedPolicyPath } from "@t3tools/shared/managedPolicyFile";
import * as Config from "effect/Config";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";

import { telemetryChannel } from "../config.ts";

const HttpsUrl = TrimmedNonEmptyString.check(
  Schema.makeFilter((value: string) => {
    try {
      return new URL(value).protocol === "https:" ? true : "must be an https URL";
    } catch {
      return "must be a URL";
    }
  }),
);

const Jwk = Schema.Record(Schema.String, Schema.Unknown);

export const EnterpriseConfigDocument = Schema.Struct({
  schemaVersion: Schema.Literal(1),
  organization: TrimmedNonEmptyString,
  controlPlaneUrl: HttpsUrl,
  gatewayUrl: HttpsUrl,
  /** Public keys that sign the organization's policy; tokens signed by any other key are refused. */
  policyKeys: Schema.Struct({ keys: Schema.Array(Jwk) }),
  /** Extra CA certificates (PEM) for the control plane's and gateway's TLS, when they are private. */
  serverCaPem: Schema.optional(TrimmedNonEmptyString),
  /** Applies until the device holds an unexpired signed policy from the control plane. */
  bootstrapPolicy: Schema.optional(ManagedPolicyDocument),
  /**
   * `use-cached-until-expiry` keeps a lease until it expires when the control plane cannot be
   * reached; `deny` stops new model calls as soon as a renewal fails.
   */
  whenUnreachable: Schema.optional(Schema.Literals(["use-cached-until-expiry", "deny"])),
  policyRefreshSeconds: Schema.optional(Schema.Int.check(Schema.isGreaterThanOrEqualTo(60))),
  supportUrl: Schema.optional(HttpsUrl),
});
export type EnterpriseConfigDocument = typeof EnterpriseConfigDocument.Type;

export class EnterpriseConfigError extends Schema.TaggedError<EnterpriseConfigError>()(
  "EnterpriseConfigError",
  { path: Schema.String, reason: Schema.String, cause: Schema.optional(Schema.Defect()) },
) {
  override get message(): string {
    return `T3 Code cannot use the enterprise configuration at ${this.path}: ${this.reason}. It will not start until an administrator fixes this.`;
  }
}

/** Beside the policy file, in a folder only administrators can write. */
export const enterpriseConfigPath = (platform: NodeJS.Platform) =>
  managedPolicyPath(platform).replace(/policy\.json$/, "enterprise.json");

const decodeConfig = Schema.decodeUnknownEffect(Schema.fromJsonString(EnterpriseConfigDocument), {
  onExcessProperty: "error",
});

export interface LoadedEnterpriseConfig {
  readonly path: string;
  readonly document: EnterpriseConfigDocument;
}

const readEnterpriseConfigFile = Effect.fn("EnterpriseConfig.readFile")(function* (path: string) {
  const fs = yield* FileSystem.FileSystem;
  const exists = yield* fs
    .exists(path)
    .pipe(
      Effect.mapError(
        (cause) => new EnterpriseConfigError({ path, reason: "the file cannot be checked", cause }),
      ),
    );
  if (!exists) return undefined;
  const raw = yield* fs
    .readFileString(path)
    .pipe(
      Effect.mapError(
        (cause) => new EnterpriseConfigError({ path, reason: "the file cannot be read", cause }),
      ),
    );
  const document = yield* decodeConfig(raw).pipe(
    Effect.mapError(
      (cause) =>
        new EnterpriseConfigError({
          path,
          reason: `it does not match the enterprise schema (${cause.message.replace(/\s*\n\s*/g, " ")})`,
        }),
    ),
  );
  return { path, document } satisfies LoadedEnterpriseConfig;
});

/** The deployed config, or undefined on an unmanaged machine. */
export const readEnterpriseConfig = Effect.gen(function* () {
  // Source builds may read the config from elsewhere so it can be tried without root. Release
  // builds never do: a user-set override would let them pin their own trust anchor.
  const devPath =
    telemetryChannel === "dev"
      ? yield* Config.option(Config.String("T3CODE_DEV_ENTERPRISE_CONFIG_PATH")).pipe(
          Effect.orElseSucceed(() => Option.none<string>()),
        )
      : Option.none<string>();
  const path = Option.isSome(devPath)
    ? devPath.value
    : enterpriseConfigPath(yield* HostProcess.Platform);
  return yield* readEnterpriseConfigFile(path);
});
