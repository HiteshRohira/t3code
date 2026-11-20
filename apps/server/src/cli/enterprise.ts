import * as HostProcess from "@t3tools/shared/HostProcess";
import * as Console from "effect/Console";
import * as Effect from "effect/Effect";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import { Command, Flag } from "effect/cli";
import * as CliError from "effect/cli/CliError";

import packageJson from "../../package.json" with { type: "json" };
import * as EnterpriseConfig from "../enterprise/EnterpriseConfig.ts";
import * as EnterpriseDevice from "../enterprise/EnterpriseDevice.ts";
import * as EnterpriseEnrollment from "../enterprise/EnterpriseEnrollment.ts";
import * as EnterpriseLibrary from "../enterprise/EnterpriseLibrary.ts";
import * as EnterprisePolicy from "../enterprise/EnterprisePolicy.ts";
import * as ExternalLauncher from "../process/externalLauncher.ts";

const requireConfig = Effect.gen(function* () {
  const loaded = yield* EnterpriseConfig.readEnterpriseConfig;
  if (loaded === undefined) {
    const path = EnterpriseConfig.enterpriseConfigPath(yield* HostProcess.Platform);
    return yield* new CliError.UserError({
      cause: path,
      userMessage: `This computer is not managed by an organization: there is no ${path}.`,
    });
  }
  return loaded;
});

const RunningStatus = Schema.Struct({
  lease: Schema.Struct({
    active: Schema.Boolean,
    expiresAt: Schema.NullOr(Schema.String),
    problem: Schema.NullOr(Schema.String),
  }),
  policy: Schema.Struct({
    loadedVersion: Schema.NullOr(Schema.Number),
    restartRequired: Schema.Boolean,
  }),
  updatedAt: Schema.String,
});
const decodeRunningStatus = Schema.decodeUnknownEffect(Schema.fromJsonString(RunningStatus));

const enrollCommand = Command.make("enroll", {
  noBrowser: Flag.Boolean("no-browser").pipe(
    Flag.withDescription("Print the sign-in link instead of opening a browser, as over SSH."),
    Flag.withDefault(false),
  ),
}).pipe(
  Command.withDescription("Sign in to your organization and enroll this computer."),
  Command.withHandler(
    Effect.fn("cli.enterprise.enroll")(function* ({ noBrowser }) {
      const { document: config } = yield* requireConfig;
      const launcher = yield* ExternalLauncher.ExternalLauncher;
      const { identity, policyVersion } = yield* EnterpriseEnrollment.enroll(config, {
        clientVersion: packageJson.version,
        showSignInUrl: (url) =>
          Console.log(`Sign in to ${config.organization} in your browser:\n\n  ${url}\n`).pipe(
            Effect.andThen(
              noBrowser ? Effect.void : launcher.launchBrowser(url).pipe(Effect.ignore),
            ),
          ),
      });
      yield* Console.log(
        [
          `Enrolled as ${identity.record.email} (${identity.record.roles.join(", ")}).`,
          `Device ${identity.record.deviceId}, certificate valid until ${identity.record.expiresAt}.`,
          policyVersion === undefined
            ? "No organization policy is published yet; the bootstrap policy applies."
            : `Fetched policy version ${policyVersion}.`,
          "Restart T3 Code to apply it. Model access starts within a minute.",
        ].join("\n"),
      );
    }, Effect.provide(ExternalLauncher.layer)),
  ),
);

const statusCommand = Command.make("status").pipe(
  Command.withDescription("Show this computer's enrollment, model access, and policy."),
  Command.withHandler(
    Effect.fn("cli.enterprise.status")(function* () {
      const loaded = yield* requireConfig;
      const config = loaded.document;
      const paths = yield* EnterpriseDevice.statePaths;
      const identity = yield* EnterpriseDevice.readIdentity(paths, config.controlPlaneUrl);
      const lines = [`Managed by ${config.organization} (${loaded.path}).`];
      if (Option.isNone(identity)) {
        lines.push("Not enrolled. Run `t3 enterprise enroll`.");
        yield* Console.log(lines.join("\n"));
        return;
      }
      const { record } = identity.value;
      lines.push(
        `Enrolled as ${record.email} (${record.roles.join(", ")}); device ${record.deviceId}.`,
        `Certificate valid until ${record.expiresAt}.`,
      );
      const resolved = yield* EnterprisePolicy.resolve(config, loaded.path);
      lines.push(`Policy on disk: ${resolved.source}.`);
      const running = yield* EnterpriseDevice.readText(paths.status).pipe(
        Effect.flatMap((text) =>
          Option.isNone(text)
            ? Effect.succeedNone
            : decodeRunningStatus(text.value).pipe(Effect.option),
        ),
      );
      if (Option.isSome(running)) {
        const snapshot = running.value;
        lines.push(
          snapshot.lease.active
            ? `Model access: active until ${snapshot.lease.expiresAt} (checked ${snapshot.updatedAt}).`
            : `Model access: none. ${snapshot.lease.problem ?? ""}`.trim(),
          snapshot.policy.restartRequired
            ? "A newer policy is on disk. Restart T3 Code to apply it."
            : `The running server enforces policy version ${snapshot.policy.loadedVersion ?? "bootstrap"}.`,
        );
      } else {
        lines.push("No running T3 Code server has reported in yet.");
      }
      yield* Console.log(lines.join("\n"));
    }),
  ),
);

const unenrollCommand = Command.make("unenroll").pipe(
  Command.withDescription("Remove this computer's enrollment and its device key."),
  Command.withHandler(
    Effect.fn("cli.enterprise.unenroll")(function* () {
      const { document: config } = yield* requireConfig;
      yield* EnterpriseLibrary.uninstall(config.organization).pipe(Effect.ignore);
      yield* EnterpriseDevice.removeIdentity(yield* EnterpriseDevice.statePaths);
      yield* Console.log(
        `Removed this computer's enrollment with ${config.organization}. Ask an admin to revoke the device too.`,
      );
    }),
  ),
);

export const enterpriseCommand = Command.make("enterprise").pipe(
  Command.withDescription("Enroll this computer with your organization and check its status."),
  Command.withSubcommands([enrollCommand, statusCommand, unenrollCommand]),
);
