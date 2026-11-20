#!/usr/bin/env node
import * as NodeRuntime from "@effect/platform-node/NodeRuntime";
import * as NodeServices from "@effect/platform-node/NodeServices";
import { publicJwks } from "@t3tools/enterprise-protocol/tokens";
import * as Clock from "effect/Clock";
import * as Console from "effect/Console";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";
import * as Path from "effect/Path";
import * as Schema from "effect/Schema";
import { Command, Flag } from "effect/cli";
import * as CliError from "effect/cli/CliError";

import * as CertificateAuthority from "./CertificateAuthority.ts";
import { loadConfig } from "./Config.ts";
import * as Crypto from "./Crypto.ts";
import * as Server from "./Server.ts";
import * as SigningKeys from "./SigningKeys.ts";

const configFlag = Flag.String("config").pipe(Flag.withDescription("Path to control-plane.json."));
const encodeJson = Schema.encodeEffect(Schema.fromJsonString(Schema.Unknown));
const pretty = (value: unknown) =>
  encodeJson(value).pipe(Effect.map((text) => JSON.stringify(JSON.parse(text), null, 2)));

const serve = Command.make("serve", { config: configFlag }).pipe(
  Command.withDescription("Run the control plane."),
  Command.withHandler(
    Effect.fn("cli.serve")(function* ({ config: file }) {
      const config = yield* loadConfig(file);
      yield* Effect.logInfo(
        `${config.organization} control plane on ${config.listen.host}:${config.listen.port} (${config.publicUrl})`,
      );
      return yield* Layer.launch(Server.layer(config));
    }),
  ),
);

const trust = Command.make("trust", { config: configFlag }).pipe(
  Command.withDescription("Print the trust block for devices' enterprise.json."),
  Command.withHandler(
    Effect.fn("cli.trust")(function* ({ config: file }) {
      const config = yield* loadConfig(file);
      const keys = yield* SigningKeys.loadOrCreate(config.dataDir);
      const ca = yield* CertificateAuthority.loadOrCreate(config.ca, config.organization);
      yield* Console.log(
        yield* pretty({
          controlPlaneUrl: config.publicUrl,
          organization: config.organization,
          policyKeys: publicJwks(keys.all),
          caPem: ca.certPem,
        }),
      );
    }),
  ),
);

const rotateKeys = Command.make("rotate-keys", { config: configFlag }).pipe(
  Command.withDescription(
    "Stage a new signing key. It is published but does not sign until activate-key.",
  ),
  Command.withHandler(
    Effect.fn("cli.rotateKeys")(function* ({ config: file }) {
      const config = yield* loadConfig(file);
      const key = yield* SigningKeys.rotate(config.dataDir);
      const keys = yield* SigningKeys.loadOrCreate(config.dataDir);
      yield* Console.log(
        [
          `Staged signing key ${key.kid}. Restart the control plane so gateways see it, deploy this`,
          "policyKeys block to every device's enterprise.json, then run activate-key:",
          "",
          yield* pretty(publicJwks(keys.all)),
        ].join("\n"),
      );
    }),
  ),
);

const activateKey = Command.make("activate-key", { config: configFlag }).pipe(
  Command.withDescription("Make the staged signing key sign. Run only after devices trust it."),
  Command.withHandler(
    Effect.fn("cli.activateKey")(function* ({ config: file }) {
      const config = yield* loadConfig(file);
      const key = yield* SigningKeys.activate(config.dataDir);
      yield* Console.log(`Signing key ${key.kid} is active. Restart the control plane.`);
    }),
  ),
);

const serverCert = Command.make("server-cert", {
  config: configFlag,
  host: Flag.String("host").pipe(Flag.atLeast(1)),
  out: Flag.String("out"),
}).pipe(
  Command.withDescription(
    "Issue a TLS server certificate from the org CA (development; use your PKI in production).",
  ),
  Command.withHandler(
    Effect.fn("cli.serverCert")(function* ({ config: file, host, out }) {
      const fs = yield* FileSystem.FileSystem;
      const path = yield* Path.Path;
      const config = yield* loadConfig(file);
      const ca = yield* CertificateAuthority.loadOrCreate(config.ca, config.organization);
      const issued = CertificateAuthority.issueServerCertificatePem(ca, {
        hostnames: host,
        days: 397,
        nowMillis: yield* Clock.currentTimeMillis,
      });
      yield* fs.makeDirectory(out, { recursive: true });
      yield* fs.writeFileString(path.join(out, "tls.crt"), issued.certPem);
      yield* fs.writeFileString(path.join(out, "tls.key"), issued.keyPem, { mode: 0o600 });
      yield* Console.log(`Wrote ${path.join(out, "tls.crt")} and tls.key`);
    }),
  ),
);

const init = Command.make("init", {
  dir: Flag.String("dir"),
  organization: Flag.String("organization"),
  host: Flag.String("host").pipe(Flag.withDefault("localhost")),
}).pipe(
  Command.withDescription(
    "Create a local development setup: CA, TLS certificates, secrets, and a config file.",
  ),
  Command.withHandler(
    Effect.fn("cli.init")(function* ({ dir: rawDir, organization, host }) {
      const fs = yield* FileSystem.FileSystem;
      const path = yield* Path.Path;
      const dir = path.resolve(rawDir);
      const configFile = path.join(dir, "control-plane.json");
      if (yield* fs.exists(configFile)) {
        return yield* new CliError.UserError({
          cause: configFile,
          userMessage: `${configFile} already exists`,
        });
      }
      yield* fs.makeDirectory(path.join(dir, "data"), { recursive: true, mode: 0o700 });
      const ca = yield* CertificateAuthority.loadOrCreate(
        { certPath: path.join(dir, "data", "ca.crt"), keyPath: path.join(dir, "data", "ca.key") },
        organization,
      );
      const tls = CertificateAuthority.issueServerCertificatePem(ca, {
        hostnames: [host, "127.0.0.1"],
        days: 397,
        nowMillis: yield* Clock.currentTimeMillis,
      });
      yield* fs.writeFileString(path.join(dir, "tls.crt"), tls.certPem);
      yield* fs.writeFileString(path.join(dir, "tls.key"), tls.keyPem, { mode: 0o600 });
      const secrets = [
        `T3E_GATEWAY_TOKEN=${yield* Crypto.randomToken()}`,
        `T3E_SCIM_TOKEN=${yield* Crypto.randomToken()}`,
        `T3E_ADMIN_API_TOKEN=${yield* Crypto.randomToken()}`,
      ];
      yield* fs.writeFileString(path.join(dir, "secrets.env"), `${secrets.join("\n")}\n`, {
        mode: 0o600,
      });
      yield* fs.writeFileString(
        configFile,
        `${yield* pretty({
          publicUrl: `https://${host}:8443`,
          organization,
          listen: { host: "127.0.0.1", port: 8443 },
          tls: { certPath: "tls.crt", keyPath: "tls.key" },
          dataDir: "data",
          insecureDevLogin: true,
          provisioning: "jit",
          defaultRole: "developer",
          leaseTtlSeconds: 14400,
          policyTtlSeconds: 86400,
          auditSinks: [{ type: "jsonl", path: "data/audit.jsonl" }],
        })}\n`,
      );
      const secretsFile = path.join(dir, "secrets.env");
      yield* Console.log(
        [
          `Created ${configFile}.`,
          `Secrets are in ${secretsFile}; load them before serving:`,
          `  set -a; . ${secretsFile}; set +a`,
          `  t3-enterprise-control-plane serve --config ${configFile}`,
          'This setup signs in without an IdP. Configure "oidc" or "saml" and remove "insecureDevLogin" for real use.',
        ].join("\n"),
      );
    }),
  ),
);

const cli = Command.make("t3-enterprise-control-plane").pipe(
  Command.withDescription("The T3 Enterprise control plane."),
  Command.withSubcommands([serve, init, trust, rotateKeys, activateKey, serverCert]),
);

Command.run(cli, { version: "0.0.0" }).pipe(
  Effect.provide(NodeServices.layer),
  NodeRuntime.runMain,
);
