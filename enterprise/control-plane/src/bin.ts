#!/usr/bin/env node
import * as NodeCrypto from "node:crypto";
import * as NodeFS from "node:fs";
import * as NodePath from "node:path";
import * as NodeUtil from "node:util";

import { publicJwks } from "@t3tools/enterprise-protocol/tokens";

import { issueServerCertificate, loadOrCreateCertificateAuthority } from "./ca.ts";
import { loadConfig } from "./config.ts";
import { loadOrCreateSigningKeys, rotateSigningKeys } from "./keys.ts";
import { startControlPlane } from "./server.ts";

const USAGE = `t3-enterprise-control-plane <command>

  serve        --config <file>                    Run the control plane.
  init         --dir <dir> --organization <name>  Create a local development setup: CA, TLS
               [--host localhost]                 certificates, secrets, and a config file.
  trust        --config <file>                    Print the trust block for devices' enterprise.json.
  rotate-keys  --config <file>                    Add a signing key; devices must trust it first.
  server-cert  --config <file> --host <name>...   Issue a TLS server certificate from the org CA
               --out <dir>                        (development; use your PKI in production).
`;

const { positionals, values } = NodeUtil.parseArgs({
  allowPositionals: true,
  options: {
    config: { type: "string" },
    dir: { type: "string" },
    organization: { type: "string" },
    host: { type: "string", multiple: true },
    out: { type: "string" },
    help: { type: "boolean" },
  },
});

const command = positionals[0];
const configPath = () => {
  if (values.config === undefined) throw new Error("--config is required");
  return values.config;
};

async function trustBlock(path: string) {
  const config = loadConfig(path);
  const keys = await loadOrCreateSigningKeys(NodePath.join(config.dataDir, "signing-keys.json"));
  const ca = loadOrCreateCertificateAuthority(config.ca, config.organization);
  return {
    controlPlaneUrl: config.publicUrl,
    organization: config.organization,
    policyKeys: publicJwks(keys.all),
    caPem: ca.certPem,
  };
}

async function main() {
  if (values.help === true || command === undefined) {
    process.stdout.write(USAGE);
    return;
  }
  switch (command) {
    case "serve": {
      const config = loadConfig(configPath());
      const { close } = await startControlPlane(config);
      console.log(
        `[control-plane] ${config.organization} listening on ${config.listen.host}:${config.listen.port} (${config.publicUrl})`,
      );
      const stop = () => void close().then(() => process.exit(0));
      process.once("SIGINT", stop);
      process.once("SIGTERM", stop);
      return;
    }
    case "trust":
      process.stdout.write(`${JSON.stringify(await trustBlock(configPath()), null, 2)}\n`);
      return;
    case "rotate-keys": {
      const config = loadConfig(configPath());
      const keys = await rotateSigningKeys(NodePath.join(config.dataDir, "signing-keys.json"));
      console.log(
        `New signing key ${keys.active.kid}. Deploy the new trust block to devices before tokens they cannot verify reach them:`,
      );
      process.stdout.write(`${JSON.stringify(publicJwks(keys.all), null, 2)}\n`);
      return;
    }
    case "server-cert": {
      const config = loadConfig(configPath());
      const hosts = values.host ?? [];
      if (hosts.length === 0 || values.out === undefined)
        throw new Error("--host and --out are required");
      const ca = loadOrCreateCertificateAuthority(config.ca, config.organization);
      const issued = issueServerCertificate(ca, { hostnames: hosts, days: 397 });
      NodeFS.mkdirSync(values.out, { recursive: true });
      NodeFS.writeFileSync(NodePath.join(values.out, "tls.crt"), issued.certPem);
      NodeFS.writeFileSync(NodePath.join(values.out, "tls.key"), issued.keyPem, { mode: 0o600 });
      console.log(`Wrote ${NodePath.join(values.out, "tls.crt")} and tls.key`);
      return;
    }
    case "init": {
      if (values.dir === undefined || values.organization === undefined) {
        throw new Error("--dir and --organization are required");
      }
      const dir = NodePath.resolve(values.dir);
      const host = values.host?.[0] ?? "localhost";
      const configFile = NodePath.join(dir, "control-plane.json");
      if (NodeFS.existsSync(configFile)) throw new Error(`${configFile} already exists`);
      NodeFS.mkdirSync(NodePath.join(dir, "data"), { recursive: true, mode: 0o700 });
      const ca = loadOrCreateCertificateAuthority(
        {
          certPath: NodePath.join(dir, "data", "ca.crt"),
          keyPath: NodePath.join(dir, "data", "ca.key"),
        },
        values.organization,
      );
      const tls = issueServerCertificate(ca, { hostnames: [host, "127.0.0.1"], days: 397 });
      NodeFS.writeFileSync(NodePath.join(dir, "tls.crt"), tls.certPem);
      NodeFS.writeFileSync(NodePath.join(dir, "tls.key"), tls.keyPem, { mode: 0o600 });
      const secrets = {
        T3E_GATEWAY_TOKEN: NodeCrypto.randomBytes(32).toString("base64url"),
        T3E_SCIM_TOKEN: NodeCrypto.randomBytes(32).toString("base64url"),
        T3E_ADMIN_API_TOKEN: NodeCrypto.randomBytes(32).toString("base64url"),
      };
      NodeFS.writeFileSync(
        NodePath.join(dir, "secrets.env"),
        `${Object.entries(secrets)
          .map(([k, v]) => `${k}=${v}`)
          .join("\n")}\n`,
        { mode: 0o600 },
      );
      NodeFS.writeFileSync(
        configFile,
        `${JSON.stringify(
          {
            publicUrl: `https://${host}:8443`,
            organization: values.organization,
            listen: { host: "127.0.0.1", port: 8443 },
            tls: { certPath: "tls.crt", keyPath: "tls.key" },
            dataDir: "data",
            insecureDevLogin: true,
            provisioning: "jit",
            defaultRole: "developer",
            leaseTtlSeconds: 14400,
            policyTtlSeconds: 86400,
            auditSinks: [{ type: "jsonl", path: "data/audit.jsonl" }],
          },
          null,
          2,
        )}\n`,
      );
      console.log(`Created ${configFile}.
Secrets are in ${NodePath.join(dir, "secrets.env")}; load them before serving:
  set -a; . ${NodePath.join(dir, "secrets.env")}; set +a
  t3-enterprise-control-plane serve --config ${configFile}
This setup signs in without an IdP. Configure "oidc" and remove "insecureDevLogin" for real use.`);
      return;
    }
    default:
      process.stderr.write(USAGE);
      process.exitCode = 2;
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
