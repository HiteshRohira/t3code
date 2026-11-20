import * as NodeFS from "node:fs";
import * as NodeHttps from "node:https";
import * as NodePath from "node:path";

import { ControlPlane } from "./app.ts";
import { loadOrCreateCertificateAuthority } from "./ca.ts";
import type { ControlPlaneConfig } from "./config.ts";
import { loadOrCreateSigningKeys } from "./keys.ts";
import { Store } from "./store.ts";

export async function startControlPlane(
  config: ControlPlaneConfig,
  options: { fetch?: typeof fetch } = {},
): Promise<{ plane: ControlPlane; server: NodeHttps.Server; close: () => Promise<void> }> {
  NodeFS.mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
  const ca = loadOrCreateCertificateAuthority(config.ca, config.organization);
  const keys = await loadOrCreateSigningKeys(NodePath.join(config.dataDir, "signing-keys.json"));
  const store = new Store(NodePath.join(config.dataDir, "control-plane.sqlite"));
  const plane = new ControlPlane({
    config,
    store,
    ca,
    keys,
    ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
  });
  // Client certificates are optional at the TLS layer so browsers can sign in; device routes
  // require a certificate the org CA verified.
  const server = NodeHttps.createServer(
    {
      cert: NodeFS.readFileSync(config.tls.certPath),
      key: NodeFS.readFileSync(config.tls.keyPath),
      ca: ca.certPem,
      requestCert: true,
      rejectUnauthorized: false,
      minVersion: "TLSv1.2",
    },
    plane.handle,
  );
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.listen.port, config.listen.host, () => resolve());
  });
  return {
    plane,
    server,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => {
          store.close();
          resolve();
        });
        server.closeAllConnections();
      }),
  };
}
