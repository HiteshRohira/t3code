/**
 * Server - the control plane as one layer: HTTPS with optional client certificates (browsers
 * sign in without one; device routes require one the org CA signed).
 *
 * @module Server
 */
import * as NodeHttpClient from "@effect/platform-node/NodeHttpClient";
import * as NodeHttpServer from "@effect/platform-node/NodeHttpServer";
import * as NodeServices from "@effect/platform-node/NodeServices";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";
import { HttpRouter } from "effect/http";
// @effect-diagnostics-next-line nodeBuiltinImport:off -- mutual TLS needs Node's https server.
import * as NodeHttps from "node:https";

import * as AdminRoutes from "./AdminRoutes.ts";
import * as AuditSinks from "./AuditSinks.ts";
import * as CertificateAuthority from "./CertificateAuthority.ts";
import { ControlPlaneConfig, type ControlPlaneSettings } from "./Config.ts";
import * as ControlPlane from "./ControlPlane.ts";
import * as Oidc from "./Oidc.ts";
import * as Retention from "./Retention.ts";
import * as Routes from "./Routes.ts";
import * as Saml from "./Saml.ts";
import * as ScimRoutes from "./ScimRoutes.ts";
import * as Sessions from "./Sessions.ts";
import * as SigningKeys from "./SigningKeys.ts";
import * as Store from "./Store.ts";
import * as TeamRoutes from "./TeamRoutes.ts";

const layerHttps = Layer.unwrap(
  Effect.gen(function* () {
    const config = yield* ControlPlaneConfig;
    const fs = yield* FileSystem.FileSystem;
    const ca = yield* CertificateAuthority.CertificateAuthority;
    const cert = yield* fs.readFileString(config.tls.certPath);
    const key = yield* fs.readFileString(config.tls.keyPath);
    return NodeHttpServer.layer(
      () =>
        NodeHttps.createServer({
          cert,
          key,
          ca: ca.certPem,
          requestCert: true,
          rejectUnauthorized: false,
          minVersion: "TLSv1.2",
        }),
      { host: config.listen.host, port: config.listen.port },
    );
  }),
);

const layerDomain = ControlPlane.layer.pipe(
  Layer.provideMerge(Layer.mergeAll(AuditSinks.layer, Oidc.layer, Saml.layer, Sessions.layer)),
  Layer.provideMerge(
    Layer.mergeAll(Store.layerConfig, CertificateAuthority.layer, SigningKeys.layer),
  ),
);

const layerRoutes = HttpRouter.serve(
  Layer.mergeAll(Routes.layer, AdminRoutes.layer, ScimRoutes.layer, TeamRoutes.layer),
  { disableLogger: true },
);

/** The whole control plane for `settings`; build it to listen, release its scope to stop. */
export const layer = (settings: ControlPlaneSettings) =>
  Layer.mergeAll(layerRoutes.pipe(Layer.provide(layerHttps)), Retention.layer).pipe(
    Layer.provideMerge(layerDomain),
    Layer.provide(NodeHttpClient.layerUndici),
    Layer.provide(NodeServices.layer),
    Layer.provideMerge(Layer.succeed(ControlPlaneConfig, settings)),
  );
