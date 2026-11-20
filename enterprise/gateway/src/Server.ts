/**
 * Server - the gateway as one layer. Only devices holding a certificate from the org CA complete
 * the TLS handshake; the control plane is synced in the background and once more at shutdown so
 * metered usage is not lost.
 *
 * @module Server
 */
import * as NodeHttpClient from "@effect/platform-node/NodeHttpClient";
import * as NodeHttpServer from "@effect/platform-node/NodeHttpServer";
import * as NodeServices from "@effect/platform-node/NodeServices";
import * as Context from "effect/Context";
import * as SecureRandom from "effect/crypto/SecureRandom";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";
import * as Schedule from "effect/Schedule";
import { HttpClient, HttpRouter } from "effect/http";
// @effect-diagnostics-next-line nodeBuiltinImport:off -- mutual TLS needs Node's https server.
import * as NodeHttps from "node:https";

import { GatewayConfig, type GatewaySettings } from "./Config.ts";
import * as Gateway from "./Gateway.ts";

const layerGateway = Layer.effect(
  Gateway.Gateway,
  Effect.gen(function* () {
    const config = yield* GatewayConfig;
    const fs = yield* FileSystem.FileSystem;
    const ca =
      config.controlPlaneCaPath === undefined
        ? undefined
        : yield* fs.readFileString(config.controlPlaneCaPath);
    const controlPlaneClient = Context.get(
      yield* Layer.build(NodeHttpClient.layerNodeHttpOptions(ca === undefined ? {} : { ca })),
      HttpClient.HttpClient,
    );
    return yield* Gateway.make(controlPlaneClient);
  }),
);

const layerSync = Layer.effectDiscard(
  Effect.gen(function* () {
    const config = yield* GatewayConfig;
    const gateway = yield* Gateway.Gateway;
    const syncLogged = gateway.sync.pipe(
      Effect.catch((error) =>
        Effect.logWarning("Control plane sync failed", { error: error.message }),
      ),
    );
    yield* Effect.addFinalizer(() => syncLogged);
    yield* syncLogged.pipe(
      Effect.repeat(Schedule.spaced(`${config.syncIntervalSeconds} seconds`)),
      Effect.forkScoped,
    );
  }),
);

const layerHttps = Layer.unwrap(
  Effect.gen(function* () {
    const config = yield* GatewayConfig;
    const fs = yield* FileSystem.FileSystem;
    const cert = yield* fs.readFileString(config.tls.certPath);
    const key = yield* fs.readFileString(config.tls.keyPath);
    const deviceCa = yield* fs.readFileString(config.deviceCaPath);
    return NodeHttpServer.layer(
      () =>
        NodeHttps.createServer({
          cert,
          key,
          ca: deviceCa,
          requestCert: true,
          rejectUnauthorized: true,
          minVersion: "TLSv1.2",
        }),
      { host: config.listen.host, port: config.listen.port },
    );
  }),
);

const layerRoutes = HttpRouter.serve(
  HttpRouter.use((router) =>
    Effect.gen(function* () {
      const gateway = yield* Gateway.Gateway;
      yield* router.add("*", "*", gateway.handle);
    }),
  ),
  { disableLogger: true },
);

/** The whole gateway for `settings`; build it to listen, release its scope to stop. */
export const layer = (settings: GatewaySettings) =>
  Layer.mergeAll(layerRoutes.pipe(Layer.provide(layerHttps)), layerSync).pipe(
    Layer.provideMerge(layerGateway),
    Layer.provide(Layer.mergeAll(NodeHttpClient.layerUndici, SecureRandom.layerWebCrypto)),
    Layer.provide(NodeServices.layer),
    Layer.provideMerge(Layer.succeed(GatewayConfig, settings)),
  );
