#!/usr/bin/env node
import * as NodeRuntime from "@effect/platform-node/NodeRuntime";
import * as NodeServices from "@effect/platform-node/NodeServices";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import { Command, Flag } from "effect/cli";

import { loadConfig } from "./Config.ts";
import * as Server from "./Server.ts";

const gateway = Command.make("t3-enterprise-gateway", {
  config: Flag.String("config").pipe(Flag.withDescription("Path to gateway.json.")),
}).pipe(
  Command.withDescription("The T3 Enterprise model gateway."),
  Command.withHandler(
    Effect.fn("cli.gateway")(function* ({ config: file }) {
      const config = yield* loadConfig(file);
      yield* Effect.logInfo(
        `Gateway on ${config.listen.host}:${config.listen.port}; upstreams ${config.upstreams
          .map(
            (upstream) =>
              `${upstream.prefix}${upstream.region === undefined ? "" : ` [${upstream.region}]`} → ${upstream.baseUrl}`,
          )
          .join(", ")}; redaction ${config.redaction.mode}`,
      );
      return yield* Layer.launch(Server.layer(config));
    }),
  ),
);

Command.run(gateway, { version: "0.0.0" }).pipe(
  Effect.provide(NodeServices.layer),
  NodeRuntime.runMain,
);
