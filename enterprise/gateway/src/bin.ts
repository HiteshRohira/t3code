#!/usr/bin/env node
import * as NodeUtil from "node:util";

import { loadConfig } from "./config.ts";
import { startGateway } from "./gateway.ts";

const { values } = NodeUtil.parseArgs({ options: { config: { type: "string" } } });
if (values.config === undefined) {
  console.error("usage: t3-enterprise-gateway --config <file>");
  process.exit(2);
}

try {
  const config = loadConfig(values.config);
  const { gateway, close } = await startGateway(config);
  gateway.startSync();
  console.log(
    `[gateway] listening on ${config.listen.host}:${config.listen.port}; upstreams ${config.upstreams.map((u) => `${u.prefix} → ${u.baseUrl}`).join(", ")}`,
  );
  const stop = () => void close().then(() => process.exit(0));
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
}
