import { describe, expect, it } from "vite-plus/test";

import { codexAppServerArgs } from "../provider/codexLaunchArgs.ts";
import { codexGatewayLaunchArgs } from "./EnterpriseAgent.ts";

describe("codexGatewayLaunchArgs", () => {
  it("survives T3's argument tokenizing as Codex provider overrides, keeping the user's", () => {
    expect(codexAppServerArgs(codexGatewayLaunchArgs(4100, "--enable foo"))).toEqual([
      "app-server",
      "-c",
      "model_provider=t3-enterprise",
      "-c",
      "model_providers.t3-enterprise.name=t3-enterprise",
      "-c",
      "model_providers.t3-enterprise.base_url=http://127.0.0.1:4100/openai/v1",
      "-c",
      "model_providers.t3-enterprise.env_key=OPENAI_API_KEY",
      "-c",
      "model_providers.t3-enterprise.wire_api=responses",
      "--enable",
      "foo",
    ]);
  });
});
