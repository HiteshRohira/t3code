import * as NodeAssert from "node:assert/strict";

import { describe, it } from "vite-plus/test";

import {
  codexAppServerArgs,
  codexExecLaunchArgs,
  resolveCodexLaunchArgs,
} from "./codexLaunchArgs.ts";

describe("codexAppServerArgs", () => {
  it("preserves escaped TOML quotes in config values", () => {
    NodeAssert.deepStrictEqual(
      codexAppServerArgs(String.raw`--config model=\"gpt-6.1-sol\" --strict-config`),
      ["app-server", "--config", 'model="gpt-6.1-sol"', "--strict-config"],
    );
  });
});

describe("codexExecLaunchArgs", () => {
  it("keeps shared codex flags and omits app-server-only flags", () => {
    NodeAssert.deepStrictEqual(
      codexExecLaunchArgs('--strict-config --enable foo --listen off --config model="gpt 5"'),
      ["--strict-config", "--enable", "foo", "--config", "model=gpt 5"],
    );
  });

  it("does not pair value-taking flags with adjacent flags", () => {
    NodeAssert.deepStrictEqual(codexExecLaunchArgs("--config --strict-config --enable --disable"), [
      "--strict-config",
    ]);
  });
});

describe("resolveCodexLaunchArgs", () => {
  it("routes Codex to a loopback enterprise gateway ahead of the user's own arguments", () => {
    NodeAssert.deepStrictEqual(
      codexAppServerArgs(
        resolveCodexLaunchArgs("--enable foo", {
          T3E_CODEX_GATEWAY_URL: "http://127.0.0.1:4100/openai/v1",
        }),
      ),
      [
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
      ],
    );
  });

  it("ignores a gateway URL that is not loopback or would smuggle extra arguments", () => {
    for (const url of [
      "https://evil.example/v1",
      "http://127.0.0.1:1/v1 --dangerously-bypass-approvals-and-sandbox",
      "not a url",
    ]) {
      NodeAssert.strictEqual(resolveCodexLaunchArgs("", { T3E_CODEX_GATEWAY_URL: url }), "");
    }
  });
});
