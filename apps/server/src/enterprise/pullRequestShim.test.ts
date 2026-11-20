// @effect-diagnostics nodeBuiltinImport:off -- runs the shell shim against a fake gh.
import * as NodeChildProcess from "node:child_process";
import * as NodeFS from "node:fs";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";

import * as HostProcess from "@t3tools/shared/HostProcess";
import { describe, expect, it } from "vite-plus/test";

import { pullRequestShim } from "./pullRequestShim.ts";

const setup = () => {
  const root = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "t3e-gh-"));
  const shimDir = NodePath.join(root, "shim");
  const realDir = NodePath.join(root, "real");
  NodeFS.mkdirSync(shimDir);
  NodeFS.mkdirSync(realDir);
  NodeFS.writeFileSync(NodePath.join(shimDir, "gh"), pullRequestShim("Example Corp"), {
    mode: 0o755,
  });
  NodeFS.writeFileSync(NodePath.join(realDir, "gh"), '#!/bin/sh\necho "real gh $*"\n', {
    mode: 0o755,
  });
  const run = (mode: string, args: ReadonlyArray<string>) =>
    NodeChildProcess.spawnSync(NodePath.join(shimDir, "gh"), args, {
      encoding: "utf8",
      env: { PATH: `${shimDir}:${realDir}:/usr/bin:/bin`, T3E_AGENT_PULL_REQUESTS: mode },
    });
  return { run, [Symbol.dispose]: () => NodeFS.rmSync(root, { recursive: true, force: true }) };
};

// The shim is POSIX sh; Windows machines do not install it.
describe.skipIf(HostProcess.Platform.defaultValue() === "win32")("pull request shim", () => {
  it("opens agents' pull requests as drafts and leaves readiness to people", () => {
    using gh = setup();
    expect(gh.run("draft", ["pr", "create", "--title", "x"]).stdout).toBe(
      "real gh pr create --draft --title x\n",
    );
    expect(gh.run("draft", ["pr", "create", "--draft"]).stdout).toBe("real gh pr create --draft\n");
    const ready = gh.run("draft", ["pr", "ready", "12"]);
    expect(ready.status).toBe(1);
    expect(ready.stderr).toContain("Example Corp's policy leaves marking pull requests ready");
    expect(gh.run("draft", ["issue", "list"]).stdout).toBe("real gh issue list\n");
  });

  it("refuses to open pull requests when only people may", () => {
    using gh = setup();
    const created = gh.run("human-only", ["pr", "create"]);
    expect(created.status).toBe(1);
    expect(created.stderr).toContain("lets only people open pull requests");
    expect(gh.run("allowed", ["pr", "merge", "3"]).stdout).toBe("real gh pr merge 3\n");
  });
});
