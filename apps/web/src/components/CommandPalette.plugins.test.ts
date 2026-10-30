import { describe, expect, it, vi } from "vite-plus/test";
import { EnvironmentId, type PluginCommand } from "@t3tools/contracts";

import {
  buildPluginCommandActionItems,
  resolvePluginCommandEnvironmentId,
} from "./CommandPalette.logic";

describe("buildPluginCommandActionItems", () => {
  it("renders only commands for the current host surface and routes execution", async () => {
    const run = vi.fn(async () => undefined);
    const commands: ReadonlyArray<PluginCommand> = [
      {
        id: "plugin.status",
        label: "Check plugin status",
        description: "Verify the runtime.",
        surfaces: ["web", "desktop"],
      },
      {
        id: "plugin.mobile",
        label: "Mobile only",
        surfaces: ["mobile"],
      },
    ];

    const items = buildPluginCommandActionItems({ commands, icon: null, run, surface: "web" });

    expect(items.map((item) => item.value)).toEqual(["plugin-command:plugin.status"]);
    expect(items[0]?.description).toBe("Verify the runtime.");
    await items[0]?.run();
    expect(run).toHaveBeenCalledWith(commands[0]);
  });
});

describe("resolvePluginCommandEnvironmentId", () => {
  it("prefers an active remote draft over the primary environment", () => {
    expect(
      resolvePluginCommandEnvironmentId({
        activeDraftEnvironmentId: EnvironmentId.make("remote"),
        activeThreadEnvironmentId: null,
        primaryEnvironmentId: EnvironmentId.make("primary"),
      }),
    ).toBe("remote");
  });
});
