import type { LibraryItem } from "@t3tools/enterprise-protocol/wire";
import { describe, expect, it } from "vite-plus/test";

import { planLibrary, replaceManagedBlock } from "./EnterpriseLibrary.ts";

const markers = { begin: "<!-- BEGIN org -->", end: "<!-- END org -->" };

describe("replaceManagedBlock", () => {
  it("adds, replaces, and removes its block without touching the user's text", () => {
    const user = "# My notes\n\nUse tabs.\n";
    const added = replaceManagedBlock(user, markers, "Org rule one.");
    expect(added).toBe(
      "# My notes\n\nUse tabs.\n\n<!-- BEGIN org -->\nOrg rule one.\n<!-- END org -->\n",
    );

    const edited = `${added}\nMore of my notes.\n`;
    const replaced = replaceManagedBlock(edited, markers, "Org rule two.");
    expect(replaced).toContain("Use tabs.");
    expect(replaced).toContain("More of my notes.");
    expect(replaced).toContain("Org rule two.");
    expect(replaced).not.toContain("Org rule one.");

    const removed = replaceManagedBlock(replaced, markers, null);
    expect(removed).not.toContain("BEGIN org");
    expect(removed).toContain("Use tabs.");
    expect(removed).toContain("More of my notes.");
  });

  it("leaves an empty file empty once the block is gone", () => {
    expect(replaceManagedBlock(replaceManagedBlock("", markers, "x"), markers, null)).toBe("");
  });
});

const item = (overrides: Partial<LibraryItem>): LibraryItem => ({
  id: "1",
  kind: "skill",
  name: "deploy",
  description: "Ship to production",
  content: "Run the checklist.",
  team: null,
  updatedAt: "2026-11-20T00:00:00.000Z",
  ...overrides,
});

describe("planLibrary", () => {
  const plan = (items: ReadonlyArray<LibraryItem>) =>
    planLibrary(items, {
      home: "/home/dev",
      organization: "Example Corp",
      join: (...parts) => parts.join("/"),
    });

  it("namespaces skills and prompts for both Claude Code and Codex", () => {
    const { files } = plan([
      item({}),
      item({ kind: "prompt", name: "review", content: "Review it." }),
    ]);
    expect([...files.keys()]).toEqual([
      "/home/dev/.claude/skills/example-corp-deploy/SKILL.md",
      "/home/dev/.codex/skills/example-corp-deploy/SKILL.md",
      "/home/dev/.claude/commands/example-corp-review.md",
      "/home/dev/.codex/prompts/example-corp-review.md",
    ]);
    expect(files.get("/home/dev/.claude/skills/example-corp-deploy/SKILL.md")).toContain(
      'name: example-corp-deploy\ndescription: "Ship to production"',
    );
  });

  it("writes Codex MCP servers as TOML tables and skips entries it cannot read", () => {
    const { codexMcp } = plan([
      item({
        kind: "mcp-server",
        name: "tickets",
        content: JSON.stringify({
          command: "npx",
          args: ["-y", "tickets-mcp"],
          env: { TOKEN: "$T" },
        }),
      }),
      item({ kind: "mcp-server", name: "broken", content: "not json" }),
    ]);
    expect(codexMcp).toBe(
      '[mcp_servers."example-corp-tickets"]\ncommand = "npx"\nargs = ["-y", "tickets-mcp"]\nenv = { "TOKEN" = "$T" }',
    );
  });
});
