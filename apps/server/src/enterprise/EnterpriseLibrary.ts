/**
 * EnterpriseLibrary - installs the org library where Claude Code and Codex look: skills and
 * prompts as namespaced files, instructions and Codex MCP servers in marked blocks of the user's
 * files. It changes only files it created and text between its own markers.
 */
import {
  LibraryResponse,
  paths as wirePaths,
  type LibraryItem,
} from "@t3tools/enterprise-protocol/wire";
import * as HostProcess from "@t3tools/shared/HostProcess";
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Path from "effect/Path";
import * as Schema from "effect/Schema";

import * as EnterpriseAgent from "./EnterpriseAgent.ts";
import * as EnterpriseDevice from "./EnterpriseDevice.ts";

const decodeLibrary = Schema.decodeUnknownOption(LibraryResponse);
const Manifest = Schema.fromJsonString(Schema.Array(Schema.String));
const decodeManifest = Schema.decodeUnknownOption(Manifest);
const encodeManifest = Schema.encodeEffect(Manifest);
const McpEntry = Schema.fromJsonString(
  Schema.Struct({
    command: Schema.optional(Schema.String),
    args: Schema.optional(Schema.Array(Schema.String)),
    env: Schema.optional(Schema.Record(Schema.String, Schema.String)),
    url: Schema.optional(Schema.String),
  }),
);
const decodeMcpEntry = Schema.decodeUnknownOption(McpEntry);

const slug = (organization: string) =>
  organization
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 24) || "org";

const quote = (value: string) => JSON.stringify(value);

const withFrontmatter = (name: string, description: string, content: string) =>
  content.trimStart().startsWith("---")
    ? content
    : `---\nname: ${name}\ndescription: ${quote(description || name)}\n---\n\n${content}`;

/** A marked block in a file the user also edits; `body` null removes it. */
export function replaceManagedBlock(
  existing: string,
  markers: { readonly begin: string; readonly end: string },
  body: string | null,
): string {
  const start = existing.indexOf(markers.begin);
  const stop = start === -1 ? -1 : existing.indexOf(markers.end, start);
  const without =
    start === -1 || stop === -1
      ? existing
      : `${existing.slice(0, start).replace(/\n+$/, "")}${existing.slice(stop + markers.end.length).replace(/^\n+/, existing.slice(0, start).trim() === "" ? "" : "\n\n")}`;
  if (body === null) return without.trim() === "" ? "" : `${without.replace(/\n+$/, "")}\n`;
  const block = `${markers.begin}\n${body.trim()}\n${markers.end}\n`;
  return without.trim() === "" ? block : `${without.replace(/\n+$/, "")}\n\n${block}`;
}

export interface LibraryPlan {
  /** Whole files this module owns, by absolute path. */
  readonly files: ReadonlyMap<string, string>;
  readonly instructions: string | null;
  readonly codexMcp: string | null;
}

export function planLibrary(
  items: ReadonlyArray<LibraryItem>,
  options: {
    readonly home: string;
    readonly organization: string;
    readonly join: (...parts: ReadonlyArray<string>) => string;
  },
): LibraryPlan {
  const prefix = slug(options.organization);
  const files = new Map<string, string>();
  const instructions: Array<string> = [];
  const mcp: Array<string> = [];
  for (const item of items) {
    const name = `${prefix}-${item.name}`;
    switch (item.kind) {
      case "skill": {
        const body = withFrontmatter(name, item.description, item.content);
        files.set(options.join(options.home, ".claude", "skills", name, "SKILL.md"), body);
        files.set(options.join(options.home, ".codex", "skills", name, "SKILL.md"), body);
        break;
      }
      case "prompt": {
        const body = item.description
          ? `---\ndescription: ${quote(item.description)}\n---\n\n${item.content}`
          : item.content;
        files.set(options.join(options.home, ".claude", "commands", `${name}.md`), body);
        files.set(options.join(options.home, ".codex", "prompts", `${name}.md`), body);
        break;
      }
      case "instructions":
        instructions.push(`## ${item.name}\n\n${item.content.trim()}`);
        break;
      case "mcp-server": {
        const entry = decodeMcpEntry(item.content);
        if (Option.isNone(entry)) break;
        const lines = [`[mcp_servers.${quote(name)}]`];
        if (entry.value.command !== undefined)
          lines.push(`command = ${quote(entry.value.command)}`);
        if (entry.value.args !== undefined) {
          lines.push(`args = [${entry.value.args.map(quote).join(", ")}]`);
        }
        if (entry.value.url !== undefined) lines.push(`url = ${quote(entry.value.url)}`);
        if (entry.value.env !== undefined) {
          lines.push(
            `env = { ${Object.entries(entry.value.env)
              .map(([key, value]) => `${quote(key)} = ${quote(value)}`)
              .join(", ")} }`,
          );
        }
        mcp.push(lines.join("\n"));
        break;
      }
    }
  }
  return {
    files,
    instructions:
      instructions.length === 0
        ? null
        : `# ${options.organization} guidelines\n\nFrom your organization; T3 Code keeps this section in sync.\n\n${instructions.join("\n\n")}`,
    codexMcp: mcp.length === 0 ? null : mcp.join("\n\n"),
  };
}

const markdownMarkers = (organization: string) => ({
  begin: `<!-- BEGIN t3-enterprise: ${slug(organization)} (managed by T3 Code; edits here are replaced) -->`,
  end: `<!-- END t3-enterprise: ${slug(organization)} -->`,
});
const tomlMarkers = (organization: string) => ({
  begin: `# BEGIN t3-enterprise: ${slug(organization)} (managed by T3 Code; edits here are replaced)`,
  end: `# END t3-enterprise: ${slug(organization)}`,
});

/** Writes `plan`, removes what an earlier sync installed that the plan no longer has. */
const install = Effect.fn("EnterpriseLibrary.install")(function* (
  plan: LibraryPlan,
  organization: string,
) {
  const fs = yield* FileSystem.FileSystem;
  const path = yield* Path.Path;
  const home = yield* HostProcess.HomeDirectory;
  const paths = yield* EnterpriseDevice.statePaths;
  const manifestPath = path.join(paths.dir, "library-manifest.json");

  const previous = (yield* EnterpriseDevice.readText(manifestPath)).pipe(
    Option.flatMap(decodeManifest),
    Option.getOrElse((): ReadonlyArray<string> => []),
  );
  for (const file of previous) {
    if (plan.files.has(file)) continue;
    yield* fs.remove(file).pipe(Effect.ignore);
    // Skills live in their own directory; drop it once its SKILL.md is gone.
    if (path.basename(file) === "SKILL.md")
      yield* fs.remove(path.dirname(file)).pipe(Effect.ignore);
  }
  for (const [file, content] of plan.files) {
    yield* fs.makeDirectory(path.dirname(file), { recursive: true });
    yield* EnterpriseDevice.writeTextAtomically(file, content);
  }

  const updateBlock = Effect.fn("EnterpriseLibrary.updateBlock")(function* (
    file: string,
    markers: { begin: string; end: string },
    body: string | null,
  ) {
    const existing = Option.getOrElse(yield* EnterpriseDevice.readText(file), () => "");
    const next = replaceManagedBlock(existing, markers, body);
    if (next === existing) return;
    yield* fs.makeDirectory(path.dirname(file), { recursive: true });
    yield* EnterpriseDevice.writeTextAtomically(file, next);
  });
  yield* updateBlock(
    path.join(home, ".claude", "CLAUDE.md"),
    markdownMarkers(organization),
    plan.instructions,
  );
  yield* updateBlock(
    path.join(home, ".codex", "AGENTS.md"),
    markdownMarkers(organization),
    plan.instructions,
  );
  yield* updateBlock(
    path.join(home, ".codex", "config.toml"),
    tomlMarkers(organization),
    plan.codexMcp,
  );
  yield* EnterpriseDevice.writeTextAtomically(
    manifestPath,
    yield* encodeManifest([...plan.files.keys()]),
  );
});

/** Removes everything the library installed, as unenrolling does. */
export const uninstall = (organization: string) =>
  install({ files: new Map(), instructions: null, codexMcp: null }, organization);

const make = Effect.gen(function* () {
  const agent = yield* EnterpriseAgent.EnterpriseAgent;
  const loaded = agent.config;
  if (loaded === undefined) return;
  const organization = loaded.document.organization;
  const path = yield* Path.Path;
  const home = yield* HostProcess.HomeDirectory;

  const sync = Effect.gen(function* () {
    const reply = yield* agent.call(wirePaths.library);
    if (Option.isNone(reply) || reply.value.status !== 200) return;
    const library = decodeLibrary(reply.value.body);
    if (Option.isNone(library)) return;
    yield* install(
      planLibrary(library.value.items, {
        home,
        organization,
        join: (...parts) => path.join(...parts),
      }),
      organization,
    );
  }).pipe(
    Effect.catchCause((cause) => Effect.logWarning("Enterprise library sync failed.", { cause })),
    Effect.withSpan("EnterpriseLibrary.sync"),
  );

  yield* sync.pipe(
    Effect.delay(Duration.seconds(10)),
    Effect.andThen(Effect.sleep(Duration.seconds(loaded.document.policyRefreshSeconds ?? 900))),
    Effect.forever,
    Effect.forkScoped,
  );
});

export const layer = Layer.effectDiscard(make);
