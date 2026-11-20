/**
 * EnterpriseSharing - hands a thread to colleagues through the control plane: its transcript as
 * Markdown and its whole change as a patch. Continuing one writes both to this machine and
 * returns a prompt for a new thread; nothing runs until the user sends it.
 *
 * @module EnterpriseSharing
 */
import {
  EnterpriseActionError,
  ThreadId,
  type EnterpriseContinueSharedThreadResult,
  type EnterpriseSharedThreadSummary,
  type EnterpriseShareThreadInput,
  type OrchestrationV2ThreadTranscript,
} from "@t3tools/contracts";
import {
  SharedThread,
  SharedThreadList,
  paths as wirePaths,
} from "@t3tools/enterprise-protocol/wire";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Path from "effect/Path";
import * as Schema from "effect/Schema";

import * as CheckpointDiffQuery from "../checkpointing/CheckpointDiffQuery.ts";
import * as ServerEnvironment from "../environment/ServerEnvironment.ts";
import * as ThreadManagement from "../orchestration-v2/ThreadManagementService.ts";
import * as RepositoryIdentityResolver from "../project/RepositoryIdentityResolver.ts";
import * as EnterpriseAgent from "./EnterpriseAgent.ts";
import * as EnterpriseDevice from "./EnterpriseDevice.ts";

const MAX_OUTPUT_CHARS = 2000;
const decodeList = Schema.decodeUnknownOption(SharedThreadList);
const decodeShared = Schema.decodeUnknownOption(SharedThread);

const fail = (message: string) => new EnterpriseActionError({ message });

const clip = (text: string, limit: number) =>
  text.length <= limit
    ? text
    : `${text.slice(0, limit)}\n… (${text.length - limit} more characters)`;

/** The parts of a thread a colleague needs to pick it up, as Markdown. */
function transcriptMarkdown(transcript: OrchestrationV2ThreadTranscript): string {
  const sections = [`# ${transcript.title}`];
  for (const { item } of transcript.items) {
    switch (item.type) {
      case "user_message":
        sections.push(`## User\n\n${item.text}`);
        break;
      case "assistant_message":
        if (item.text.trim() !== "") sections.push(`## Assistant\n\n${item.text}`);
        break;
      case "command_execution":
        sections.push(
          `### Command${item.exitCode === undefined ? "" : ` (exit ${item.exitCode})`}\n\n\`\`\`sh\n${item.input}\n\`\`\`${
            item.output === undefined || item.output.trim() === ""
              ? ""
              : `\n\n\`\`\`\n${clip(item.output, MAX_OUTPUT_CHARS)}\n\`\`\``
          }`,
        );
        break;
      case "file_change":
        if (item.changes !== undefined && item.changes.length > 0) {
          sections.push(
            `### Files changed\n\n${item.changes.map((change) => `- ${change.operation} \`${change.path}\``).join("\n")}`,
          );
        }
        break;
    }
  }
  return `${sections.join("\n\n")}\n`;
}

export class EnterpriseSharing extends Context.Service<
  EnterpriseSharing,
  {
    readonly share: (
      input: EnterpriseShareThreadInput,
    ) => Effect.Effect<{ readonly id: string }, EnterpriseActionError>;
    readonly list: Effect.Effect<
      ReadonlyArray<EnterpriseSharedThreadSummary>,
      EnterpriseActionError
    >;
    readonly continueShared: (
      id: string,
    ) => Effect.Effect<EnterpriseContinueSharedThreadResult, EnterpriseActionError>;
  }
>()("t3/enterprise/EnterpriseSharing") {}

const make = Effect.gen(function* () {
  const agent = yield* EnterpriseAgent.EnterpriseAgent;
  const threads = yield* ThreadManagement.ThreadManagementService;
  const diffs = yield* CheckpointDiffQuery.CheckpointDiffQuery;
  const repositories = yield* RepositoryIdentityResolver.RepositoryIdentityResolver;
  const identity = yield* ServerEnvironment.ServerEnvironmentIdentity;
  const fs = yield* FileSystem.FileSystem;
  const path = yield* Path.Path;

  const call = (pathname: string, options?: { method?: string; body?: unknown }) =>
    agent.call(pathname, options).pipe(
      Effect.mapError(() => fail("Cannot reach your organization. Try again when you are online.")),
      Effect.flatMap((reply) =>
        Effect.fromOption(reply).pipe(
          Effect.mapError(() => fail("Enroll this computer with your organization first.")),
        ),
      ),
    );

  const refused = (status: number, body: unknown) => {
    const message =
      typeof body === "object" &&
      body !== null &&
      typeof (body as { message?: unknown }).message === "string"
        ? (body as { message: string }).message
        : `status ${status}`;
    return fail(`Your organization refused: ${message}.`);
  };

  return EnterpriseSharing.of({
    share: Effect.fn("EnterpriseSharing.share")(function* (input) {
      const threadId = ThreadId.make(input.threadId);
      const shell = yield* threads
        .getThreadShell(threadId)
        .pipe(Effect.mapError(() => fail("This thread cannot be read.")));
      if (shell === null) return yield* fail("This thread no longer exists.");
      const transcript = yield* threads.getThreadTranscript(threadId).pipe(
        Effect.provideService(ServerEnvironment.ServerEnvironmentIdentity, identity),
        Effect.mapError(() => fail("This thread is too large to share.")),
      );
      const context = yield* threads
        .getCheckpointContext(threadId)
        .pipe(Effect.mapError(() => fail("This thread's changes cannot be read.")));
      const turns = Math.max(
        0,
        ...context.checkpoints.map((checkpoint) => checkpoint.appRunOrdinal ?? 0),
      );
      const patch =
        turns === 0
          ? ""
          : yield* diffs
              .getFullThreadDiff({ threadId, toTurnCount: turns, ignoreWhitespace: false })
              .pipe(
                Effect.map((result) => result.diff),
                Effect.orElseSucceed(() => ""),
              );
      const cwd = shell.worktreePath ?? context.checkpointScopes[0]?.cwd;
      const repository = cwd === undefined ? null : yield* repositories.resolve(cwd);
      const reply = yield* call(wirePaths.sharedThreads, {
        method: "POST",
        body: {
          title: shell.title.slice(0, 200) || "Untitled thread",
          repository: repository?.origin?.remoteUrl ?? repository?.canonicalKey ?? null,
          branch: shell.branch,
          provider: shell.providerInstanceId,
          transcript: transcriptMarkdown(transcript),
          patch,
          audience: input.audience,
          note: input.note,
        },
      });
      if (reply.status !== 201) return yield* refused(reply.status, reply.body);
      return { id: String((reply.body as { id?: unknown }).id) };
    }),

    list: Effect.gen(function* () {
      const reply = yield* call(wirePaths.sharedThreads);
      if (reply.status !== 200) return yield* refused(reply.status, reply.body);
      return Option.match(decodeList(reply.body), {
        onNone: () => [],
        onSome: (list) => list.threads,
      });
    }).pipe(Effect.withSpan("EnterpriseSharing.list")),

    continueShared: Effect.fn("EnterpriseSharing.continueShared")(function* (id) {
      const reply = yield* call(`${wirePaths.sharedThreads}/${encodeURIComponent(id)}`);
      if (reply.status !== 200) return yield* refused(reply.status, reply.body);
      const shared = Option.getOrUndefined(decodeShared(reply.body));
      if (shared === undefined) return yield* fail("The shared thread arrived damaged.");
      const paths = yield* EnterpriseDevice.statePaths.pipe(Effect.provideService(Path.Path, path));
      const dir = path.join(paths.dir, "handoffs", shared.id.replace(/[^a-zA-Z0-9-]/g, ""));
      const transcriptPath = path.join(dir, "transcript.md");
      const patchPath = path.join(dir, "changes.patch");
      yield* fs.makeDirectory(dir, { recursive: true }).pipe(
        Effect.andThen(fs.writeFileString(transcriptPath, shared.transcript)),
        Effect.andThen(fs.writeFileString(patchPath, shared.patch)),
        Effect.mapError(() => fail("Cannot save the shared thread on this computer.")),
      );
      const ownerName = /[:/]([^/:]+)\/([^/]+?)(?:\.git)?$/.exec(shared.repository ?? "");
      const lines = [
        `Continue work ${shared.sharedBy} handed off: "${shared.title}".`,
        `Read the transcript at ${transcriptPath}.`,
        shared.patch.trim() === ""
          ? "It made no file changes yet."
          : `Apply their changes with \`git apply ${patchPath}\`${shared.branch === null ? "" : ` (they worked on branch ${shared.branch})`}, then check the result.`,
        ...(shared.note.trim() === "" ? [] : [`Their note: ${shared.note.trim()}`]),
        "Then continue from where they stopped.",
      ];
      return {
        prompt: lines.join("\n"),
        repository: ownerName === null ? null : `${ownerName[1]}/${ownerName[2]}`,
        provider: shared.provider,
      };
    }),
  });
});

export const layer = Layer.effect(EnterpriseSharing, make);
