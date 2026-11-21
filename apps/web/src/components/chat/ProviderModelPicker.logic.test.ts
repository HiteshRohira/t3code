import {
  ProviderDriverKind,
  ProviderInstanceId,
  type ModelSelection,
  type ServerProvider,
} from "@t3tools/contracts";
import { describe, expect, it } from "vite-plus/test";

import { deriveProviderInstanceEntries } from "../../providerInstances";
import {
  lastUsedModelCandidates,
  retainedModelWhileProviderLocked,
} from "./ProviderModelPicker.logic";

const claude = ProviderDriverKind.make("claudeAgent");
const opus = { slug: "claude-opus-5-5", name: "Claude Opus 5.5", shortName: "Opus 5.5" };
const sonnet = { slug: "claude-sonnet-5-5", name: "Claude Sonnet 5.5", shortName: "Sonnet 5.5" };
const retained = (enabled: boolean, isAvailable: boolean, models = [sonnet, opus]) =>
  retainedModelWhileProviderLocked({ driverKind: claude, enabled, isAvailable, models }, opus.slug);

describe("retainedModelWhileProviderLocked", () => {
  it("shows a hidden saved model while its provider cannot run", () => {
    expect(retained(false, true)).toBe(opus);
    expect(retained(true, false)).toBe(opus);
    expect(retained(false, true, [sonnet])).toEqual({ slug: opus.slug, name: opus.slug });
    expect(retained(true, true)).toBeUndefined();
    expect(retainedModelWhileProviderLocked(null, opus.slug)).toBeUndefined();
  });
});

function claudeProvider(instanceId: string, groupKey: string, enabled = true): ServerProvider {
  return {
    instanceId: ProviderInstanceId.make(instanceId),
    driver: claude,
    continuation: { groupKey },
    enabled,
    installed: true,
    version: null,
    status: "ready",
    auth: { status: "authenticated" },
    checkedAt: "2026-11-20T12:00:00.000Z",
    models: [],
    slashCommands: [],
    skills: [],
  };
}

describe("lastUsedModelCandidates", () => {
  const home = ProviderInstanceId.make("claude_home");
  const work = ProviderInstanceId.make("claude_work");
  const off = ProviderInstanceId.make("claude_off");
  const pick = (instanceId: ProviderInstanceId, model: string): ModelSelection => ({
    instanceId,
    model,
  });
  const candidates = (
    picks: ReadonlyArray<ModelSelection>,
    overrides: {
      current?: ModelSelection;
      lockedContinuationGroupKey?: string;
      disabledModel?: string;
    } = {},
  ) =>
    lastUsedModelCandidates({
      picks,
      current: overrides.current ?? pick(home, opus.slug),
      entries: deriveProviderInstanceEntries([
        claudeProvider(home, "home"),
        claudeProvider(work, "work"),
        claudeProvider(off, "home", false),
      ]),
      optionsByInstance: new Map([
        [home, [{ ...opus, aliases: ["opus"] }, sonnet]],
        [work, [opus, sonnet, { slug: "claude-haiku-5-5", name: "Haiku", isUnavailable: true }]],
        [off, [opus, sonnet]],
      ]),
      lockedProvider: overrides.lockedContinuationGroupKey ? claude : null,
      lockedContinuationGroupKey: overrides.lockedContinuationGroupKey,
      getModelDisabledReason: (_instanceId, model) =>
        model === overrides.disabledModel ? "blocked" : null,
    });

  it("offers only recent picks the picker would let you choose", () => {
    expect(candidates([pick(home, sonnet.slug), pick(home, opus.slug)])).toEqual([
      pick(home, sonnet.slug),
    ]);
    // An alias of the shown model is the shown model, so the older pick wins.
    expect(candidates([pick(home, "opus"), pick(work, sonnet.slug)])).toEqual([
      pick(work, sonnet.slug),
    ]);
    // Hidden, unavailable, and turned-off picks fall through instead of resolving elsewhere.
    expect(
      candidates([
        pick(home, "claude-retired"),
        pick(work, "claude-haiku-5-5"),
        pick(off, sonnet.slug),
      ]),
    ).toEqual([]);
    expect(
      candidates([pick(work, sonnet.slug), pick(home, sonnet.slug)], {
        lockedContinuationGroupKey: "home",
      }),
    ).toEqual([pick(home, sonnet.slug)]);
    expect(candidates([pick(home, sonnet.slug)], { disabledModel: sonnet.slug })).toEqual([]);
  });
});
