import type { ModelSelection, ProviderDriverKind, ProviderInstanceId } from "@t3tools/contracts";
import { resolveSelectableModel } from "@t3tools/shared/model";

import { isProviderInstancePickerReady, type ProviderInstanceEntry } from "../../providerInstances";
import type { ModelEsque } from "./providerIconUtils";

/** Keeps a hidden model visible while its provider is locked or turned off. */
export function retainedModelWhileProviderLocked(
  entry: {
    readonly driverKind: ProviderDriverKind;
    readonly enabled: boolean;
    readonly isAvailable: boolean;
    readonly models: ReadonlyArray<Pick<ModelEsque, "slug" | "name" | "shortName" | "subProvider">>;
  } | null,
  model: string,
): ModelEsque | undefined {
  if (!entry || (entry.enabled && entry.isAvailable) || !model) return undefined;
  if (entry.driverKind === "opencode" || entry.driverKind === "antigravity") return undefined;
  return entry.models.find((candidate) => candidate.slug === model) ?? { slug: model, name: model };
}

/**
 * Where the picker's toggle chord switches to, best first: recent picks other than the shown model
 * that the picker itself would offer. Resolving through its list skips hidden models and maps aliases.
 */
export function lastUsedModelCandidates(input: {
  readonly picks: ReadonlyArray<ModelSelection>;
  readonly current: ModelSelection;
  readonly entries: ReadonlyArray<ProviderInstanceEntry>;
  readonly optionsByInstance: ReadonlyMap<ProviderInstanceId, ReadonlyArray<ModelEsque>>;
  readonly lockedProvider: ProviderDriverKind | null;
  readonly lockedContinuationGroupKey: string | null | undefined;
  readonly getModelDisabledReason: (instanceId: ProviderInstanceId, model: string) => string | null;
}): ReadonlyArray<{ readonly instanceId: ProviderInstanceId; readonly model: string }> {
  return input.picks.flatMap((pick) => {
    const entry = input.entries.find((candidate) => candidate.instanceId === pick.instanceId);
    if (
      !entry ||
      !isProviderInstancePickerReady(entry) ||
      (input.lockedProvider !== null && entry.driverKind !== input.lockedProvider) ||
      (input.lockedContinuationGroupKey &&
        entry.continuationGroupKey !== input.lockedContinuationGroupKey)
    ) {
      return [];
    }
    const options = input.optionsByInstance.get(entry.instanceId) ?? [];
    const model = resolveSelectableModel(entry.driverKind, pick.model, options);
    if (
      !model ||
      options.find((option) => option.slug === model)?.isUnavailable ||
      (entry.instanceId === input.current.instanceId && model === input.current.model) ||
      input.getModelDisabledReason(entry.instanceId, model) !== null
    ) {
      return [];
    }
    return [{ instanceId: entry.instanceId, model }];
  });
}
