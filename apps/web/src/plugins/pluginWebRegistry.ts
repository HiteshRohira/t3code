/**
 * Experimental: loads the web entrypoints of active plugin packages and keeps the panels they
 * register. Packages are trusted local code, so a module runs in the app itself.
 */
import type { PluginWebEntrypoint } from "@t3tools/contracts";
import { isMacPlatform } from "@t3tools/shared/keybindings";
import { create } from "zustand";

export interface PluginPanelContext {
  readonly environmentId: string;
  readonly threadId: string;
  /** Stable key for the thread this panel is shown in. */
  readonly threadKey: string;
  /** Small string storage kept on this device, namespaced to the package. */
  readonly storage: {
    readonly get: (key: string) => string | null;
    readonly set: (key: string, value: string) => void;
    readonly remove: (key: string) => void;
  };
}

export interface PluginPanelDefinition {
  /** Must be listed in the manifest's `contributes.views`. */
  readonly id: string;
  readonly title: string;
  /** For example "mod+alt+s". `mod` is Cmd on macOS and Ctrl elsewhere. */
  readonly shortcut?: string;
  readonly render: (
    container: HTMLElement,
    context: PluginPanelContext,
  ) => void | (() => void) | Promise<void | (() => void)>;
}

export interface PluginWebApi {
  readonly id: string;
  readonly registerPanel: (panel: PluginPanelDefinition) => void;
  readonly onDispose: (cleanup: () => void) => void;
}

export interface RegisteredPluginPanel extends PluginPanelDefinition {
  readonly pluginId: string;
}

interface PluginPanelStore {
  readonly panels: Readonly<Record<string, RegisteredPluginPanel>>;
}

export const usePluginPanelStore = create<PluginPanelStore>(() => ({ panels: {} }));

export const pluginPanelKey = (pluginId: string, panelId: string) => `${pluginId}/${panelId}`;

interface LoadedEntrypoint {
  readonly key: string;
  readonly dispose: () => void;
}

const loaded = new Map<string, LoadedEntrypoint>();

const entrypointKey = (entrypoint: PluginWebEntrypoint) =>
  `${entrypoint.id}:${entrypoint.generation}`;

function storageFor(pluginId: string): PluginPanelContext["storage"] {
  const prefix = `t3code:extension:${pluginId}:`;
  return {
    get: (key) => globalThis.localStorage?.getItem(prefix + key) ?? null,
    set: (key, value) => globalThis.localStorage?.setItem(prefix + key, value),
    remove: (key) => globalThis.localStorage?.removeItem(prefix + key),
  };
}

export const pluginPanelStorage = storageFor;

async function activateEntrypoint(entrypoint: PluginWebEntrypoint): Promise<() => void> {
  const declaredViews = new Set(entrypoint.views);
  const cleanups: Array<() => void> = [];
  const panelKeys: string[] = [];
  const dispose = () => {
    usePluginPanelStore.setState((state) => {
      const panels = { ...state.panels };
      for (const key of panelKeys) delete panels[key];
      return { panels };
    });
    for (const cleanup of [...cleanups].reverse()) {
      try {
        cleanup();
      } catch (error) {
        console.error(`Extension ${entrypoint.id} failed to clean up`, error);
      }
    }
  };
  const api: PluginWebApi = {
    id: entrypoint.id,
    registerPanel(panel) {
      if (!declaredViews.has(panel.id)) {
        throw new Error(`View ${panel.id} is not declared in the manifest`);
      }
      const key = pluginPanelKey(entrypoint.id, panel.id);
      panelKeys.push(key);
      usePluginPanelStore.setState((state) => ({
        panels: { ...state.panels, [key]: { ...panel, pluginId: entrypoint.id } },
      }));
    },
    onDispose(cleanup) {
      cleanups.push(cleanup);
    },
  };

  const url = URL.createObjectURL(new Blob([entrypoint.source], { type: "text/javascript" }));
  try {
    const module = (await import(/* @vite-ignore */ url)) as { default?: unknown };
    if (typeof module.default !== "function") {
      throw new Error("web entrypoint must export a default activation function");
    }
    await (module.default as (api: PluginWebApi) => unknown)(api);
  } catch (error) {
    dispose();
    throw error;
  } finally {
    URL.revokeObjectURL(url);
  }
  return dispose;
}

let reconcileQueue: Promise<void> = Promise.resolve();

/** Brings loaded modules in line with the server's list: new generations replace old ones. */
export function reconcilePluginWebEntrypoints(
  entrypoints: ReadonlyArray<PluginWebEntrypoint>,
): Promise<void> {
  reconcileQueue = reconcileQueue.then(async () => {
    const wanted = new Map(entrypoints.map((entrypoint) => [entrypoint.id, entrypoint]));
    for (const [id, current] of loaded) {
      const next = wanted.get(id);
      if (next !== undefined && entrypointKey(next) === current.key) continue;
      loaded.delete(id);
      current.dispose();
    }
    for (const entrypoint of wanted.values()) {
      if (loaded.has(entrypoint.id)) continue;
      try {
        const dispose = await activateEntrypoint(entrypoint);
        loaded.set(entrypoint.id, { key: entrypointKey(entrypoint), dispose });
      } catch (error) {
        console.error(`Extension ${entrypoint.id} failed to load its web entrypoint`, error);
      }
    }
  });
  return reconcileQueue;
}

interface ParsedShortcut {
  readonly mod: boolean;
  readonly shift: boolean;
  readonly alt: boolean;
  readonly ctrl: boolean;
  readonly key: string;
}

export function parsePluginShortcut(shortcut: string): ParsedShortcut | null {
  const parts = shortcut.toLowerCase().split("+");
  const key = parts.pop();
  if (!key) return null;
  const modifiers = new Set(parts);
  for (const modifier of modifiers) {
    if (!["mod", "shift", "alt", "ctrl"].includes(modifier)) return null;
  }
  return {
    mod: modifiers.has("mod"),
    shift: modifiers.has("shift"),
    alt: modifiers.has("alt"),
    ctrl: modifiers.has("ctrl"),
    key,
  };
}

function eventKey(event: KeyboardEvent): string {
  // Option changes event.key on macOS, so letters and digits come from the physical key.
  if (event.code.startsWith("Key")) return event.code.slice(3).toLowerCase();
  if (event.code.startsWith("Digit")) return event.code.slice(5);
  return event.key.toLowerCase();
}

export function matchesPluginShortcut(
  shortcut: ParsedShortcut,
  event: KeyboardEvent,
  platform: string,
): boolean {
  const mac = isMacPlatform(platform);
  const wantMeta = shortcut.mod && mac;
  const wantCtrl = shortcut.ctrl || (shortcut.mod && !mac);
  return (
    event.metaKey === wantMeta &&
    event.ctrlKey === wantCtrl &&
    event.shiftKey === shortcut.shift &&
    event.altKey === shortcut.alt &&
    eventKey(event) === shortcut.key
  );
}

export function formatPluginShortcut(shortcut: string, platform: string): string {
  const parsed = parsePluginShortcut(shortcut);
  if (parsed === null) return shortcut;
  const mac = isMacPlatform(platform);
  const parts: string[] = [];
  if (parsed.ctrl || (parsed.mod && !mac)) parts.push(mac ? "⌃" : "Ctrl");
  if (parsed.alt) parts.push(mac ? "⌥" : "Alt");
  if (parsed.shift) parts.push(mac ? "⇧" : "Shift");
  if (parsed.mod && mac) parts.push("⌘");
  parts.push(parsed.key.length === 1 ? parsed.key.toUpperCase() : parsed.key);
  return mac ? parts.join("") : parts.join("+");
}
