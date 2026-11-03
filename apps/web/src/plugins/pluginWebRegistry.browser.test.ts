import { expect, it } from "vite-plus/test";

import {
  formatPluginShortcut,
  matchesPluginShortcut,
  parsePluginShortcut,
  pluginPanelKey,
  reconcilePluginWebEntrypoints,
  usePluginPanelStore,
} from "./pluginWebRegistry";

const keydown = (init: KeyboardEventInit) => new KeyboardEvent("keydown", init);

it("parses shortcuts and rejects unknown modifiers", () => {
  expect(parsePluginShortcut("mod+alt+s")).toEqual({
    mod: true,
    shift: false,
    alt: true,
    ctrl: false,
    key: "s",
  });
  expect(parsePluginShortcut("hyper+s")).toBeNull();
  expect(parsePluginShortcut("")).toBeNull();
});

it("matches mod to Cmd on macOS and Ctrl elsewhere, using the physical key", () => {
  const shortcut = parsePluginShortcut("mod+alt+s")!;
  // Option+S types "ß" on macOS; the physical key still matches.
  const mac = keydown({ key: "ß", code: "KeyS", metaKey: true, altKey: true });
  expect(matchesPluginShortcut(shortcut, mac, "MacIntel")).toBe(true);
  expect(matchesPluginShortcut(shortcut, mac, "Win32")).toBe(false);
  const windows = keydown({ key: "s", code: "KeyS", ctrlKey: true, altKey: true });
  expect(matchesPluginShortcut(shortcut, windows, "Win32")).toBe(true);
  const extraShift = keydown({
    key: "S",
    code: "KeyS",
    metaKey: true,
    altKey: true,
    shiftKey: true,
  });
  expect(matchesPluginShortcut(shortcut, extraShift, "MacIntel")).toBe(false);
});

it("formats shortcuts per platform", () => {
  expect(formatPluginShortcut("mod+alt+s", "MacIntel")).toBe("⌥⌘S");
  expect(formatPluginShortcut("mod+alt+s", "Win32")).toBe("Ctrl+Alt+S");
});

const entrypoint = (generation: string, source: string) => ({
  id: "com.acme.notes",
  version: "0.1.0",
  generation,
  views: ["com.acme.notes.panel"],
  source,
});

const panelSource = (title: string) => `
export default function activate(api) {
  api.registerPanel({ id: "com.acme.notes.panel", title: ${JSON.stringify(title)}, render() {} });
}
`;

it("registers declared panels and replaces them on a new generation", async () => {
  const key = pluginPanelKey("com.acme.notes", "com.acme.notes.panel");
  await reconcilePluginWebEntrypoints([entrypoint("0", panelSource("Notes"))]);
  expect(usePluginPanelStore.getState().panels[key]?.title).toBe("Notes");

  await reconcilePluginWebEntrypoints([entrypoint("1", panelSource("Notes v2"))]);
  expect(usePluginPanelStore.getState().panels[key]?.title).toBe("Notes v2");

  await reconcilePluginWebEntrypoints([]);
  expect(usePluginPanelStore.getState().panels[key]).toBeUndefined();
});

it("rejects panels the manifest does not declare", async () => {
  const source = `export default function activate(api) {
    api.registerPanel({ id: "com.acme.notes.other", title: "Other", render() {} });
  }`;
  await reconcilePluginWebEntrypoints([entrypoint("2", source)]);
  expect(usePluginPanelStore.getState().panels).toEqual({});
  await reconcilePluginWebEntrypoints([]);
});
