/**
 * Experimental: React side of the plugin web host. Loads web entrypoints for the primary
 * environment, renders extension panels, and handles their shortcuts.
 */
import { scopedThreadKey } from "@t3tools/client-runtime/environment";
import type { ScopedThreadRef } from "@t3tools/contracts";
import { PuzzleIcon } from "lucide-react";
import { useEffect, useRef } from "react";

import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "../components/ui/empty";
import { useRightPanelStore } from "../rightPanelStore";
import { usePrimaryEnvironmentId } from "../state/environments";
import { useEnvironmentQuery } from "../state/query";
import { serverEnvironment } from "../state/server";
import {
  matchesPluginShortcut,
  parsePluginShortcut,
  pluginPanelKey,
  pluginPanelStorage,
  reconcilePluginWebEntrypoints,
  usePluginPanelStore,
} from "./pluginWebRegistry";

const refreshListeners = new Set<() => void>();

/** Asks the host to fetch the web entrypoint list again, e.g. after enabling a package. */
export function refreshPluginWebEntrypoints() {
  for (const listener of refreshListeners) listener();
}

export function PluginWebHost() {
  const environmentId = usePrimaryEnvironmentId();
  const query = useEnvironmentQuery(
    environmentId === null
      ? null
      : serverEnvironment.pluginWebEntrypoints({ environmentId, input: {} }),
  );
  const { refresh } = query;
  const entrypoints = query.data?.entrypoints;

  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- registers this query in the module refresh registry while mounted.
  useEffect(() => {
    refreshListeners.add(refresh);
    return () => {
      refreshListeners.delete(refresh);
    };
  }, [refresh]);

  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- keeps loaded extension modules in step with the server list.
  useEffect(() => {
    if (entrypoints !== undefined) void reconcilePluginWebEntrypoints(entrypoints);
  }, [entrypoints]);

  return null;
}

/** Toggles an extension panel in the active thread's right panel when its shortcut is pressed. */
export function usePluginPanelShortcuts(threadRef: ScopedThreadRef | null, enabled: boolean) {
  const panels = usePluginPanelStore((state) => state.panels);

  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- holds a window keydown listener for extension shortcuts.
  useEffect(() => {
    if (!enabled || threadRef === null) return;
    const bindings = Object.values(panels).flatMap((panel) => {
      const parsed = panel.shortcut ? parsePluginShortcut(panel.shortcut) : null;
      return parsed === null ? [] : [{ panel, parsed }];
    });
    if (bindings.length === 0) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.defaultPrevented || event.repeat) return;
      const match = bindings.find(({ parsed }) =>
        matchesPluginShortcut(parsed, event, navigator.platform),
      );
      if (match === undefined) return;
      event.preventDefault();
      event.stopPropagation();
      useRightPanelStore
        .getState()
        .toggleExtensionPanel(threadRef, match.panel.pluginId, match.panel.id);
    };
    window.addEventListener("keydown", onKeyDown, { capture: true });
    return () => window.removeEventListener("keydown", onKeyDown, { capture: true });
  }, [enabled, panels, threadRef]);
}

export function ExtensionPanelSurface(props: {
  readonly pluginId: string;
  readonly panelId: string;
  readonly threadRef: ScopedThreadRef;
}) {
  const { pluginId, panelId, threadRef } = props;
  const panel = usePluginPanelStore((state) => state.panels[pluginPanelKey(pluginId, panelId)]);
  const containerRef = useRef<HTMLDivElement>(null);
  const threadKey = scopedThreadKey(threadRef);

  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- mounts the extension-owned DOM panel and runs its cleanup.
  useEffect(() => {
    const container = containerRef.current;
    if (panel === undefined || container === null) return;
    let disposed = false;
    let cleanup: (() => void) | undefined;
    const mount = document.createElement("div");
    mount.className = "h-full";
    container.replaceChildren(mount);
    void Promise.resolve()
      .then(() =>
        panel.render(mount, {
          environmentId: threadRef.environmentId,
          threadId: threadRef.threadId,
          threadKey,
          storage: pluginPanelStorage(pluginId),
        }),
      )
      .then(
        (result) => {
          if (typeof result !== "function") return;
          if (disposed) result();
          else cleanup = result;
        },
        (error: unknown) => {
          console.error(`Extension ${pluginId} failed to render ${panelId}`, error);
        },
      );
    return () => {
      disposed = true;
      cleanup?.();
      mount.remove();
    };
  }, [panel, pluginId, panelId, threadKey, threadRef.environmentId, threadRef.threadId]);

  if (panel === undefined) {
    return (
      <Empty>
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <PuzzleIcon />
          </EmptyMedia>
          <EmptyTitle>Extension not loaded</EmptyTitle>
          <EmptyDescription>
            Enable {pluginId} in Settings → Extensions to show this panel.
          </EmptyDescription>
        </EmptyHeader>
      </Empty>
    );
  }
  return <div ref={containerRef} className="h-full min-h-0 overflow-hidden" />;
}
