import {
  AuthEnvironmentMaintainScope,
  AuthOrchestrationOperateScope,
  AuthOrchestrationReadScope,
  EnvironmentId,
  type PluginPackageStatusSnapshot,
} from "@t3tools/contracts";
import { expect, it, vi } from "vite-plus/test";

import { act, render } from "../../../test/render";

const environmentId = EnvironmentId.make("primary");

const commands = vi.hoisted(() => ({
  enable: vi.fn(),
  disable: vi.fn(),
  reload: vi.fn(),
}));
const query = vi.hoisted(() => ({
  data: null as PluginPackageStatusSnapshot | null,
  error: null as string | null,
  isPending: false,
  refresh: vi.fn(),
}));
const session = vi.hoisted(() => ({ scopes: [] as string[] }));

vi.mock(import("../../state/environments"), async (original) => ({
  ...(await original()),
  usePrimaryEnvironmentId: () => environmentId,
}));
vi.mock(import("../../environments/primary"), async (original) => ({
  ...(await original()),
  usePrimarySessionState: (() => ({
    data: { authenticated: true, permissions: session.scopes },
    error: null,
    isPending: false,
    refresh: () => undefined,
  })) as never,
}));
vi.mock(import("../../state/query"), async (original) => ({
  ...(await original()),
  useEnvironmentQuery: (() => query) as never,
}));
vi.mock(import("../../state/use-atom-command"), async (original) => {
  const { serverEnvironment } = await import("../../state/server");
  const byAtom = new Map<unknown, unknown>([
    [serverEnvironment.enablePluginPackage, commands.enable],
    [serverEnvironment.disablePluginPackage, commands.disable],
    [serverEnvironment.reloadPluginPackage, commands.reload],
  ]);
  return {
    ...(await original()),
    useAtomCommand: ((atom: unknown) => byAtom.get(atom)) as never,
  };
});

import { PluginsSettingsPanel } from "./PluginsSettings";

const snapshot: PluginPackageStatusSnapshot = {
  errors: [{ directory: "broken-package", error: "manifest is invalid" }],
  packages: [
    {
      id: "com.acme.active",
      version: "1.2.3",
      apiVersion: 1,
      enabled: true,
      state: "active",
      capabilities: ["t3.commands@1"],
      contributions: { commands: ["acme.active.run"] },
    },
    {
      id: "com.acme.disabled",
      version: "2.0.0",
      apiVersion: 1,
      enabled: false,
      state: "disabled",
      capabilities: ["t3.commands@1"],
      contributions: { commands: [] },
    },
  ],
};

function setup() {
  session.scopes = [
    AuthOrchestrationReadScope,
    AuthOrchestrationOperateScope,
    AuthEnvironmentMaintainScope,
  ];
  query.data = snapshot;
  query.error = null;
  query.isPending = false;
  query.refresh.mockReset();
  for (const command of Object.values(commands)) {
    command.mockReset().mockResolvedValue({ _tag: "Success", value: snapshot });
  }
}

async function renderPanel() {
  const screen = await render(<PluginsSettingsPanel />);
  const control = (label: string) => {
    const found = screen.container.querySelector<HTMLElement>(`[aria-label="${label}"]`);
    expect(found, label).not.toBeNull();
    return found!;
  };
  return Object.assign(screen, {
    control,
    click: (label: string) => act(async () => control(label).click()),
  });
}

it("lists packages with their state and reports discovery errors", async () => {
  setup();
  await using screen = await renderPanel();
  const text = screen.container.textContent ?? "";

  expect(text).not.toContain("Limited permissions");
  expect(text).toContain("com.acme.active");
  expect(text).toContain("com.acme.disabled");
  expect(text).toContain("Active");
  expect(text).toContain("1 command: acme.active.run");
  expect(text).toContain("broken-package");
  expect(text).toContain("manifest is invalid");
  expect(text).toContain("2 extensions");
});

it("enables, disables and reloads through the package commands, then refreshes", async () => {
  setup();
  await using screen = await renderPanel();

  await screen.click("Enable com.acme.disabled");
  await vi.waitFor(() => expect(query.refresh).toHaveBeenCalledTimes(1));
  expect(commands.enable).toHaveBeenCalledWith({
    environmentId,
    input: { id: "com.acme.disabled" },
  });

  await screen.click("Disable com.acme.active");
  await vi.waitFor(() => expect(query.refresh).toHaveBeenCalledTimes(2));
  expect(commands.disable).toHaveBeenCalledWith({
    environmentId,
    input: { id: "com.acme.active" },
  });

  await screen.click("Reload com.acme.active");
  await vi.waitFor(() => expect(query.refresh).toHaveBeenCalledTimes(3));
  expect(commands.reload).toHaveBeenCalledWith({
    environmentId,
    input: { id: "com.acme.active" },
  });
});

it("keeps packages read-only without the maintain grant", async () => {
  setup();
  session.scopes = [AuthOrchestrationReadScope, AuthOrchestrationOperateScope];
  await using screen = await renderPanel();

  expect(screen.container.textContent).toContain("Limited permissions");
  await screen.click("Enable com.acme.disabled");
  expect(commands.enable).not.toHaveBeenCalled();
});

it("shows the empty state when no packages are installed", async () => {
  setup();
  query.data = { errors: [], packages: [] };
  await using screen = await renderPanel();

  expect(screen.container.textContent).toContain("No extensions found");
});
