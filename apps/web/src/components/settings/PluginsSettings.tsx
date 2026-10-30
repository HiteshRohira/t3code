import {
  AuthEnvironmentMaintainScope,
  type PluginPackageStatus,
  sessionGrantsScope,
} from "@t3tools/contracts";
import {
  isAtomCommandInterrupted,
  squashAtomCommandFailure,
} from "@t3tools/client-runtime/state/runtime";
import {
  CircleAlertIcon,
  FolderCodeIcon,
  RefreshCwIcon,
  RotateCwIcon,
  ShieldAlertIcon,
} from "lucide-react";
import { useState } from "react";

import { usePrimarySessionState } from "../../environments/primary";
import { usePrimaryEnvironmentId } from "../../state/environments";
import { useEnvironmentQuery } from "../../state/query";
import { serverEnvironment } from "../../state/server";
import { useAtomCommand } from "../../state/use-atom-command";
import { Alert, AlertDescription, AlertTitle } from "../ui/alert";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "../ui/empty";
import { Spinner } from "../ui/spinner";
import { Switch } from "../ui/switch";
import { toastManager } from "../ui/toast";
import { Tooltip, TooltipPopup, TooltipTrigger } from "../ui/tooltip";
import { SettingsPageContainer, SettingsRow, SettingsSection } from "./settingsLayout";
import type { ProviderOperateAccess } from "./ProviderSettingsPanel.logic";
import { searchableSetting } from "./settingsSearch";

const statePresentation = {
  active: { label: "Active", variant: "success" },
  disabled: { label: "Disabled", variant: "secondary" },
  error: { label: "Error", variant: "error" },
} as const;

type PackageAction = "enable" | "disable" | "reload";

function actionFailureMessage(action: PackageAction, error: unknown): string {
  if (error instanceof Error && error.message.trim().length > 0) return error.message;
  return `The extension could not be ${action === "reload" ? "reloaded" : `${action}d`}.`;
}

function PluginPackageRow({
  pluginPackage,
  pendingAction,
  readOnly,
  onEnabledChange,
  onReload,
}: {
  readonly pluginPackage: PluginPackageStatus;
  readonly pendingAction: PackageAction | null;
  readonly readOnly: boolean;
  readonly onEnabledChange: (enabled: boolean) => void;
  readonly onReload: () => void;
}) {
  const state = statePresentation[pluginPackage.state];
  const commands = pluginPackage.contributions.commands;
  const busy = pendingAction !== null;
  const status = (
    <div className="flex flex-wrap items-center gap-1.5">
      <Badge variant={state.variant}>{state.label}</Badge>
      <Badge variant="outline">v{pluginPackage.version}</Badge>
      {pluginPackage.capabilities.map((capability) => (
        <Badge key={capability} variant="info">
          {capability}
        </Badge>
      ))}
    </div>
  );

  return (
    <SettingsRow
      title={<code className="text-sm">{pluginPackage.id}</code>}
      description={
        commands.length === 0
          ? "No command contributions"
          : `${commands.length} command${commands.length === 1 ? "" : "s"}: ${commands.join(", ")}`
      }
      status={status}
      className="border border-border/60 bg-card/35"
      control={
        <div className="flex items-center gap-2">
          {pluginPackage.enabled ? (
            <Button
              type="button"
              size="icon-sm"
              variant="ghost-muted"
              aria-label={`Reload ${pluginPackage.id}`}
              disabled={busy || readOnly}
              onClick={onReload}
            >
              {pendingAction === "reload" ? (
                <Spinner className="size-3.5" />
              ) : (
                <RotateCwIcon className="size-3.5" />
              )}
            </Button>
          ) : null}
          <Switch
            checked={pluginPackage.enabled}
            disabled={busy || readOnly}
            aria-label={`${pluginPackage.enabled ? "Disable" : "Enable"} ${pluginPackage.id}`}
            onCheckedChange={onEnabledChange}
          />
        </div>
      }
    >
      {pluginPackage.error ? (
        <Alert variant="error" className="mt-3">
          <CircleAlertIcon />
          <AlertDescription>{pluginPackage.error}</AlertDescription>
        </Alert>
      ) : null}
    </SettingsRow>
  );
}

export function PluginsSettingsPanel() {
  const environmentId = usePrimaryEnvironmentId();
  const primarySession = usePrimarySessionState();
  // Enable, disable and reload require the environment maintain grant: they run local code.
  const operateAccess: ProviderOperateAccess =
    primarySession.error !== null
      ? "denied"
      : primarySession.data === null
        ? primarySession.isPending
          ? "pending"
          : "denied"
        : sessionGrantsScope(primarySession.data, AuthEnvironmentMaintainScope)
          ? "granted"
          : "denied";
  const readOnly = operateAccess !== "granted";
  const status = useEnvironmentQuery(
    environmentId === null ? null : serverEnvironment.pluginPackages({ environmentId, input: {} }),
  );
  const enablePlugin = useAtomCommand(serverEnvironment.enablePluginPackage, {
    reportFailure: false,
  });
  const disablePlugin = useAtomCommand(serverEnvironment.disablePluginPackage, {
    reportFailure: false,
  });
  const reloadPlugin = useAtomCommand(serverEnvironment.reloadPluginPackage, {
    reportFailure: false,
  });
  const [pending, setPending] = useState<{
    readonly id: string;
    readonly action: PackageAction;
  } | null>(null);
  const packages = [...(status.data?.packages ?? [])].sort((left, right) =>
    left.id.localeCompare(right.id),
  );

  const runAction = (pluginPackage: PluginPackageStatus, action: PackageAction) => {
    if (environmentId === null || pending !== null || readOnly) return;
    setPending({ id: pluginPackage.id, action });
    const command =
      action === "enable" ? enablePlugin : action === "disable" ? disablePlugin : reloadPlugin;
    void (async () => {
      const result = await command({
        environmentId,
        input: { id: pluginPackage.id },
      });
      setPending(null);
      if (result._tag === "Success") {
        status.refresh();
        return;
      }
      if (!isAtomCommandInterrupted(result)) {
        const error = squashAtomCommandFailure(result);
        toastManager.add({
          type: "error",
          title: `Could not ${action} extension`,
          description: actionFailureMessage(action, error),
        });
      }
    })();
  };

  const countLabel = `${packages.length} ${packages.length === 1 ? "extension" : "extensions"}`;

  return (
    <SettingsPageContainer>
      <SettingsSection
        {...searchableSetting("extensions")}
        headerAction={
          <div className="flex items-center gap-2">
            <span className="text-2xs text-muted-foreground">{countLabel}</span>
            <Tooltip>
              <TooltipTrigger
                render={
                  <Button
                    type="button"
                    size="icon-micro"
                    variant="ghost-muted"
                    aria-label="Refresh extensions"
                    disabled={status.isPending}
                    onClick={status.refresh}
                  >
                    {status.isPending ? (
                      <Spinner className="size-3" />
                    ) : (
                      <RefreshCwIcon className="size-3" />
                    )}
                  </Button>
                }
              />
              <TooltipPopup side="top">Refresh extensions</TooltipPopup>
            </Tooltip>
          </div>
        }
      >
        <Alert variant="warning" className="mb-3">
          <ShieldAlertIcon />
          <AlertTitle>Trusted local code</AlertTitle>
          <AlertDescription>
            Extensions run inside this environment's server process with its filesystem and network
            access. Only install code you trust.
          </AlertDescription>
        </Alert>

        {operateAccess === "denied" ? (
          <Alert variant="info" className="mb-3" data-plugin-read-only>
            <ShieldAlertIcon />
            <AlertTitle>Limited permissions</AlertTitle>
            <AlertDescription>
              This session can inspect extensions, but it cannot enable, disable, or reload them.
            </AlertDescription>
          </Alert>
        ) : null}

        {status.error ? (
          <Alert variant="error">
            <CircleAlertIcon />
            <AlertTitle>Could not load extensions</AlertTitle>
            <AlertDescription>{status.error}</AlertDescription>
          </Alert>
        ) : null}

        {status.data?.errors.map((error) => (
          <Alert
            key={error.directory}
            variant="error"
            className="mb-2"
            data-plugin-error={error.directory}
          >
            <CircleAlertIcon />
            <AlertTitle>{error.directory}</AlertTitle>
            <AlertDescription>{error.error}</AlertDescription>
          </Alert>
        ))}

        {status.isPending && status.data === null ? (
          <Empty className="min-h-52">
            <EmptyMedia>
              <Spinner className="size-4" />
            </EmptyMedia>
            <EmptyHeader>
              <EmptyDescription>Loading extensions</EmptyDescription>
            </EmptyHeader>
          </Empty>
        ) : null}

        {!status.isPending &&
        status.error === null &&
        packages.length === 0 &&
        (status.data?.errors.length ?? 0) === 0 ? (
          <Empty data-plugin-empty className="min-h-52">
            <EmptyMedia variant="icon">
              <FolderCodeIcon />
            </EmptyMedia>
            <EmptyHeader>
              <EmptyTitle>No extensions found</EmptyTitle>
              <EmptyDescription>
                Add a trusted extension package to this environment's userdata/plugins directory,
                then refresh this page.
              </EmptyDescription>
            </EmptyHeader>
          </Empty>
        ) : null}

        <div className="space-y-2">
          {packages.map((pluginPackage) => (
            <PluginPackageRow
              key={pluginPackage.id}
              pluginPackage={pluginPackage}
              readOnly={readOnly || pending !== null}
              pendingAction={
                pending !== null && pending.id === pluginPackage.id ? pending.action : null
              }
              onEnabledChange={(enabled) =>
                runAction(pluginPackage, enabled ? "enable" : "disable")
              }
              onReload={() => runAction(pluginPackage, "reload")}
            />
          ))}
        </div>
      </SettingsSection>
    </SettingsPageContainer>
  );
}
