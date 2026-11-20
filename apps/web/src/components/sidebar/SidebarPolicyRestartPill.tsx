import { settlePromise } from "@t3tools/client-runtime/state/runtime";
import { BuildingIcon } from "lucide-react";
import { useState } from "react";

import { usePrimaryEnvironmentId } from "~/state/environments";
import { useEnvironmentQuery } from "~/state/query";
import { serverEnvironment } from "~/state/server";
import { useAtomCommand } from "~/state/use-atom-command";
import { SidebarMenuItem } from "../ui/sidebar";
import { Tooltip, TooltipPopup, TooltipTrigger } from "../ui/tooltip";

/**
 * Beside the update control: the organization published a policy this server only applies after
 * a restart. Shown only where the server can restart itself; Settings explains the other cases.
 */
export function SidebarPolicyRestartPill() {
  const environmentId = usePrimaryEnvironmentId();
  const status = useEnvironmentQuery(
    environmentId === null
      ? null
      : serverEnvironment.enterpriseStatus({ environmentId, input: {} }),
  ).data;
  const restart = useAtomCommand(serverEnvironment.restartForEnterprisePolicy);
  const [restarting, setRestarting] = useState(false);

  if (
    environmentId === null ||
    status == null ||
    !status.policy.restartRequired ||
    status.restart !== "self"
  ) {
    return null;
  }

  const label = restarting ? "Restarting…" : "Restart for new policy";
  return (
    <SidebarMenuItem className="shrink-0">
      <Tooltip>
        <TooltipTrigger
          render={
            <button
              type="button"
              disabled={restarting}
              onClick={() => {
                setRestarting(true);
                void settlePromise(() => restart({ environmentId, input: {} })).then(() =>
                  setRestarting(false),
                );
              }}
              className="flex h-8 items-center gap-1.5 rounded-full bg-sidebar-control-surface px-3 text-sidebar-foreground text-xs outline-hidden ring-ring hover:bg-sidebar-row-hover focus-visible:ring-2 focus-visible:ring-inset disabled:opacity-60"
            />
          }
        >
          <BuildingIcon aria-hidden="true" className="size-3.5 text-muted-foreground" />
          {label}
        </TooltipTrigger>
        <TooltipPopup side="top">
          {status.organization} published policy version {status.policy.availableVersion}. T3 Code
          applies it when it restarts.
        </TooltipPopup>
      </Tooltip>
    </SidebarMenuItem>
  );
}
