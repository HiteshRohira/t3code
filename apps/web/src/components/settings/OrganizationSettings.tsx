import type { EnterpriseStatus } from "@t3tools/contracts";
import {
  isAtomCommandInterrupted,
  settlePromise,
  squashAtomCommandFailure,
  type AtomCommandResult,
} from "@t3tools/client-runtime/state/runtime";
import { useNavigate } from "@tanstack/react-router";
import { useRef, useState } from "react";

import { ensureLocalApi } from "../../localApi";
import { usePrimaryEnvironmentId } from "../../state/environments";
import { useEnvironmentQuery } from "../../state/query";
import { serverEnvironment } from "../../state/server";
import { useAtomCommand } from "../../state/use-atom-command";
import { Button } from "../ui/button";
import { SettingsRow, SettingsSection } from "./settingsLayout";

const formatDate = (iso: string | null) =>
  iso === null
    ? null
    : new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

/** What the policy row says, and whether it offers a restart. */
function policyDescription(status: EnterpriseStatus): string {
  const { loadedVersion, availableVersion, restartRequired } = status.policy;
  const running =
    loadedVersion === null ? "the bootstrap policy" : `policy version ${loadedVersion}`;
  if (!restartRequired) return `T3 Code enforces ${running}.`;
  const next = availableVersion === null ? "A new policy" : `Policy version ${availableVersion}`;
  return status.restart === "self"
    ? `${next} is ready. T3 Code enforces ${running} until it restarts.`
    : `${next} is ready. Restart T3 Code where it runs to apply it; until then it enforces ${running}.`;
}

function modelAccessDescription(status: EnterpriseStatus): string {
  if (!status.enrolled) return "Enroll this computer to use your organization's models.";
  if (status.lease.active) {
    return `Active until ${formatDate(status.lease.expiresAt)}; renews automatically.`;
  }
  return status.lease.problem ?? "Connecting to your organization…";
}

/** Enrollment, model access, and policy for an environment an organization manages. */
export function OrganizationSettingsSection() {
  const environmentId = usePrimaryEnvironmentId();
  const statusQuery = useEnvironmentQuery(
    environmentId === null
      ? null
      : serverEnvironment.enterpriseStatus({ environmentId, input: {} }),
  );
  const options = { reportFailure: false, reportDefect: false };
  const restart = useAtomCommand(serverEnvironment.restartForEnterprisePolicy, options);
  const continueShared = useAtomCommand(serverEnvironment.continueSharedThread, options);
  const navigate = useNavigate();
  const sharedQuery = useEnvironmentQuery(
    environmentId === null || !statusQuery.data?.enrolled
      ? null
      : serverEnvironment.sharedThreads({ environmentId, input: {} }),
  );
  const enroll = useAtomCommand(serverEnvironment.enrollEnterpriseDevice, options);
  const [pending, setPending] = useState<string | null>(null);
  const pendingRef = useRef(false);
  const [error, setError] = useState<string | null>(null);

  const status = statusQuery.data;
  if (environmentId === null || status === null || status === undefined) return null;

  async function run<A, E>(
    label: string,
    request: () => Promise<AtomCommandResult<A, E>>,
  ): Promise<A | undefined> {
    if (pendingRef.current) return undefined;
    pendingRef.current = true;
    setPending(label);
    setError(null);
    const settled = await settlePromise(request);
    pendingRef.current = false;
    setPending(null);
    if (settled._tag === "Failure") {
      setError("The request did not reach T3 Code. Try again.");
      return undefined;
    }
    const result = settled.value;
    if (result._tag === "Failure") {
      if (!isAtomCommandInterrupted(result)) {
        const failure = squashAtomCommandFailure(result);
        setError(failure instanceof Error ? failure.message : "That did not work. Try again.");
      }
      return undefined;
    }
    return result.value;
  }

  const startEnrollment = async () => {
    const result = await run("enroll", () => enroll({ environmentId, input: {} }));
    if (result !== undefined) void ensureLocalApi().shell.openExternal(result.signInUrl);
  };

  const continueThread = async (id: string) => {
    const result = await run(`continue:${id}`, () =>
      continueShared({ environmentId, input: { id } }),
    );
    if (result === undefined) return;
    const search = new URLSearchParams({ prompt: result.prompt });
    if (result.repository !== null) search.set("repo", result.repository);
    if (result.provider !== null) search.set("provider", result.provider);
    void navigate({ href: `/new?${search}` });
  };

  const shared = sharedQuery.data ?? [];
  const enrollment = status.enrollment;
  return (
    <SettingsSection id="organization" title="Organization">
      <SettingsRow
        title={`Managed by ${status.organization}`}
        description={`Models, policy, and audit come from ${new URL(status.controlPlaneUrl).host}.`}
        control={
          status.supportUrl ? (
            <Button
              variant="outline"
              size="sm"
              onClick={() => void ensureLocalApi().shell.openExternal(status.supportUrl!)}
            >
              Get help
            </Button>
          ) : null
        }
      />
      <SettingsRow
        title="This computer"
        description={
          status.enrolled
            ? `Enrolled as ${status.email}. Certificate valid until ${formatDate(status.certificateExpiresAt)}.`
            : enrollment === null
              ? "Not enrolled. Sign in with your organization account to enroll it."
              : enrollment.error === null
                ? "Finish signing in in your browser."
                : `Enrollment failed: ${enrollment.error}`
        }
        control={
          status.enrolled ? null : (
            <div className="flex items-center gap-2">
              {enrollment !== null && enrollment.error === null ? (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => void ensureLocalApi().shell.openExternal(enrollment.signInUrl)}
                >
                  Open sign-in page
                </Button>
              ) : null}
              <Button size="sm" disabled={pending !== null} onClick={() => void startEnrollment()}>
                {pending === "enroll" ? "Starting…" : "Enroll"}
              </Button>
            </div>
          )
        }
      />
      <SettingsRow
        title="Model access"
        description={modelAccessDescription(status)}
        status={
          status.enrolled && !status.lease.active ? (
            <span className="text-destructive-foreground text-xs">Unavailable</span>
          ) : null
        }
      />
      <SettingsRow
        title="Policy"
        description={policyDescription(status)}
        control={
          status.policy.restartRequired && status.restart === "self" ? (
            <Button
              size="sm"
              disabled={pending !== null}
              onClick={() => void run("restart", () => restart({ environmentId, input: {} }))}
            >
              {pending === "restart" ? "Restarting…" : "Restart to apply"}
            </Button>
          ) : null
        }
      />
      {status.enrolled ? (
        <SettingsRow
          title="Shared with you"
          description={
            shared.length === 0
              ? "Threads colleagues hand off appear here. Hand off one of yours from its menu in the sidebar."
              : `${shared.length} handed-off ${shared.length === 1 ? "thread" : "threads"}. Continue one to start a new thread with its transcript and changes.`
          }
        >
          {shared.length === 0 ? null : (
            <ul className="mt-2 divide-y divide-border rounded-md border">
              {shared.slice(0, 20).map((thread) => (
                <li key={thread.id} className="flex items-center gap-3 px-3 py-2">
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm">{thread.title}</p>
                    <p className="truncate text-muted-foreground text-xs">
                      {thread.sharedBy} · {thread.audience === "org" ? "everyone" : "your team"} ·{" "}
                      {formatDate(thread.createdAt)}
                      {thread.repository ? ` · ${thread.repository}` : ""}
                    </p>
                  </div>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={pending !== null}
                    onClick={() => void continueThread(thread.id)}
                  >
                    {pending === `continue:${thread.id}` ? "Opening…" : "Continue"}
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </SettingsRow>
      ) : null}
      {error === null ? null : (
        <p role="alert" className="px-3 text-destructive-foreground text-xs sm:px-4">
          {error}
        </p>
      )}
    </SettingsSection>
  );
}
