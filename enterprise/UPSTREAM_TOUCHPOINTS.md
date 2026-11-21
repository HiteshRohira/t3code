# Upstream touchpoints

Files outside `enterprise/` that this fork changes. Each is a possible merge conflict when pulling
`remote/main`; keep the list short and the edits small.

| File                                                                                        | Change                                                                                                  | Why it cannot live in `enterprise/`   |
| ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| `pnpm-workspace.yaml`, `pnpm-lock.yaml`                                                     | `enterprise/*` workspace; `node-forge`, `@node-saml/node-saml` in the catalog                           | Workspace membership                  |
| `knip.jsonc`                                                                                | `enterprise/*` workspaces; admin console script entry                                                   | Knip config is repo-wide              |
| `apps/server/package.json`                                                                  | `@t3tools/enterprise-protocol`; control plane and forge as test dependencies                            | Server imports the protocol           |
| `apps/server/src/policy/ManagedPolicy.ts`                                                   | `makeEnterprise`: with an `enterprise.json`, the policy comes from the control plane; `pairing` summary | The policy service is built here      |
| `apps/server/src/policy/managedLimits.ts`                                                   | `requiresSsoPairing`, `refuseLinkPairing`                                                               | Limit helpers live beside the others  |
| `apps/server/src/auth/EnvironmentAuth.ts` (+ test)                                          | `createPairingLink` refuses plain links under `pairing: "sso"` unless the caller verified a sign-in     | Pairing links are minted here         |
| `apps/server/src/server.ts`                                                                 | Enterprise layers (agent, audit, library, pairing routes, sharing for `ws`)                             | Layer composition                     |
| `apps/server/src/binCli.ts`                                                                 | Registers `t3 enterprise`                                                                               | CLI root                              |
| `apps/server/src/ws.ts` (+ test), `auth/RpcAuthorization.ts`, `RpcInstrumentation.ts`       | Handlers, scopes, and spans for the `enterprise*` RPC methods                                           | Every RPC method is registered there  |
| `apps/server/src/provider/codexLaunchArgs.ts` (+ test), `CodexManagedRuntime.ts`            | `T3E_CODEX_GATEWAY_URL` becomes Codex provider overrides; managed Codex logins drop it                  | Codex ignores `OPENAI_BASE_URL`       |
| `apps/server/src/orchestration-v2/Adapters/CodexAdapterV2.ts` (+ test)                      | `thread/resume` passes the gateway provider, so sessions from before enrollment also use it             | Codex pins a session's provider       |
| `packages/contracts/src/{managedPolicy,rpc,clientRpcPermissions,index}.ts`                  | `pairing` and `agentPullRequests` limits; `enterprise*` RPC methods and their scopes                    | Wire types are shared by every client |
| `packages/client-runtime/src/{rpc/client,state/server}.ts`                                  | Status subscription and the enterprise command atoms                                                    | Shared client state                   |
| `apps/web/src/components/settings/{SettingsPanels,AuthorizedClientsSettings}.tsx`           | Organization section at the top of General; "Pair with sign-in" under SSO pairing                       | Settings layout                       |
| `apps/web/src/components/{Sidebar.tsx,sidebar/SidebarChrome.tsx,threadActionMenu.logic.ts}` | Restart pill; "Hand off to colleagues" thread action                                                    | Sidebar and thread menu               |

New files, which upstream never touches: `apps/server/src/enterprise/`,
`apps/server/src/cli/enterprise.ts`, `packages/contracts/src/enterprise.ts`,
`apps/web/src/components/settings/OrganizationSettings.tsx`,
`apps/web/src/components/sidebar/SidebarPolicyRestartPill.tsx`, `enterprise/`.

## Pulling upstream

```sh
git fetch remote
git merge remote/main          # conflicts, if any, are in the files above
vp i
vp run check:changed
vp test run enterprise apps/server/src/enterprise
```

Things that can break silently after a merge, and the test that catches them:

- Upstream renames or reshapes orchestration events: `EnterpriseAudit.ts` stops matching them.
  The typecheck fails on renamed fields; a removed event type just stops being audited, so read
  the contracts diff for `orchestrationV2.ts`.
- Upstream adds a provider that reads credentials from somewhere other than the environment: it
  would bypass the gateway. Keep it out of `providers.allowedDrivers` until it is routed.
- Upstream adds another `thread/resume` or `thread/fork` path to the Codex adapter: it must pass
  the gateway provider too, or threads started before enrollment call OpenAI directly and fail.
- Upstream changes the managed policy schema: the control plane stores policies as opaque JSON and
  devices validate them, so publish with `t3 policy check` from the matching version.
