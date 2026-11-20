# Upstream touchpoints

Files outside `enterprise/` that this fork changes. Each is a possible merge conflict when pulling
`remote/main`; keep the list short and the edits small.

| File                                      | Change                                                                                               | Why it cannot live in `enterprise/` |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------- | ----------------------------------- |
| `pnpm-workspace.yaml`                     | `enterprise/*` workspace; `node-forge` and `@types/node-forge` in the catalog                        | Workspace membership                |
| `knip.jsonc`                              | `enterprise/*` workspaces; admin console script entry                                                | Knip config is repo-wide            |
| `apps/server/package.json`                | `@t3tools/enterprise-protocol`; control plane and forge as test dependencies                         | Server imports the protocol         |
| `apps/server/src/policy/ManagedPolicy.ts` | `makeEnterprise`: with an `enterprise.json`, the policy comes from the control plane                 | The policy service is built here    |
| `apps/server/src/server.ts`               | `EnterpriseAgent.layer` outermost in the runtime layers; `EnterpriseAudit.layer` beside the reactors | Layer composition                   |
| `apps/server/src/binCli.ts`               | Registers `t3 enterprise`                                                                            | CLI root                            |

New directories, which upstream never touches: `apps/server/src/enterprise/`,
`apps/server/src/cli/enterprise.ts`, `enterprise/`.

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
- Upstream changes the managed policy schema: the control plane stores policies as opaque JSON and
  devices validate them, so publish with `t3 policy check` from the matching version.
