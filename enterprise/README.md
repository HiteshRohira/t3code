# T3 Enterprise

An enterprise layer for this T3 Code fork. Model credentials stay with the organization, only
enrolled machines can use them, and admins get policy, budgets, and an audit trail. See
[PLAN.md](PLAN.md) for the reasoning and what is still to come.

```
 developer laptop                          organization
┌──────────────────────────────┐     ┌──────────────────────────────────────┐
│ T3 Code (enterprise build)   │     │ control plane   SSO, SCIM, enrollment, │
│  provider CLIs ──► loopback ─┼─mTLS┤                 leases, signed policy, │
│  proxy (lease + device cert) │     │                 audit, admin console   │
│  audit shipper ──────────────┼─mTLS┤                                        │
└──────────────────────────────┘     │ gateway ──► Anthropic / OpenAI         │
                                     │  org keys, mTLS, budgets, model rules  │
                                     └──────────────────────────────────────┘
```

| Piece         | Where                                                          | What it does                                                                                                                                                                                  |
| ------------- | -------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Control plane | [`control-plane/`](control-plane)                              | OIDC or SAML sign-in, SCIM 2.0, device CA and enrollment, short leases, signed policy, audit and usage, retention, org library, shared threads, admin console                                 |
| Gateway       | [`gateway/`](gateway)                                          | Accepts only org-CA device certificates and valid leases; enforces revocation, budgets, model allow-lists, rate limits, regions; redacts secrets; holds the real provider keys; meters tokens |
| Protocol      | [`protocol/`](protocol)                                        | Lease and policy tokens, certificate thumbprints, usage parsing, wire types                                                                                                                   |
| Device agent  | [`apps/server/src/enterprise/`](../apps/server/src/enterprise) | Policy from the control plane, lease renewal, loopback proxy for provider CLIs, audit shipping, heartbeats, org library install, thread hand-offs, `t3 enterprise` CLI                        |

## Why stock T3 Code cannot use the org's credits

1. The provider keys exist only in the gateway's environment. Laptops never receive one.
2. The gateway completes a TLS handshake only with a certificate the org CA issued at enrollment.
3. Every request also needs a lease: a 4-hour token signed by the control plane and bound to that
   certificate's thumbprint. A lease copied to another machine is refused.
4. Enrollment needs an IdP sign-in by an active user. Deactivating the user (in the admin console
   or through SCIM) revokes all their devices; the gateway stops them within one sync (15 s).

Provider CLIs on an enrolled machine talk to a loopback proxy inside the T3 server, which adds the
certificate and lease. The proxy accepts only a random per-start token that T3 hands to the
processes it starts.

What this does not stop: a user who controls their machine can use their own lease while it is
valid. Budgets, rate limits, revocation, and the audit trail cover that.

## Try it locally

```sh
enterprise/dev/demo.sh .t3/enterprise-demo      # control plane, gateway, mock Anthropic and OpenAI APIs
export T3CODE_DEV_ENTERPRISE_CONFIG_PATH=$PWD/.t3/enterprise-demo/enterprise.json
export T3CODE_ENTERPRISE_STATE_DIR=$PWD/.t3/enterprise-demo/device
node apps/server/src/bin.ts enterprise enroll    # sign in with any email
vp run dev
enterprise/dev/demo.sh .t3/enterprise-demo stop
```

The mock APIs answer every Claude and Codex turn with a fixed reply and log which key reached them;
the Anthropic mock also says which redaction markers arrived instead of a secret. You can also
enroll from Settings → General → Organization. Admin console: `https://localhost:8443/admin`
(development sign-in; give a user the `admin` role with the API token in `secrets.env`).

## Deploy

### 1. Control plane

```sh
node enterprise/control-plane/src/bin.ts init --dir /srv/t3e --organization "Example Corp" --host t3.example.com
```

Then edit `/srv/t3e/control-plane.json`:

- Put a publicly trusted TLS certificate in `tls`, or terminate TLS yourself only if your proxy
  forwards client certificates. Device routes need the client certificate at this process.
- Replace `insecureDevLogin` with `oidc` or `saml`, and map groups to roles:
  ```json
  "oidc": { "issuer": "https://example.okta.com", "clientId": "…", "groupsClaim": "groups" },
  "allowedGroups": ["t3-users"],
  "groupRoles": { "t3-admins": "admin", "t3-leads": "maintainer", "t3-security": "auditor", "t3-users": "developer" }
  ```
  For OIDC, register `https://<host>/oidc/callback` as the redirect URI; the client secret is read
  from `T3E_OIDC_CLIENT_SECRET`. For SAML, set `"saml": { "entryPoint": …, "idpCertificate": … }`
  (plus `groupsAttribute` if the IdP sends groups), and give the IdP
  `https://<host>/saml/metadata`; assertions must be signed and post to `/saml/acs`. Groups can
  also come from SCIM, so an IdP that sends none at sign-in still maps to roles.
- `provisioning: "scim"` admits only users your IdP provisioned. Point the IdP's SCIM 2.0 app at
  `https://<host>/scim/v2` with `T3E_SCIM_TOKEN` as the bearer token. It accepts Users and
  Groups; `department` (enterprise extension) sets the user's team.
- `defaultMonthlyTokens` and `defaultModels` set org-wide limits; teams and users override them in
  the admin console.
- `auditSinks`: `{"type":"jsonl","path":…}` or `{"type":"http","url":…,"headers":{"Authorization":"$SPLUNK_HEC_TOKEN"}}`
  (a value starting with `$` is read from the environment). The database stays the source of
  truth; a SIEM can backfill from `GET /v1/admin/audit.jsonl?after=<seq>`.
- `retention`: `{"auditDays": 365, "usageDays": 400, "leaseDays": 30}` deletes older rows daily.
  Unset keeps them forever. A legal hold (Users tab) keeps a user's records past it.
- `regions` and `defaultRegion` pin users or teams to a data region; the gateway then sends their
  requests only to upstreams labelled with that region, and refuses when none is configured.

Secrets come from the environment: `T3E_GATEWAY_TOKEN`, `T3E_SCIM_TOKEN`, `T3E_ADMIN_API_TOKEN`,
`T3E_OIDC_CLIENT_SECRET`. Back up `dataDir`: it holds the CA key, signing keys, and the database.

Roles: `admin` (everything), `maintainer` (directory, revoke devices, teams and budgets),
`auditor` (read directory, policy, audit, usage), `developer` (model access), `viewer` (signs in,
no model access).

### 2. Gateway

```json
{
  "listen": { "host": "0.0.0.0", "port": 9443 },
  "tls": { "certPath": "tls.crt", "keyPath": "tls.key" },
  "deviceCaPath": "/srv/t3e/data/ca.crt",
  "controlPlaneUrl": "https://t3.example.com",
  "upstreams": [
    { "family": "anthropic", "apiKeyEnv": "ANTHROPIC_API_KEY" },
    { "family": "openai", "apiKeyEnv": "OPENAI_API_KEY" }
  ],
  "requestsPerMinute": 120,
  "redaction": { "mode": "redact" }
}
```

Add `"region": "eu"` to an upstream to serve only users and teams pinned to that region.
`redaction.mode` is `redact` by default: private keys and cloud, GitHub, GitLab, Slack, Stripe,
Google, Anthropic, and OpenAI tokens in a request become `[REDACTED:<kind>]` before it leaves.
`block` refuses such requests instead; `off` forwards them. `detectors` narrows the list. Counts
show in the Usage tab.

`baseUrl` on an upstream points at Bedrock-, Vertex-, or Azure-compatible endpoints, or at an
existing gateway such as LiteLLM. The gateway must reach the control plane; with no fresh state
for `maxStateAgeSeconds` (15 minutes) it refuses requests rather than run on stale revocations.

### 3. Publish a policy

Write a normal [managed policy](../docs/user/managed-policy.md), check it with
`t3 policy check policy.json`, and publish it in the admin console's Policy tab. Devices fetch it
every 15 minutes and apply it at the next start. Typical limits: `connect: false`,
`clients: ["desktop"]`, `maxRuntimeMode`, `providers.allowedDrivers: ["claudeAgent", "codex"]`,
`telemetry: false`. Two limits exist for enterprise machines: `pairing: "sso"` lets another
browser pair only after its user signs in with the IdP as the machine's owner, and
`agentPullRequests` (`"draft"` or `"human-only"`) gates what agents may do with `gh pr`.

### 4. Devices

Deploy with your MDM, beside the policy location (`/Library/Application Support/T3Code/` on
macOS, `C:\Program Files\T3Code\` on Windows, `/etc/t3code/` on Linux):

`enterprise.json`, built from `t3-enterprise-control-plane trust --config …`:

```json
{
  "schemaVersion": 1,
  "organization": "Example Corp",
  "controlPlaneUrl": "https://t3.example.com",
  "gatewayUrl": "https://gateway.t3.example.com",
  "policyKeys": { "keys": [ … ] },
  "bootstrapPolicy": { "schemaVersion": 1, "organization": "Example Corp", "limits": { "connect": false, "maxRuntimeMode": "approval-required" } },
  "whenUnreachable": "use-cached-until-expiry"
}
```

Do not also deploy a `policy.json`: an enterprise machine takes its policy from the control plane
and refuses to start with both. Add `serverCaPem` if the control plane or gateway uses a private
CA.

Each user then enrolls from Settings → General → Organization, or with `t3 enterprise enroll`
(`--no-browser` over SSH), and signs in. The same section shows model access and the policy
version; when a newer policy arrives it offers **Restart to apply** (the desktop app restarts
itself; a server started from the CLI says to restart it). `t3 enterprise status` shows the same
in a terminal.

### Team features

- **Fleet and Activity** tabs show enrolled machines (version, health, active turns, policy) and a
  live feed of agent work, filterable by team.
- **Library**: skills, prompts, instructions, and MCP servers, for everyone or one team. Enrolled
  machines install them into Claude Code's and Codex's own folders and keep them in sync;
  unenrolling removes them.
- **Hand-offs**: a thread's menu has **Hand off to colleagues**. Colleagues find it under
  Settings → General → Organization and continue it as a new thread that starts from the
  transcript and the thread's changes as a patch.

### Operations

- **Rotate signing keys**: `t3-enterprise-control-plane rotate-keys` stages a key and prints the
  new `policyKeys`. Deploy them to devices, then run `activate-key` so the new key signs.
- **Offline behavior**: leases last `leaseTtlSeconds` (4 h). With `whenUnreachable:
  "use-cached-until-expiry"` a device keeps working until then; `"deny"` stops model calls as soon
  as a renewal fails. Policy tokens expire after `policyTtlSeconds` (24 h), after which the device
  falls back to `bootstrapPolicy`. Nothing widens when the control plane is unreachable.
- **Deactivate a leaver**: SCIM or the Users tab. Their devices are revoked and the gateway stops
  them within a sync.
