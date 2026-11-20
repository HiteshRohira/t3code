# Enterprise fork: plan

Status: Phase 1 built, Phase 2 partly · Owner: Hitesh · Base: fork of `pingdotgg/t3code` (MIT)

## 0. Progress

Operator guide: [README.md](README.md). Upstream edits: [UPSTREAM_TOUCHPOINTS.md](UPSTREAM_TOUCHPOINTS.md).

| Item                                                                        | State                                                              |
| --------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Milestone 1 (§10): gateway, control plane, leases, device agent, demo       | Done; verified with a real Claude Code turn through T3             |
| SSO (OIDC + PKCE), group → role mapping, allowed groups                     | Done (SAML not yet)                                                |
| Device enrollment, org CA, mTLS, cert-bound leases                          | Done (keys in files, not Secure Enclave/TPM yet)                   |
| Roles: admin, maintainer, auditor, developer, viewer                        | Done in the control plane                                          |
| Audit: device events, admin actions, JSONL/HTTP sinks, export API           | Done                                                               |
| Signed central policy, `whenUnreachable` modes (§7)                         | Done; policy applies at restart (upstream reads it once)           |
| SCIM 2.0 Users (Okta / Entra)                                               | Done (Groups endpoint not yet)                                     |
| Budgets per user and team, model allow-lists, rate limits, usage reports    | Done                                                               |
| Admin console                                                               | Done: users, devices, teams, policy, usage, audit                  |
| `t3 enterprise enroll / status / unenroll`                                  | Done                                                               |
| Enterprise status in the T3 Settings UI                                     | Not yet (CLI and in-chat errors only)                              |
| SSO-gated pairing for web/mobile clients (§4.4)                             | Not yet; restrict with `clients` and `connect: false`              |
| Secret redaction at the gateway, retention, data residency                  | Not yet                                                            |
| Codex through the gateway                                                   | Routed (`OPENAI_BASE_URL`), not yet verified with a real Codex CLI |
| Phase 3 team features, Phase 4 packaging (rebrand, signing, MDM installers) | Not yet; need decisions in §9                                      |

## 1. Goal

A version of T3 Code that a company can deploy to its developers, where:

- People sign in with the company's identity provider. Access ends when they leave.
- Model credentials (API keys, credit pools) belong to the org and never sit on a laptop.
- Only machines enrolled by the org can use those credentials. Stock T3 Code, or a personal
  install, cannot reach them, even when a developer has the URL.
- Admins set policy, see audit trails, and control spend centrally.

It keeps what makes T3 Code good: fast clients, remote-first architecture, and web, desktop and
mobile surfaces.

## 2. Key facts about upstream that shape this plan

There is **no central "main T3 Code server"** upstream. Each machine runs its own server, called an
_environment_. That server spawns provider CLIs (`claude`, `codex`, …) using credentials on that
machine. Clients (desktop, web, mobile) pair with an environment directly or through the T3 Connect
relay. So "pooled credits" doesn't exist yet. We have to add a new central component, and the
isolation question becomes: _who may talk to that component?_

Upstream already has extension points we can build on:

| Need                                                      | Upstream piece                                                                       | Where                                        |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------ | -------------------------------------------- |
| Lock settings, cap permission modes, allow-list providers | Managed policy (`policy.json` / MDM / GPO)                                           | `docs/user/managed-policy.md`                |
| Point providers at a gateway                              | `limits.providers.instances.<id>.environment` + pinned `binaryPath`                  | same                                         |
| Turn off the public relay                                 | `limits.connect: false`                                                              | same                                         |
| Restrict client types                                     | `limits.clients`                                                                     | same                                         |
| Private update channel                                    | `limits.updates.feedUrl`                                                             | same                                         |
| Roles                                                     | Scoped sessions (`orchestration:operate`, `terminal:operate`, `providers:manage`, …) | `packages/contracts`, `apps/server/src/auth` |
| Audit data                                                | Event-sourced orchestration: every command and event is already persisted            | `apps/server/src/orchestration-v2`           |
| Secrets                                                   | `secret-provider-core` (1Password adapter exists)                                    | `packages/secret-provider-*`                 |
| Self-hostable relay                                       | `infra/relay`                                                                        | `docs/internals/t3-connect.md`               |

## 3. Architecture

```
                         ┌───────────────────────────── Org network / cloud ─────────────────────────────┐
                         │                                                                               │
  Developer laptop       │   ┌─────────────────┐   ┌──────────────────┐   ┌──────────────────────────┐   │
  (MDM-enrolled)         │   │  Control Plane  │   │   LLM Gateway    │   │  Org Relay (self-hosted  │   │
 ┌──────────────────┐    │   │  - SSO / SCIM   │   │  - holds org     │   │  infra/relay, optional)  │   │
 │ Enterprise build │◀──mTLS─▶ - device enroll │   │    API keys      │   └──────────────────────────┘   │
 │  server + client │    │   │  - signed policy│   │  - budgets/quotas│                                  │
 │  device cert ────┼─mTLS + lease token──────────▶│  - audit of calls│──▶ Anthropic / OpenAI /         │
 │  provider CLIs   │    │   │  - leases       │   │                  │    Bedrock / Vertex / Azure      │
 └──────────────────┘    │   │  - audit sink   │   └──────────────────┘                                  │
                         │   └─────────────────┘                                                        │
                         └───────────────────────────────────────────────────────────────────────────────┘
```

New components, kept outside the upstream tree where possible:

1. **Control plane** (`enterprise/control-plane`): SSO (OIDC/SAML), SCIM, device enrollment, org/team/role
   model, signed policy distribution, credential leases, audit ingestion, admin UI.
2. **LLM gateway** (`enterprise/gateway`): an OpenAI/Anthropic-compatible proxy. It holds the real
   provider keys and enforces per-user/team budgets and model allow-lists. Start from an existing
   gateway (LiteLLM, Portkey, Envoy AI Gateway, or the cloud's native Bedrock/Vertex) instead of
   writing one. Only the auth hook is custom.
3. **Enterprise build** of the desktop app and server: upstream plus a small `enterprise` module
   that enrolls the device, fetches signed policy and leases, and pins the gateway and relay URLs.

## 4. Isolation: keeping stock T3 Code out

The property we need: **a valid org credential only ever reaches an enrolled device, for a signed-in
org user, for a short time.** Stock T3 Code fails each check below without us needing to detect it.

### 4.1 The keys never leave the gateway

Laptops never receive a real Anthropic or OpenAI key. Provider CLIs get:

- `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` (and Bedrock/Vertex equivalents) → the org gateway
- `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` → a **lease token** (short-lived, per user, per device)

So the most a stolen laptop or a copied config can leak is a lease that expires within hours and is
bound to a device certificate it can't use somewhere else.

### 4.2 The gateway only accepts enrolled devices

Every gateway request needs **both** of these:

1. **mTLS with a device certificate** issued by the org's CA during MDM enrollment. Its private key
   lives in the Secure Enclave, TPM or Keychain where possible. Stock T3 Code doesn't present one, so
   the TLS handshake fails before any HTTP request is made.
2. **A lease token** from the control plane. It's minted only after SSO login, bound to the device
   cert's fingerprint (the same idea as upstream's DPoP binding), and checked against the gateway's
   revocation list.

Put the gateway behind private networking (VPN, Zero Trust such as Cloudflare Access or Tailscale
ACLs, or a VPC endpoint) for defence in depth. That way it isn't reachable from the public internet
at all.

### 4.3 The control plane only enrolls org devices

- Enrollment requires an MDM-delivered bootstrap (a configuration profile or Intune package that
  installs the device cert and `policy.json`) **plus** an SSO login by a user in the right group.
- SCIM deprovisioning or a device wipe revokes the cert and every outstanding lease.

### 4.4 Enterprise clients only talk to enterprise environments

The reverse direction matters too. A developer shouldn't pair their work environment with a personal
phone through the public relay, or point the work client at a personal server.

- Policy: `limits.connect: false` (or connect only to the org relay), `limits.clients: ["desktop"]`,
  or allow the browser/mobile client only through the org relay.
- The enterprise server refuses pairing unless the client proves the same org identity (SSO session
  exchanged for an environment session). This is a new auth path next to pairing codes.
- Mobile: distribute through MDM (managed App Store / Managed Google Play) with an app config that
  pins the org relay.

### 4.5 What this does not stop

Be honest about these limits in the plan:

- A user with admin rights on their laptop can patch the build. That's why the real boundary is
  _keys stay in the gateway_ and _leases are short and device-bound_, not _the binary is trusted_.
  Binary attestation is a later, optional hardening step.
- An enrolled user can still copy their lease plus device cert within the lease window. Budgets,
  rate limits, anomaly alerts and the audit log cover that.
- Code leaving the laptop through the agent's own tools (curl, git push) is a sandbox and egress
  concern (network policy and devcontainers). The policy layer can't solve it alone. See
  `docs/user/managed-policy.md` → "What a policy does not cover".

## 5. Features by phase

### Phase 1: Wedge (things procurement requires)

1. **SSO sign-in** (OIDC first, SAML second) to the control plane and to enterprise environments.
2. **Device enrollment + mTLS certs** via MDM bootstrap.
3. **LLM gateway with leased credentials** for Claude and Codex first.
4. **Roles** mapped onto existing scopes: Admin, Maintainer, Developer, Viewer, Auditor.
5. **Audit log export**: stream orchestration events (thread started, permission mode, approvals,
   commands run, files written, PR opened) to the control plane, then to a SIEM (Splunk, Datadog,
   S3). This is a projection of events already stored, not new instrumentation.
6. **Signed central policy**: the same schema as upstream `policy.json`, served by the control plane
   and signed by it. The server verifies the signature and caches it (see §7).

### Phase 2: Governance

- SCIM provisioning and deprovisioning.
- Budgets and quotas per user, team or project, enforced at the gateway, with alerts and hard caps.
- Chargeback reports by team, repo and model.
- Model allow-lists per team. Cheap models for scheduled tasks.
- Approved-MCP-server and command deny lists.
- Secret scanning and redaction on prompts at the gateway.
- Retention, legal hold and data residency settings.

### Phase 3: Team features

- Org-shared threads and handoffs, with checkpoints.
- Org libraries for prompts, skills, MCP configs and team-level `AGENTS.md`.
- Fleet view: every environment, its version, health and active agents.
- A lead's "watch" view of live agent work across a team.
- Human-approval gates on agent PRs.

### Phase 4: Deployment options

- Self-hosted relay (`infra/relay`) per org.
- Air-gapped and on-prem install, with a private update feed (`limits.updates.feedUrl`).
- Pinned versions per ring (canary, then everyone).
- Signed builds and notarization under the company's own Apple and Windows certificates.

## 6. Fork strategy (replaces "don't fork the core")

Earlier advice said "don't fork the core". That was written as if this would land upstream. As an
outside fork, forking is the plan. The real concern is **staying able to pull upstream every week**.
Upstream ships many commits a day, and a fork that drifts falls behind on providers, fixes and
security patches within a month.

Rules to stay mergeable:

1. **New code lives in new places.** Control plane, gateway auth hook and admin UI go under
   `enterprise/` (or `apps/enterprise-*`, `packages/enterprise-*`). Upstream never touches those
   paths, so they never conflict.
2. **Touch upstream files through seams, not edits.** Prefer adding a Layer or service
   implementation that upstream code already depends on, such as a policy source, a secret provider,
   or an auth method, over editing call sites. Each upstream file we modify is a future merge
   conflict. Keep a list of them in `enterprise/UPSTREAM_TOUCHPOINTS.md`.
3. **Use what policy already does.** Gateway URLs, locked provider instances, disabling Connect,
   client restrictions and the update feed are already supported. Configure them rather than
   reimplementing them.
4. **Rebase or merge `remote/main` weekly**, run `vp run check:changed`, and keep a CI job that
   tries the merge nightly so drift shows up early.
5. **Upstream generic seams when possible.** If a hook would be useful to anyone, such as "policy
   from a signed URL" or "OIDC environment login", propose it upstream as a small PR. Every seam
   upstream accepts is one less patch we carry. Follow upstream `CONTRIBUTING.md`.
6. **Rebrand the shipped product.** The code is MIT, but "T3 Code" is upstream's name. Ship under
   our own name, bundle ID (not `com.t3tools.t3code`), policy domain, icons and update feed, so it
   installs side by side with personal T3 Code and the two can't be confused.

## 7. Online vs. offline control plane

My earlier note, "don't require an always-online control plane", was too short. Many enterprises
require online checks, and that's a valid choice. The real question is narrower: **what happens to
a developer's running work when the control plane can't be reached?** That can happen in two
different ways:

- **The laptop is offline** (plane, train, captive Wi-Fi). Note that agents need network to reach
  models anyway, so "offline" mostly means the gateway is reachable but the control plane isn't.
  That's rare, and it's usually covered by running both behind the same network path.
- **The control plane is down** (deploy, outage, IdP outage). This is the real risk. If every server
  checks the control plane on every action, one outage stops every agent turn in the company at
  once, mid-edit.

The decision is about **where checks happen and what a missed check does**, not whether to be online.

### Recommended model: online to start, cached while running, fail closed on expiry

| Moment                                         | Check                                                     | Needs control plane?                     |
| ---------------------------------------------- | --------------------------------------------------------- | ---------------------------------------- |
| Sign-in / device enrollment                    | SSO + device cert                                         | Yes, always                              |
| Lease issue/renew (every 1–8 h, set by policy) | User still active, device not revoked, budget left        | Yes                                      |
| Policy fetch                                   | Signed policy, cached on disk with signature + expiry     | Yes to refresh; cached copy used between |
| Each command, turn and approval                | Enforced **locally** from cached signed policy            | No                                       |
| Each model call                                | Gateway checks lease + mTLS + budget                      | Gateway yes, control plane no            |
| Audit events                                   | Buffered locally, shipped when reachable, with gap alerts | No (eventually consistent)               |

This gives security teams what they want: revocation takes effect within one lease window, and the
gateway can revoke instantly. And a control plane deploy doesn't freeze 500 agents in the middle of
a turn.

### Make strictness a policy setting

Different orgs will want different trade-offs, so expose it rather than hard-coding it:

```json
{
  "controlPlane": {
    "url": "https://t3.corp.example.com",
    "leaseTtl": "4h",
    "policyMaxStaleness": "24h",
    "whenUnreachable": "use-cached-until-expiry"
  }
}
```

- `"use-cached-until-expiry"` (default): keep working on cached policy and lease until they expire,
  then stop and show "Reconnect to Corp to continue".
- `"deny"`: strict mode for regulated orgs. Stop new turns as soon as a lease renewal or policy check
  fails. Let the current turn finish or interrupt it cleanly, and never leave a half-applied edit.
- No fail-open mode. An unreachable control plane never _widens_ permissions.

Requirements either way:

- Run the control plane highly available, with the gateway able to validate leases without it
  (signed tokens plus a revocation list it pulls).
- The UI shows an honest status (connected / using cached policy until 14:00 / blocked), not a
  spinner that hides what's going on.
- Audit buffering has a size cap and an admin alert when a device stops reporting.

## 8. Other things to resist

- **Policy checks on the hot path.** Enforce at command execution, where upstream already checks
  grants. Never add a network round-trip per streamed token or WebSocket event. Performance is the
  product.
- **Building our own LLM gateway from scratch.** Adopt one and write only the lease/mTLS auth hook.
- **A second policy language.** Extend upstream's `policy.json` schema so admins and docs stay
  consistent and `t3 policy check` keeps working.
- **Trusting the client binary.** Design so a patched binary gains nothing beyond what its
  short-lived, device-bound lease allows.
- **An enterprise-only client fork of web or mobile UI.** Add org features as screens behind a
  capability flag, so upstream UI changes keep merging cleanly.

## 9. Open questions

- Which IdP and MDM do the first target customers use (Okta / Entra; Jamf / Intune / Kandji)?
- Which providers are in scope first? Claude Code and Codex both support base URL overrides. Cursor,
  Grok and others need a per-adapter decision.
- Hosted SaaS control plane, customer-hosted, or both?
- Is the browser/mobile client in scope for Phase 1, or desktop only?
- Data residency: do prompts and audit logs need to stay in a region?
- Product name and bundle ID for the rebrand.

## 10. First milestone (proof of concept)

1. Gateway (LiteLLM or similar) with one org Anthropic key, mTLS required, and a lease-token auth
   hook.
2. Minimal control plane: OIDC login, issues device certs from a dev CA and 4 h leases bound to the
   cert.
3. Upstream `policy.json` that pins `claudeAgent` to the gateway URL and the lease variable, with
   `connect: false` and `clients: ["desktop"]`.
4. Small enterprise module in the server that fetches and renews the lease and injects it into the
   provider instance environment.
5. Demo: an enrolled laptop runs a Claude turn through the gateway. Stock T3 Code with the same URL
   gets a TLS failure. Revoking the user stops new turns within one lease window.
