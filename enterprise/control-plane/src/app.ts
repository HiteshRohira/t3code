import * as NodeCrypto from "node:crypto";
import type * as NodeHttp from "node:http";

import { certificateThumbprint } from "@t3tools/enterprise-protocol/thumbprint";
import { publicJwks, signLease, signPolicy } from "@t3tools/enterprise-protocol/tokens";
import {
  enrollmentProofMessage,
  LEASE_ROLES,
  paths,
  type AuditBatch,
  type AuditEvent,
  type EnrollRequest,
  type EnrollResponse,
  type GatewayState,
  type LeaseDenial,
  type LeaseResponse,
  type Role,
  type UsageBatch,
  type UsageRecord,
} from "@t3tools/enterprise-protocol/wire";

import { handleAdmin, type AdminActor } from "./admin.ts";
import { AuditFanout } from "./auditSinks.ts";
import { InvalidDeviceKey, issueDeviceCertificate, type CertificateAuthority } from "./ca.ts";
import type { ControlPlaneConfig } from "./config.ts";
import {
  bearer,
  constantTimeEqual,
  cookie,
  escapeHtml,
  HttpError,
  readForm,
  readJson,
  redirect,
  sendError,
  sendHtml,
  sendJson,
  verifiedClientCertificate,
} from "./http.ts";
import type { SigningKeys } from "./keys.ts";
import { OidcClient, randomToken, type OidcIdentity } from "./oidc.ts";
import { handleScim } from "./scim.ts";
import { monthOf, type Device, type Store, type User } from "./store.ts";

const LOGIN_TTL_MS = 10 * 60 * 1000;
const SESSION_TTL_MS = 8 * 3600 * 1000;
const ENROLLMENT_CODE_TTL_SECONDS = 5 * 60;
const SESSION_COOKIE = "t3e_session";

type PendingLogin =
  | { kind: "admin"; verifier: string; nonce: string; expiresAt: number }
  | {
      kind: "enroll";
      verifier: string;
      nonce: string;
      expiresAt: number;
      deviceRedirect: string;
      deviceState: string;
    };

export interface ControlPlaneOptions {
  readonly config: ControlPlaneConfig;
  readonly store: Store;
  readonly ca: CertificateAuthority;
  readonly keys: SigningKeys;
  readonly fetch?: typeof fetch;
}

/** Loopback HTTP only, so a code can never be delivered to another host. */
export function isLoopbackRedirect(value: string): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  return (
    url.protocol === "http:" &&
    (url.hostname === "127.0.0.1" || url.hostname === "[::1]" || url.hostname === "localhost") &&
    url.username === "" &&
    url.password === ""
  );
}

export class ControlPlane {
  readonly config: ControlPlaneConfig;
  readonly store: Store;
  readonly ca: CertificateAuthority;
  readonly keys: SigningKeys;
  readonly audit: AuditFanout;
  readonly #oidc: OidcClient | undefined;
  readonly #pending = new Map<string, PendingLogin>();
  readonly #sessions = new Map<string, { userId: string; expiresAt: number }>();

  constructor(options: ControlPlaneOptions) {
    this.config = options.config;
    this.store = options.store;
    this.ca = options.ca;
    this.keys = options.keys;
    this.audit = new AuditFanout(options.config.auditSinks, options.fetch ?? fetch);
    this.#oidc =
      options.config.oidc === undefined
        ? undefined
        : new OidcClient(options.config.oidc, options.fetch);
  }

  readonly handle = async (
    request: NodeHttp.IncomingMessage,
    response: NodeHttp.ServerResponse,
  ) => {
    try {
      await this.#route(request, response);
    } catch (error) {
      if (error instanceof HttpError) {
        sendError(response, error);
        return;
      }
      console.error("[control-plane] request failed", error);
      if (!response.headersSent)
        sendError(response, new HttpError(500, "internal", "internal error"));
      else response.destroy();
    }
  };

  async #route(request: NodeHttp.IncomingMessage, response: NodeHttp.ServerResponse) {
    const url = new URL(request.url ?? "/", this.config.publicUrl);
    const method = request.method ?? "GET";
    const route = `${method} ${url.pathname}`;

    switch (route) {
      case `GET ${paths.health}`:
        return sendJson(response, 200, { ok: true });
      case `GET ${paths.jwks}`:
        return sendJson(response, 200, publicJwks(this.keys.all));
      case `GET ${paths.enrollStart}`:
        return this.#startEnrollment(url, response);
      case "GET /admin/login":
        return this.#beginLogin(response, { kind: "admin" });
      case "GET /oidc/callback":
        return this.#oidcCallback(url, response);
      case "GET /dev/login":
        return this.#devLoginForm(url, response);
      case "POST /dev/login":
        return this.#devLogin(request, response);
      case "POST /admin/logout":
        return this.#logout(request, response);
      case `POST ${paths.enroll}`:
        return this.#enroll(request, response);
      case `POST ${paths.lease}`:
        return this.#lease(request, response);
      case `GET ${paths.policy}`:
        return this.#policy(request, response);
      case `POST ${paths.audit}`:
        return this.#ingestAudit(request, response);
      case `GET ${paths.gatewayState}`:
        this.#requireGateway(request);
        return sendJson(response, 200, this.gatewayState());
      case `POST ${paths.gatewayUsage}`:
        return this.#ingestUsage(request, response);
    }
    if (url.pathname.startsWith("/scim/v2/")) {
      return handleScim(this, request, response, url);
    }
    if (
      url.pathname === "/admin" ||
      url.pathname.startsWith("/admin/") ||
      url.pathname.startsWith("/v1/admin/")
    ) {
      return handleAdmin(this, request, response, url);
    }
    throw new HttpError(404, "not_found", "no such route");
  }

  // Sign-in

  #startEnrollment(url: URL, response: NodeHttp.ServerResponse) {
    const deviceRedirect = url.searchParams.get("redirect_uri") ?? "";
    const deviceState = url.searchParams.get("state") ?? "";
    if (!isLoopbackRedirect(deviceRedirect)) {
      throw new HttpError(400, "invalid_redirect", "redirect_uri must be a loopback http URL");
    }
    if (deviceState.length < 16) throw new HttpError(400, "invalid_state", "state is too short");
    return this.#beginLogin(response, { kind: "enroll", deviceRedirect, deviceState });
  }

  async #beginLogin(
    response: NodeHttp.ServerResponse,
    login: { kind: "admin" } | { kind: "enroll"; deviceRedirect: string; deviceState: string },
  ) {
    this.#sweep();
    const state = randomToken();
    const pending: PendingLogin = {
      ...login,
      verifier: randomToken(48),
      nonce: randomToken(),
      expiresAt: Date.now() + LOGIN_TTL_MS,
    };
    this.#pending.set(state, pending);
    if (this.#oidc === undefined) {
      return redirect(response, `/dev/login?state=${encodeURIComponent(state)}`);
    }
    return redirect(
      response,
      await this.#oidc.authorizationUrl({
        redirectUri: `${this.config.publicUrl}/oidc/callback`,
        state,
        nonce: pending.nonce,
        codeVerifier: pending.verifier,
      }),
    );
  }

  #takePending(state: string | null): PendingLogin {
    const pending = state === null ? undefined : this.#pending.get(state);
    if (state !== null) this.#pending.delete(state);
    if (pending === undefined || pending.expiresAt < Date.now()) {
      throw new HttpError(400, "login_expired", "this sign-in link expired; start again");
    }
    return pending;
  }

  async #oidcCallback(url: URL, response: NodeHttp.ServerResponse) {
    if (this.#oidc === undefined) throw new HttpError(404, "not_found", "OIDC is not configured");
    const error = url.searchParams.get("error");
    const pending = this.#takePending(url.searchParams.get("state"));
    if (error !== null) {
      return sendHtml(response, 403, page("Sign-in failed", `<p>${escapeHtml(error)}</p>`));
    }
    const identity = await this.#oidc.exchange({
      code: url.searchParams.get("code") ?? "",
      redirectUri: `${this.config.publicUrl}/oidc/callback`,
      codeVerifier: pending.verifier,
      nonce: pending.nonce,
    });
    return this.#completeLogin(response, pending, identity);
  }

  #devLoginForm(url: URL, response: NodeHttp.ServerResponse) {
    if (!this.config.insecureDevLogin) throw new HttpError(404, "not_found", "no such route");
    const state = url.searchParams.get("state") ?? "";
    return sendHtml(
      response,
      200,
      page(
        "Development sign-in",
        `<p>This control plane has no identity provider. Anyone who can reach it can sign in as anyone.</p>
         <form method="post" action="/dev/login">
           <input type="hidden" name="state" value="${escapeHtml(state)}">
           <label>Email <input name="email" type="email" required autofocus></label>
           <label>Groups (comma separated) <input name="groups"></label>
           <button>Sign in</button>
         </form>`,
      ),
    );
  }

  async #devLogin(request: NodeHttp.IncomingMessage, response: NodeHttp.ServerResponse) {
    if (!this.config.insecureDevLogin) throw new HttpError(404, "not_found", "no such route");
    const form = await readForm(request);
    const pending = this.#takePending(form.get("state"));
    const email = (form.get("email") ?? "").trim().toLowerCase();
    if (!email.includes("@")) throw new HttpError(400, "invalid_email", "enter an email");
    const groups = (form.get("groups") ?? "")
      .split(",")
      .map((group) => group.trim())
      .filter((group) => group.length > 0);
    return this.#completeLogin(response, pending, { subject: email, email, name: null, groups });
  }

  /** IdP groups decide roles when any are mapped; otherwise the stored roles stand. */
  #rolesFromGroups(groups: ReadonlyArray<string>): ReadonlyArray<Role> | undefined {
    const mapping = this.config.oidc?.groupRoles ?? {};
    if (Object.keys(mapping).length === 0) return undefined;
    const roles = [
      ...new Set(groups.flatMap((group) => (mapping[group] === undefined ? [] : [mapping[group]]))),
    ];
    return roles.length === 0 ? [this.config.defaultRole] : roles;
  }

  resolveLogin(identity: OidcIdentity): User {
    const allowed = this.config.oidc?.allowedGroups;
    if (allowed !== undefined && !identity.groups.some((group) => allowed.includes(group))) {
      throw new HttpError(
        403,
        "not_allowed",
        "your account is not in a group allowed to use T3 Enterprise",
      );
    }
    const roles = this.#rolesFromGroups(identity.groups);
    const existing = this.store.userByEmail(identity.email);
    if (existing === undefined) {
      if (this.config.provisioning === "scim") {
        throw new HttpError(
          403,
          "not_provisioned",
          "your account has not been provisioned for T3 Enterprise",
        );
      }
      return this.store.createUser({
        email: identity.email,
        name: identity.name,
        roles: roles ?? [this.config.defaultRole],
      });
    }
    if (!existing.active) throw new HttpError(403, "user_inactive", "your account is deactivated");
    return roles === undefined
      ? existing
      : (this.store.updateUser(existing.id, { roles }) ?? existing);
  }

  #completeLogin(response: NodeHttp.ServerResponse, pending: PendingLogin, identity: OidcIdentity) {
    let user: User;
    try {
      user = this.resolveLogin(identity);
    } catch (error) {
      if (error instanceof HttpError) {
        return sendHtml(
          response,
          error.status,
          page("Cannot sign in", `<p>${escapeHtml(error.message)}</p>`),
        );
      }
      throw error;
    }
    if (pending.kind === "enroll") {
      const code = randomToken();
      this.store.createEnrollmentCode(user.id, code, ENROLLMENT_CODE_TTL_SECONDS);
      const target = new URL(pending.deviceRedirect);
      target.searchParams.set("code", code);
      target.searchParams.set("state", pending.deviceState);
      return redirect(response, target.toString());
    }
    if (
      !user.roles.some((role) => role === "admin" || role === "maintainer" || role === "auditor")
    ) {
      return sendHtml(
        response,
        403,
        page("No admin access", "<p>Your account has no admin role.</p>"),
      );
    }
    const sessionId = randomToken();
    this.#sessions.set(sessionId, { userId: user.id, expiresAt: Date.now() + SESSION_TTL_MS });
    return redirect(response, "/admin", {
      "set-cookie": `${SESSION_COOKIE}=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL_MS / 1000}`,
    });
  }

  #logout(request: NodeHttp.IncomingMessage, response: NodeHttp.ServerResponse) {
    const sessionId = cookie(request, SESSION_COOKIE);
    if (sessionId !== undefined) this.#sessions.delete(sessionId);
    return redirect(response, "/admin", {
      "set-cookie": `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
    });
  }

  /** The signed-in admin, or the automation token acting as one. */
  adminActor(request: NodeHttp.IncomingMessage): AdminActor | undefined {
    const token = bearer(request);
    const apiToken = this.config.secrets.adminApiToken;
    if (token !== undefined && apiToken !== undefined && constantTimeEqual(token, apiToken)) {
      return { id: "api", email: "api", roles: ["admin"], viaCookie: false };
    }
    const sessionId = cookie(request, SESSION_COOKIE);
    const session = sessionId === undefined ? undefined : this.#sessions.get(sessionId);
    if (session === undefined || session.expiresAt < Date.now()) return undefined;
    const user = this.store.userById(session.userId);
    if (user === undefined || !user.active) return undefined;
    return { id: user.id, email: user.email, roles: user.roles, viaCookie: true };
  }

  #sweep() {
    const now = Date.now();
    for (const [key, value] of this.#pending) if (value.expiresAt < now) this.#pending.delete(key);
    for (const [key, value] of this.#sessions)
      if (value.expiresAt < now) this.#sessions.delete(key);
  }

  // Enrollment

  async #enroll(request: NodeHttp.IncomingMessage, response: NodeHttp.ServerResponse) {
    const body = (await readJson(request, 64 * 1024)) as Partial<EnrollRequest>;
    if (
      typeof body.code !== "string" ||
      typeof body.publicKeyPem !== "string" ||
      typeof body.proof !== "string" ||
      typeof body.hostname !== "string" ||
      typeof body.platform !== "string"
    ) {
      throw new HttpError(
        400,
        "invalid_request",
        "code, publicKeyPem, proof, hostname, platform are required",
      );
    }
    let proven = false;
    try {
      proven = NodeCrypto.verify(
        "sha256",
        Buffer.from(enrollmentProofMessage(body.code)),
        NodeCrypto.createPublicKey(body.publicKeyPem),
        Buffer.from(body.proof, "base64url"),
      );
    } catch {
      proven = false;
    }
    if (!proven) throw new HttpError(400, "invalid_proof", "proof does not match the device key");
    const userId = this.store.redeemEnrollmentCode(body.code);
    const user = userId === undefined ? undefined : this.store.userById(userId);
    if (user === undefined)
      throw new HttpError(400, "invalid_code", "enrollment code is unknown, used, or expired");
    if (!user.active) throw new HttpError(403, "user_inactive", "this account is deactivated");

    const deviceId = NodeCrypto.randomUUID();
    let issued: { certPem: string; expiresAt: Date };
    try {
      issued = issueDeviceCertificate(this.ca, {
        publicKeyPem: body.publicKeyPem,
        deviceId,
        userId: user.id,
        days: this.config.deviceCertDays,
      });
    } catch (error) {
      if (error instanceof InvalidDeviceKey) throw new HttpError(400, "invalid_key", error.message);
      throw error;
    }
    this.store.createDevice({
      id: deviceId,
      userId: user.id,
      thumbprint: certificateThumbprint(issued.certPem),
      hostname: body.hostname.slice(0, 255),
      platform: body.platform.slice(0, 64),
      clientVersion:
        typeof body.clientVersion === "string" ? body.clientVersion.slice(0, 64) : null,
      expiresAt: issued.expiresAt.toISOString(),
    });
    await this.recordAdminEvent({ id: user.id, email: user.email }, "device.enrolled", {
      deviceId,
      hostname: body.hostname,
      platform: body.platform,
    });
    const result: EnrollResponse = {
      deviceId,
      certificatePem: issued.certPem,
      caPem: this.ca.certPem,
      expiresAt: issued.expiresAt.toISOString(),
      user: { email: user.email, roles: user.roles },
    };
    return sendJson(response, 200, result);
  }

  // Device routes: a CA-signed client certificate for a live device of an active user.

  #device(request: NodeHttp.IncomingMessage): { device: Device; user: User } {
    const certificate = verifiedClientCertificate(request);
    if (certificate === undefined) {
      throw new HttpError(401, "device_unknown", "present an enrolled device certificate");
    }
    const device = this.store.deviceByThumbprint(certificateThumbprint(certificate));
    if (device === undefined)
      throw new HttpError(401, "device_unknown", "this device is not enrolled");
    const denial = this.deviceDenial(device);
    if (denial !== undefined) throw new HttpError(403, denial, denialMessage(denial));
    const user = this.store.userById(device.userId)!;
    this.store.touchDevice(device.id);
    return { device, user };
  }

  deviceDenial(device: Device): LeaseDenial | undefined {
    if (device.revokedAt !== null) return "device_revoked";
    if (new Date(device.expiresAt).getTime() < Date.now()) return "device_expired";
    const user = this.store.userById(device.userId);
    if (user === undefined || !user.active) return "user_inactive";
    return undefined;
  }

  /** User and team limits; a user over either is over budget. */
  budgetOf(user: User, month = monthOf(new Date())) {
    const team = user.team === null ? undefined : this.store.team(user.team);
    const userLimit = user.monthlyTokens ?? this.config.defaultMonthlyTokens ?? null;
    const used = this.store.tokensUsed(user.id, month);
    const teamLimit = team?.monthlyTokens ?? null;
    const teamUsed =
      team === undefined || teamLimit === null ? null : this.store.teamTokensUsed(team.name, month);
    const over =
      (userLimit !== null && used >= userLimit) ||
      (teamLimit !== null && teamUsed !== null && teamUsed >= teamLimit);
    return { month, used, limit: userLimit, team: team?.name ?? null, teamUsed, teamLimit, over };
  }

  modelsOf(user: User): ReadonlyArray<string> | undefined {
    if (user.models !== null) return user.models;
    const team = user.team === null ? undefined : this.store.team(user.team);
    return team?.models ?? this.config.defaultModels;
  }

  async #lease(request: NodeHttp.IncomingMessage, response: NodeHttp.ServerResponse) {
    const { device, user } = this.#device(request);
    if (!user.roles.some((role) => LEASE_ROLES.includes(role))) {
      throw new HttpError(403, "role_denied", denialMessage("role_denied"));
    }
    if (this.budgetOf(user).over)
      throw new HttpError(403, "over_budget", denialMessage("over_budget"));
    const leaseId = NodeCrypto.randomUUID();
    const models = this.modelsOf(user);
    const lease = await signLease(
      this.keys.active,
      {
        userId: user.id,
        email: user.email,
        deviceId: device.id,
        roles: user.roles,
        thumbprint: device.thumbprint,
        leaseId,
        ...(models === undefined ? {} : { models }),
      },
      { issuer: this.config.publicUrl, ttlSeconds: this.config.leaseTtlSeconds },
    );
    const expiresAt = new Date(Date.now() + this.config.leaseTtlSeconds * 1000);
    this.store.recordLease({ id: leaseId, userId: user.id, deviceId: device.id, expiresAt });
    const result: LeaseResponse = {
      lease,
      expiresAt: expiresAt.toISOString(),
      user: { id: user.id, email: user.email, roles: user.roles },
    };
    return sendJson(response, 200, result);
  }

  async #policy(request: NodeHttp.IncomingMessage, response: NodeHttp.ServerResponse) {
    this.#device(request);
    const current = this.store.currentPolicy();
    if (current === undefined)
      throw new HttpError(404, "no_policy", "no policy has been published");
    const policy = await signPolicy(
      this.keys.active,
      { version: current.version, document: current.document },
      { issuer: this.config.publicUrl, ttlSeconds: this.config.policyTtlSeconds },
    );
    return sendJson(response, 200, { policy });
  }

  async #ingestAudit(request: NodeHttp.IncomingMessage, response: NodeHttp.ServerResponse) {
    const { device, user } = this.#device(request);
    const body = (await readJson(request, 4 * 1024 * 1024)) as Partial<AuditBatch>;
    if (!Array.isArray(body.events) || body.events.length > 1000) {
      throw new HttpError(400, "invalid_request", "events must be a list of at most 1000");
    }
    const events = body.events.filter(isAuditEvent);
    const stored = this.store.appendAudit({ id: device.id, userId: user.id }, events);
    await this.audit.publish(stored.map((event) => ({ ...event, email: user.email })));
    return sendJson(response, 200, { accepted: events.length });
  }

  /** Org actions (enrollment, revocations, policy changes) land in the same audit trail. */
  async recordAdminEvent(
    actor: { id: string; email: string },
    type: string,
    detail: Record<string, unknown>,
  ) {
    const stored = this.store.appendAudit({ id: "control-plane", userId: actor.id }, [
      { id: NodeCrypto.randomUUID(), occurredAt: new Date().toISOString(), type, detail },
    ]);
    await this.audit.publish(stored.map((event) => ({ ...event, email: actor.email })));
  }

  // Gateway routes

  #requireGateway(request: NodeHttp.IncomingMessage) {
    const token = bearer(request);
    if (token === undefined || !constantTimeEqual(token, this.config.secrets.gatewayToken)) {
      throw new HttpError(401, "unauthorized", "gateway token required");
    }
  }

  gatewayState(): GatewayState {
    const overBudgetUsers = this.store
      .listUsers()
      .filter((user) => user.active && this.budgetOf(user).over)
      .map((user) => user.id);
    return {
      generatedAt: new Date().toISOString(),
      revokedDevices: this.store.revokedDeviceIds(),
      inactiveUsers: this.store.inactiveUserIds(),
      overBudgetUsers,
    };
  }

  async #ingestUsage(request: NodeHttp.IncomingMessage, response: NodeHttp.ServerResponse) {
    this.#requireGateway(request);
    const body = (await readJson(request, 4 * 1024 * 1024)) as Partial<UsageBatch>;
    if (!Array.isArray(body.records))
      throw new HttpError(400, "invalid_request", "records must be a list");
    const records = body.records.filter(isUsageRecord);
    this.store.recordUsage(records);
    return sendJson(response, 200, { accepted: records.length, state: this.gatewayState() });
  }
}

function denialMessage(denial: LeaseDenial): string {
  switch (denial) {
    case "device_unknown":
      return "this device is not enrolled";
    case "device_revoked":
      return "this device was revoked by your organization; enroll it again";
    case "device_expired":
      return "this device's certificate expired; enroll it again";
    case "user_inactive":
      return "your account is deactivated";
    case "role_denied":
      return "your role cannot use model credits";
    case "over_budget":
      return "you have used this month's model budget";
  }
}

const isAuditEvent = (value: unknown): value is AuditEvent => {
  if (typeof value !== "object" || value === null) return false;
  const event = value as Record<string, unknown>;
  return (
    typeof event["id"] === "string" &&
    event["id"].length <= 128 &&
    typeof event["type"] === "string" &&
    event["type"].length <= 128 &&
    typeof event["occurredAt"] === "string" &&
    !Number.isNaN(Date.parse(event["occurredAt"]))
  );
};

const isUsageRecord = (value: unknown): value is UsageRecord => {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    typeof record["id"] === "string" &&
    typeof record["userId"] === "string" &&
    typeof record["deviceId"] === "string" &&
    typeof record["provider"] === "string" &&
    typeof record["model"] === "string" &&
    typeof record["inputTokens"] === "number" &&
    typeof record["outputTokens"] === "number" &&
    typeof record["status"] === "number" &&
    typeof record["occurredAt"] === "string" &&
    !Number.isNaN(Date.parse(record["occurredAt"]))
  );
};

export function page(title: string, body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title><link rel="stylesheet" href="/admin/assets/admin.css"></head>
<body><main class="narrow"><h1>${escapeHtml(title)}</h1>${body}</main></body></html>`;
}
