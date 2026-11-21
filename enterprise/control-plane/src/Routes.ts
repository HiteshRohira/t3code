/**
 * Routes - sign-in (OIDC, SAML, development), device enrollment, and the routes enrolled
 * devices and gateways call.
 *
 * @module Routes
 */
import { publicJwks } from "@t3tools/enterprise-protocol/tokens";
import {
  AuditBatch,
  EnrollRequest,
  Heartbeat,
  paths,
  UsageBatch,
} from "@t3tools/enterprise-protocol/wire";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Predicate from "effect/Predicate";
import { HttpRouter, HttpServerRequest } from "effect/http";

import { ControlPlaneConfig } from "./Config.ts";
import { ControlPlane, Refusal } from "./ControlPlane.ts";
import * as Crypto from "./Crypto.ts";
import {
  asset,
  bearer,
  clientCertificate,
  escapeHtml,
  html,
  json,
  messagePage,
  page,
  readForm,
  readJson,
  redirect,
  respond,
  respondPage,
  searchParams,
} from "./Http.ts";
import { Oidc, type Identity } from "./Oidc.ts";
import * as Pairing from "./Pairing.ts";
import { SAML_CALLBACK_PATH, Saml } from "./Saml.ts";
import { SESSION_TTL_SECONDS, Sessions, type PendingLogin } from "./Sessions.ts";
import * as SigningKeys from "./SigningKeys.ts";

export const SESSION_COOKIE = "t3e_session";
const OIDC_CALLBACK_PATH = "/oidc/callback";

/** Loopback HTTP only, so an enrollment code can never be delivered to another host. */
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

const refuse = (status: number, code: string, reason: string) =>
  Effect.fail(new Refusal({ status, code, reason }));

const loginExpired = () => refuse(400, "login_expired", "this sign-in link expired; start again");

/** Sends the browser to the IdP: OIDC when configured, else SAML, else the development form. */
const beginLogin = Effect.fn("Routes.beginLogin")(function* (
  purpose: Parameters<Sessions["Service"]["begin"]>[0],
) {
  const config = yield* ControlPlaneConfig;
  const sessions = yield* Sessions;
  const { state, pending } = yield* sessions.begin(purpose);
  if (config.oidc !== undefined) {
    const oidc = yield* Oidc;
    return redirect(
      yield* oidc.authorizationUrl({
        redirectUri: `${config.publicUrl}${OIDC_CALLBACK_PATH}`,
        state,
        nonce: pending.nonce,
        codeVerifier: pending.verifier,
      }),
    );
  }
  const saml = yield* Saml;
  if (saml.configured) return redirect(yield* saml.authorizationUrl(state));
  return redirect(`/dev/login?state=${encodeURIComponent(state)}`);
});

/** The IdP vouched for `identity`; finish whatever the sign-in was for. */
const completeLogin = Effect.fn("Routes.completeLogin")(function* (
  pending: PendingLogin,
  identity: Identity,
) {
  const plane = yield* ControlPlane;
  const sessions = yield* Sessions;
  const resolved = yield* plane.resolveLogin(identity).pipe(Effect.result);
  if (resolved._tag === "Failure") {
    const error = resolved.failure;
    if (Predicate.isTagged(error, "Refusal")) {
      return messagePage("Cannot sign in", error.reason, error.status);
    }
    return yield* error;
  }
  const user = resolved.success;
  switch (pending.kind) {
    case "enroll": {
      const target = new URL(pending.deviceRedirect);
      target.searchParams.set("code", yield* plane.issueEnrollmentCode(user));
      target.searchParams.set("state", pending.deviceState);
      return redirect(target.toString());
    }
    case "pair":
      return yield* Pairing.completeSignIn(pending, user);
    case "pair-confirm":
      return yield* loginExpired();
    case "admin": {
      if (
        !user.roles.some((role) => role === "admin" || role === "maintainer" || role === "auditor")
      ) {
        return messagePage("No admin access", "Your account has no admin role.", 403);
      }
      const sessionId = yield* sessions.create(user.id);
      return redirect("/admin", {
        "set-cookie": `${SESSION_COOKIE}=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL_SECONDS}`,
      });
    }
  }
});

const signInRoutes = Layer.mergeAll(
  HttpRouter.add("GET", paths.health, json({ ok: true })),
  HttpRouter.add(
    "GET",
    paths.jwks,
    Effect.gen(function* () {
      return json(publicJwks((yield* SigningKeys.SigningKeys).all));
    }),
  ),
  HttpRouter.add(
    "GET",
    paths.enrollStart,
    respondPage(
      Effect.gen(function* () {
        const params = searchParams(yield* HttpServerRequest.HttpServerRequest);
        const deviceRedirect = params.get("redirect_uri") ?? "";
        const deviceState = params.get("state") ?? "";
        if (!isLoopbackRedirect(deviceRedirect)) {
          return yield* refuse(400, "invalid_redirect", "redirect_uri must be a loopback http URL");
        }
        if (deviceState.length < 16)
          return yield* refuse(400, "invalid_state", "state is too short");
        return yield* beginLogin({ kind: "enroll", deviceRedirect, deviceState });
      }),
    ),
  ),
  HttpRouter.add("GET", "/admin/login", respondPage(beginLogin({ kind: "admin" }))),
  HttpRouter.add(
    "GET",
    paths.pairingStart,
    respondPage(
      Effect.gen(function* () {
        const params = searchParams(yield* HttpServerRequest.HttpServerRequest);
        const returnTo = params.get("return_to") ?? "";
        const clientState = params.get("state") ?? "";
        const clientNonce = params.get("nonce") ?? "";
        const deviceId = params.get("device") ?? "";
        if (!Pairing.isPairingReturnUrl(returnTo)) {
          return yield* refuse(400, "invalid_redirect", "return_to must be https or loopback");
        }
        if (clientState.length < 16 || clientNonce.length < 16 || deviceId.length === 0) {
          return yield* refuse(400, "invalid_request", "state, nonce, and device are required");
        }
        return yield* beginLogin({ kind: "pair", deviceId, returnTo, clientState, clientNonce });
      }),
    ),
  ),

  HttpRouter.add(
    "GET",
    OIDC_CALLBACK_PATH,
    respondPage(
      Effect.gen(function* () {
        const config = yield* ControlPlaneConfig;
        const params = searchParams(yield* HttpServerRequest.HttpServerRequest);
        const pending = yield* (yield* Sessions).take(params.get("state") ?? undefined);
        if (pending === undefined) return yield* loginExpired();
        const error = params.get("error");
        if (error !== null) return messagePage("Sign-in failed", error, 403);
        const identity = yield* (yield* Oidc)
          .exchange({
            code: params.get("code") ?? "",
            redirectUri: `${config.publicUrl}${OIDC_CALLBACK_PATH}`,
            codeVerifier: pending.verifier,
            nonce: pending.nonce,
          })
          .pipe(
            Effect.mapError(
              (cause) => new Refusal({ status: 403, code: "sign_in_failed", reason: cause.reason }),
            ),
          );
        return yield* completeLogin(pending, identity);
      }),
    ),
  ),
  HttpRouter.add(
    "POST",
    SAML_CALLBACK_PATH,
    respondPage(
      Effect.gen(function* () {
        const form = yield* readForm;
        const pending = yield* (yield* Sessions).take(form.get("RelayState") ?? undefined);
        if (pending === undefined) return yield* loginExpired();
        const identity = yield* (yield* Saml)
          .validate(form.get("SAMLResponse") ?? "")
          .pipe(
            Effect.mapError(
              (cause) => new Refusal({ status: 403, code: "sign_in_failed", reason: cause.reason }),
            ),
          );
        return yield* completeLogin(pending, identity);
      }),
    ),
  ),
  HttpRouter.add(
    "GET",
    "/saml/metadata",
    respond(
      Effect.gen(function* () {
        const metadata = yield* (yield* Saml).metadata.pipe(
          Effect.mapError(
            () => new Refusal({ status: 404, code: "not_found", reason: "SAML is not configured" }),
          ),
        );
        return asset(metadata, "application/samlmetadata+xml; charset=utf-8");
      }),
    ),
  ),
  HttpRouter.add(
    "GET",
    "/dev/login",
    respondPage(
      Effect.gen(function* () {
        const config = yield* ControlPlaneConfig;
        if (!config.insecureDevLogin) return yield* refuse(404, "not_found", "no such route");
        const state = searchParams(yield* HttpServerRequest.HttpServerRequest).get("state") ?? "";
        return html(
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
      }),
    ),
  ),
  HttpRouter.add(
    "POST",
    "/dev/login",
    respondPage(
      Effect.gen(function* () {
        const config = yield* ControlPlaneConfig;
        if (!config.insecureDevLogin) return yield* refuse(404, "not_found", "no such route");
        const form = yield* readForm;
        const pending = yield* (yield* Sessions).take(form.get("state") ?? undefined);
        if (pending === undefined) return yield* loginExpired();
        const email = (form.get("email") ?? "").trim().toLowerCase();
        if (!email.includes("@")) return yield* refuse(400, "invalid_email", "enter an email");
        const groups = (form.get("groups") ?? "")
          .split(",")
          .map((group) => group.trim())
          .filter((group) => group.length > 0);
        return yield* completeLogin(pending, { subject: email, email, name: null, groups });
      }),
    ),
  ),
  HttpRouter.add(
    "POST",
    "/admin/logout",
    Effect.gen(function* () {
      const request = yield* HttpServerRequest.HttpServerRequest;
      yield* (yield* Sessions).end(request.cookies[SESSION_COOKIE]);
      return redirect("/admin", {
        "set-cookie": `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
      });
    }),
  ),
);

/** A CA-signed client certificate for a live device of an active user. */
const device = Effect.fn("Routes.device")(function* (options?: { allowRevoked?: boolean }) {
  const request = yield* HttpServerRequest.HttpServerRequest;
  return yield* (yield* ControlPlane).authenticateDevice(clientCertificate(request), options);
});

const deviceRoutes = Layer.mergeAll(
  HttpRouter.add(
    "POST",
    paths.enroll,
    respond(
      Effect.gen(function* () {
        const body = yield* readJson(EnrollRequest, 64 * 1024);
        return json(yield* (yield* ControlPlane).enroll(body));
      }),
    ),
  ),
  HttpRouter.add(
    "POST",
    paths.lease,
    respond(
      Effect.gen(function* () {
        const { device: enrolled, user } = yield* device();
        return json(yield* (yield* ControlPlane).lease(enrolled, user));
      }),
    ),
  ),
  HttpRouter.add(
    "GET",
    paths.policy,
    respond(
      Effect.gen(function* () {
        yield* device();
        return json({ policy: yield* (yield* ControlPlane).policyToken });
      }),
    ),
  ),
  HttpRouter.add(
    "POST",
    paths.audit,
    respond(
      Effect.gen(function* () {
        // A revoked device may still report what it did; that is what security most wants.
        const { device: enrolled, user } = yield* device({ allowRevoked: true });
        const body = yield* readJson(AuditBatch, 4 * 1024 * 1024);
        return json(yield* (yield* ControlPlane).ingestAudit(enrolled, user, body.events));
      }),
    ),
  ),
  HttpRouter.add(
    "POST",
    paths.heartbeat,
    respond(
      Effect.gen(function* () {
        const { device: enrolled } = yield* device({ allowRevoked: true });
        const body = yield* readJson(Heartbeat, 16 * 1024);
        yield* (yield* ControlPlane).heartbeat(enrolled, body);
        return json({ ok: true });
      }),
    ),
  ),
);

const requireGateway = Effect.gen(function* () {
  const config = yield* ControlPlaneConfig;
  const token = bearer(yield* HttpServerRequest.HttpServerRequest);
  if (token === undefined || !Crypto.constantTimeEqual(token, config.secrets.gatewayToken)) {
    return yield* refuse(401, "unauthorized", "gateway token required");
  }
});

const gatewayRoutes = Layer.mergeAll(
  HttpRouter.add(
    "GET",
    paths.gatewayState,
    respond(
      Effect.gen(function* () {
        yield* requireGateway;
        return json(yield* (yield* ControlPlane).gatewayState);
      }),
    ),
  ),
  HttpRouter.add(
    "POST",
    paths.gatewayUsage,
    respond(
      Effect.gen(function* () {
        yield* requireGateway;
        const body = yield* readJson(UsageBatch, 4 * 1024 * 1024);
        return json(yield* (yield* ControlPlane).ingestUsage(body.records));
      }),
    ),
  ),
);

export const layer = Layer.mergeAll(signInRoutes, deviceRoutes, gatewayRoutes, Pairing.routes);
