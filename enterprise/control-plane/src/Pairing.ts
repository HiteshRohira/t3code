/**
 * Pairing - an environment sends a browser here to prove its user is the environment's owner.
 * The owner signs in, approves the asking origin, and returns with a short-lived assertion.
 * @module Pairing
 */
import { signPairingAssertion } from "@t3tools/enterprise-protocol/tokens";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import { HttpRouter } from "effect/http";

import { ControlPlaneConfig } from "./Config.ts";
import { ControlPlane, Refusal } from "./ControlPlane.ts";
import { escapeHtml, html, page, readForm, redirect, respondPage } from "./Http.ts";
import { Sessions, type PendingLogin } from "./Sessions.ts";
import * as SigningKeys from "./SigningKeys.ts";
import { Store, type User } from "./Store.ts";

const ASSERTION_TTL_SECONDS = 120;
const CONFIRM_PATH = "/pair/confirm";

const refuse = (status: number, code: string, reason: string) =>
  Effect.fail(new Refusal({ status, code, reason }));

/** Environments are reached over HTTPS, or over loopback HTTP on the same machine. */
export function isPairingReturnUrl(value: string): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.username !== "" || url.password !== "") return false;
  if (url.protocol === "https:") return true;
  return (
    url.protocol === "http:" &&
    (url.hostname === "127.0.0.1" || url.hostname === "[::1]" || url.hostname === "localhost")
  );
}

/** Called once the IdP vouched for `user`: ask them to approve the connection. */
export const completeSignIn = Effect.fn("Pairing.completeSignIn")(function* (
  pending: Extract<PendingLogin, { kind: "pair" }>,
  user: User,
) {
  const store = yield* Store;
  const plane = yield* ControlPlane;
  const device = yield* store.deviceById(pending.deviceId);
  if (device === undefined || (yield* plane.deviceDenial(device)) !== undefined) {
    return yield* refuse(403, "device_unknown", "this environment is not an enrolled device");
  }
  if (device.userId !== user.id) {
    return yield* refuse(
      403,
      "not_owner",
      "this environment belongs to someone else; sign in as its owner",
    );
  }
  const { state } = yield* (yield* Sessions).begin({
    kind: "pair-confirm",
    userId: user.id,
    deviceId: device.id,
    returnTo: pending.returnTo,
    clientState: pending.clientState,
    clientNonce: pending.clientNonce,
  });
  const origin = new URL(pending.returnTo).origin;
  return html(
    page(
      "Connect to your environment?",
      `<p><strong>${escapeHtml(origin)}</strong> wants to connect to your T3 Code environment on
       <strong>${escapeHtml(device.hostname)}</strong> as ${escapeHtml(user.email)}.</p>
       <p>Approve only if you just opened T3 Code at that address.</p>
       <form method="post" action="${CONFIRM_PATH}">
         <input type="hidden" name="state" value="${escapeHtml(state)}">
         <button>Connect</button>
       </form>`,
    ),
  );
});

export const routes = Layer.mergeAll(
  HttpRouter.add(
    "POST",
    CONFIRM_PATH,
    respondPage(
      Effect.gen(function* () {
        const config = yield* ControlPlaneConfig;
        const keys = yield* SigningKeys.SigningKeys;
        const store = yield* Store;
        const form = yield* readForm;
        const pending = yield* (yield* Sessions).take(form.get("state") ?? undefined);
        if (pending?.kind !== "pair-confirm") {
          return yield* refuse(400, "login_expired", "this approval expired; start again");
        }
        const user = yield* store.userById(pending.userId);
        if (user === undefined || !user.active) {
          return yield* refuse(403, "user_inactive", "your account is deactivated");
        }
        const assertion = yield* signPairingAssertion(
          keys.active,
          {
            userId: user.id,
            email: user.email,
            deviceId: pending.deviceId,
            nonce: pending.clientNonce,
          },
          { issuer: config.publicUrl, ttlSeconds: ASSERTION_TTL_SECONDS },
        );
        yield* (yield* ControlPlane).recordAdminEvent(user, "environment.paired", {
          deviceId: pending.deviceId,
          origin: new URL(pending.returnTo).origin,
        });
        const target = new URL(pending.returnTo);
        target.searchParams.set("assertion", assertion);
        target.searchParams.set("state", pending.clientState);
        return redirect(target.toString());
      }),
    ),
  ),
);
