/**
 * EnterprisePairing - pairing through the organization's sign-in. A browser opens
 * `/api/enterprise/pair/start`, signs in at the control plane as this environment's owner, and
 * comes back with an assertion; only then does this server issue a pairing credential.
 *
 * @module EnterprisePairing
 */
import { AuthStandardClientScopes } from "@t3tools/contracts";
import { verifyPairingAssertion } from "@t3tools/enterprise-protocol/tokens";
import { paths as wirePaths } from "@t3tools/enterprise-protocol/wire";
import { setPairingTokenOnUrl } from "@t3tools/shared/remote";
import * as Clock from "effect/Clock";
import * as Context from "effect/Context";
import * as SecureRandom from "effect/crypto/SecureRandom";
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Base64Url from "effect/encoding/Base64Url";
import * as Layer from "effect/Layer";
import * as Schema from "effect/Schema";
import { HttpRouter, HttpServerRequest, HttpServerResponse } from "effect/http";

import * as EnvironmentAuth from "../auth/EnvironmentAuth.ts";
import * as EnterpriseAgent from "./EnterpriseAgent.ts";

const PAIR_START_PATH = "/api/enterprise/pair/start";
const PAIR_CALLBACK_PATH = "/api/enterprise/pair/callback";
const STATE_COOKIE = "t3e_pair_state";
const PENDING_TTL_MS = 10 * 60 * 1000;
const CREDENTIAL_TTL = Duration.minutes(10);

export class EnterprisePairingError extends Schema.TaggedError<EnterprisePairingError>()(
  "EnterprisePairingError",
  { reason: Schema.String },
) {
  override get message(): string {
    return this.reason;
  }
}

/** `browser` pairs the browser that signed in; `link` shows a link for another app, like desktop. */
export type PairingMode = "browser" | "link";

export class EnterprisePairing extends Context.Service<
  EnterprisePairing,
  {
    readonly begin: (input: {
      readonly origin: string;
      readonly mode: PairingMode;
    }) => Effect.Effect<
      { readonly redirect: string; readonly state: string },
      EnterprisePairingError
    >;
    readonly complete: (input: {
      readonly origin: string;
      readonly state: string;
      readonly browserState: string | undefined;
      readonly assertion: string;
    }) => Effect.Effect<
      { readonly pairingUrl: string; readonly mode: PairingMode; readonly email: string },
      EnterprisePairingError
    >;
  }
>()("t3/enterprise/EnterprisePairing") {}

const fail = (reason: string) => new EnterprisePairingError({ reason });

const make = Effect.gen(function* () {
  const agent = yield* EnterpriseAgent.EnterpriseAgent;
  const auth = yield* EnvironmentAuth.EnvironmentAuth;
  const random = yield* SecureRandom.SecureRandom;
  const pending = new Map<string, { nonce: string; mode: PairingMode; expiresAt: number }>();
  const token = Effect.map(random.randomBytes(32), Base64Url.encode);

  const identity = Effect.gen(function* () {
    const loaded = agent.config;
    const status = yield* agent.status;
    if (loaded === undefined || status === undefined) {
      return yield* fail("This environment is not managed by an organization.");
    }
    if (!status.enrolled || status.deviceId === null || status.email === null) {
      return yield* fail("Enroll this computer with your organization before pairing devices.");
    }
    return { config: loaded.document, deviceId: status.deviceId, email: status.email };
  });

  return EnterprisePairing.of({
    begin: Effect.fn("EnterprisePairing.begin")(function* ({ origin, mode }) {
      const { config, deviceId } = yield* identity;
      const now = yield* Clock.currentTimeMillis;
      for (const [key, value] of pending) if (value.expiresAt < now) pending.delete(key);
      const state = yield* token;
      const nonce = yield* token;
      pending.set(state, { nonce, mode, expiresAt: now + PENDING_TTL_MS });
      const target = new URL(`${config.controlPlaneUrl}${wirePaths.pairingStart}`);
      target.searchParams.set("device", deviceId);
      target.searchParams.set("return_to", `${origin}${PAIR_CALLBACK_PATH}`);
      target.searchParams.set("state", state);
      target.searchParams.set("nonce", nonce);
      return { redirect: target.toString(), state };
    }),
    complete: Effect.fn("EnterprisePairing.complete")(function* (input) {
      // The state cookie ties the sign-in to the browser that started it.
      if (input.browserState !== input.state) {
        return yield* fail("This sign-in was started in another browser. Start pairing again.");
      }
      const started = pending.get(input.state);
      pending.delete(input.state);
      if (started === undefined || started.expiresAt < (yield* Clock.currentTimeMillis)) {
        return yield* fail("This pairing expired. Start again.");
      }
      const { config, deviceId, email } = yield* identity;
      const claims = yield* verifyPairingAssertion(input.assertion, config.policyKeys, {
        issuer: config.controlPlaneUrl,
      }).pipe(
        Effect.mapError((error) => fail(`The organization's answer was refused: ${error.reason}`)),
      );
      if (claims.deviceId !== deviceId || claims.nonce !== started.nonce) {
        return yield* fail("The organization's answer is for a different pairing. Start again.");
      }
      if (claims.email.toLowerCase() !== email.toLowerCase()) {
        return yield* fail(`Sign in as ${email}, who enrolled this environment.`);
      }
      const issued = yield* auth
        .createPairingLink({
          ssoVerified: true,
          ttl: CREDENTIAL_TTL,
          scopes: AuthStandardClientScopes,
          label: `${claims.email} (organization sign-in)`,
        })
        .pipe(Effect.mapError((error) => fail(error.message)));
      return {
        pairingUrl: setPairingTokenOnUrl(
          new URL(`${input.origin}/pair`),
          issued.credential,
        ).toString(),
        mode: started.mode,
        email: claims.email,
      };
    }),
  });
});

const layer = Layer.effect(EnterprisePairing, make);

/** The origin the browser used, which proxies such as Tailscale Serve report in forwarded headers. */
const originOf = (request: HttpServerRequest.HttpServerRequest) => {
  const proto = request.headers["x-forwarded-proto"]?.split(",")[0]?.trim() ?? "http";
  const host = request.headers["x-forwarded-host"] ?? request.headers["host"] ?? "localhost";
  return `${proto}://${host}`;
};

const escapeHtml = (value: string) =>
  value.replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);

const page = (title: string, body: string, status = 200) =>
  HttpServerResponse.text(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)}</title>
<style>body{font:15px/1.5 system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem;color:#222}code{display:block;word-break:break-all;background:#f3f3f3;padding:.75rem;border-radius:6px}@media(prefers-color-scheme:dark){body{background:#151515;color:#eee}code{background:#262626}}</style>
</head><body><h1>${escapeHtml(title)}</h1>${body}</body></html>`,
    {
      status,
      contentType: "text/html; charset=utf-8",
      headers: {
        "cache-control": "no-store",
        "referrer-policy": "no-referrer",
        "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'",
      },
    },
  );

const failurePage = (error: EnterprisePairingError) =>
  Effect.succeed(page("Cannot pair", `<p>${escapeHtml(error.reason)}</p>`, 403));

export const routes = HttpRouter.use((router) =>
  Effect.gen(function* () {
    const pairing = yield* EnterprisePairing;
    yield* router.add(
      "GET",
      PAIR_START_PATH,
      Effect.gen(function* () {
        const request = yield* HttpServerRequest.HttpServerRequest;
        const mode: PairingMode =
          new URL(request.originalUrl, "http://t3.invalid").searchParams.get("client") === "link"
            ? "link"
            : "browser";
        const { redirect, state } = yield* pairing.begin({
          origin: originOf(request),
          mode,
        });
        return HttpServerResponse.redirect(redirect, {
          status: 302,
          headers: {
            "cache-control": "no-store",
            "set-cookie": `${STATE_COOKIE}=${state}; Path=${PAIR_CALLBACK_PATH}; HttpOnly; SameSite=Lax; Max-Age=600`,
          },
        });
      }).pipe(Effect.catchTags({ EnterprisePairingError: failurePage })),
    );
    yield* router.add(
      "GET",
      PAIR_CALLBACK_PATH,
      Effect.gen(function* () {
        const request = yield* HttpServerRequest.HttpServerRequest;
        const params = new URL(request.originalUrl, "http://t3.invalid").searchParams;
        const result = yield* pairing.complete({
          origin: originOf(request),
          state: params.get("state") ?? "",
          browserState: request.cookies[STATE_COOKIE],
          assertion: params.get("assertion") ?? "",
        });
        const clearCookie = `${STATE_COOKIE}=; Path=${PAIR_CALLBACK_PATH}; HttpOnly; SameSite=Lax; Max-Age=0`;
        if (result.mode === "browser") {
          return HttpServerResponse.redirect(result.pairingUrl, {
            status: 302,
            headers: { "cache-control": "no-store", "set-cookie": clearCookie },
          });
        }
        return page(
          "Pair the T3 Code app",
          `<p>Signed in as ${escapeHtml(result.email)}. In the T3 Code app, choose <strong>Add environment</strong> and paste this link. It works once, for ten minutes.</p>
         <code>${escapeHtml(result.pairingUrl)}</code>`,
        ).pipe(HttpServerResponse.setHeader("set-cookie", clearCookie));
      }).pipe(Effect.catchTags({ EnterprisePairingError: failurePage })),
    );
  }),
).pipe(Layer.provide(layer));
