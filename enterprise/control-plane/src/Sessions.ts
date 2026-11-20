/**
 * Sessions - sign-ins in flight and signed-in browser sessions. Both live in memory: a restart
 * signs admins out and abandons half-finished sign-ins, which users simply retry.
 *
 * @module Sessions
 */
import * as Clock from "effect/Clock";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";

import * as Crypto from "./Crypto.ts";

const LOGIN_TTL_MS = 10 * 60 * 1000;
export const SESSION_TTL_SECONDS = 8 * 3600;

/** Where a sign-in goes once the IdP vouches for the user. */
export type LoginPurpose =
  | { readonly kind: "admin" }
  | { readonly kind: "enroll"; readonly deviceRedirect: string; readonly deviceState: string }
  | {
      readonly kind: "pair";
      readonly deviceId: string;
      readonly returnTo: string;
      readonly clientState: string;
      readonly clientNonce: string;
    }
  | {
      readonly kind: "pair-confirm";
      readonly userId: string;
      readonly deviceId: string;
      readonly returnTo: string;
      readonly clientState: string;
      readonly clientNonce: string;
    };

export type PendingLogin = LoginPurpose & {
  readonly verifier: string;
  readonly nonce: string;
  readonly expiresAt: number;
};

export class Sessions extends Context.Service<
  Sessions,
  {
    readonly begin: (
      purpose: LoginPurpose,
    ) => Effect.Effect<{ readonly state: string; readonly pending: PendingLogin }>;
    /** Spends a sign-in state once; undefined when unknown or expired. */
    readonly take: (state: string | undefined) => Effect.Effect<PendingLogin | undefined>;
    readonly create: (userId: string) => Effect.Effect<string>;
    readonly userOf: (sessionId: string | undefined) => Effect.Effect<string | undefined>;
    readonly end: (sessionId: string | undefined) => Effect.Effect<void>;
  }
>()("@t3tools/enterprise-control-plane/Sessions") {}

const make = Effect.sync(() => {
  const pending = new Map<string, PendingLogin>();
  const sessions = new Map<string, { userId: string; expiresAt: number }>();

  const sweep = (now: number) => {
    for (const [key, value] of pending) if (value.expiresAt < now) pending.delete(key);
    for (const [key, value] of sessions) if (value.expiresAt < now) sessions.delete(key);
  };

  return Sessions.of({
    begin: Effect.fn("Sessions.begin")(function* (purpose) {
      const now = yield* Clock.currentTimeMillis;
      sweep(now);
      const state = yield* Crypto.randomToken();
      const login: PendingLogin = {
        ...purpose,
        verifier: yield* Crypto.randomToken(48),
        nonce: yield* Crypto.randomToken(),
        expiresAt: now + LOGIN_TTL_MS,
      };
      pending.set(state, login);
      return { state, pending: login };
    }),
    take: Effect.fn("Sessions.take")(function* (state) {
      if (state === undefined) return undefined;
      const login = pending.get(state);
      pending.delete(state);
      if (login === undefined || login.expiresAt < (yield* Clock.currentTimeMillis)) {
        return undefined;
      }
      return login;
    }),
    create: Effect.fn("Sessions.create")(function* (userId) {
      const id = yield* Crypto.randomToken();
      sessions.set(id, {
        userId,
        expiresAt: (yield* Clock.currentTimeMillis) + SESSION_TTL_SECONDS * 1000,
      });
      return id;
    }),
    userOf: Effect.fn("Sessions.userOf")(function* (sessionId) {
      const session = sessionId === undefined ? undefined : sessions.get(sessionId);
      if (session === undefined || session.expiresAt < (yield* Clock.currentTimeMillis)) {
        return undefined;
      }
      return session.userId;
    }),
    end: Effect.fn("Sessions.end")((sessionId) =>
      Effect.sync(() => {
        if (sessionId !== undefined) sessions.delete(sessionId);
      }),
    ),
  });
});

export const layer = Layer.effect(Sessions, make);
