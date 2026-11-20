import { assert, describe, it } from "@effect/vitest";
import * as Effect from "effect/Effect";
import * as TestClock from "effect/testing/TestClock";

import {
  generateSigningKey,
  modelAllowed,
  publicJwks,
  signLease,
  signPolicy,
  verifyLease,
  verifyPolicy,
} from "./tokens.ts";

const issuer = "https://cp.example.test";

const lease = {
  userId: "user-1",
  email: "dev@example.test",
  deviceId: "device-1",
  roles: ["developer"] as const,
  thumbprint: "thumb-1",
  leaseId: "lease-1",
  region: "eu",
};

const rejection = <A, E extends { _tag: string; message: string }, R>(
  effect: Effect.Effect<A, E, R>,
) =>
  effect.pipe(
    Effect.flip,
    Effect.map((error) => `${error._tag}: ${error.message}`),
  );

describe("leases", () => {
  it.effect("verifies a lease only for the device certificate it was bound to", () =>
    Effect.gen(function* () {
      const key = yield* generateSigningKey("k1");
      const token = yield* signLease(key, lease, { issuer, ttlSeconds: 3600 });
      const jwks = publicJwks([key]);

      const claims = yield* verifyLease(token, jwks, { issuer, thumbprint: "thumb-1" });
      assert.deepInclude(claims, { userId: "user-1", deviceId: "device-1", region: "eu" });

      const stolen = yield* rejection(
        verifyLease(token, jwks, { issuer, thumbprint: "someone-else" }),
      );
      assert.include(stolen, "different device certificate");
    }),
  );

  it.effect("rejects an expired lease and one signed by an unknown key", () =>
    Effect.gen(function* () {
      const key = yield* generateSigningKey("k1");
      const other = yield* generateSigningKey("k1");
      const token = yield* signLease(key, lease, { issuer, ttlSeconds: 60 });

      const forged = yield* rejection(
        verifyLease(token, publicJwks([other]), { issuer, thumbprint: "thumb-1" }),
      );
      assert.include(forged, "TokenRejected");

      yield* TestClock.adjust("2 minutes");
      const expired = yield* rejection(
        verifyLease(token, publicJwks([key]), { issuer, thumbprint: "thumb-1" }),
      );
      assert.include(expired, "TokenRejected");
    }),
  );

  it.effect("does not accept a policy token as a lease", () =>
    Effect.gen(function* () {
      const key = yield* generateSigningKey("k1");
      const policy = yield* signPolicy(
        key,
        { version: 1, document: { schemaVersion: 1, organization: "Example" } },
        { issuer, ttlSeconds: 3600 },
      );
      const refused = yield* rejection(
        verifyLease(policy, publicJwks([key]), { issuer, thumbprint: "thumb-1" }),
      );
      assert.include(refused, "TokenRejected");
    }),
  );
});

describe("policy tokens", () => {
  it.effect("round-trips the document and version", () =>
    Effect.gen(function* () {
      const key = yield* generateSigningKey("k1");
      const document = { schemaVersion: 1, organization: "Example" };
      const token = yield* signPolicy(key, { version: 7, document }, { issuer, ttlSeconds: 60 });
      const claims = yield* verifyPolicy(token, publicJwks([key]), { issuer });
      assert.strictEqual(claims.version, 7);
      assert.deepStrictEqual(claims.policy, document);
    }),
  );
});

describe("modelAllowed", () => {
  it.each([
    [undefined, "claude-opus-5-5", true],
    [["claude-*"], "claude-haiku-5-5", true],
    [["claude-haiku-5-5"], "claude-opus-5-5", false],
    [[], "anything", false],
  ] as const)("%j allows %s: %s", (models, model, expected) => {
    assert.strictEqual(modelAllowed(models, model), expected);
  });
});
