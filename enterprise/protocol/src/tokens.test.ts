import { describe, expect, it } from "vite-plus/test";

import {
  generateSigningKey,
  modelAllowed,
  publicJwks,
  signLease,
  signPolicy,
  TokenRejected,
  verifyLease,
  verifyPolicy,
} from "./tokens.ts";

const issuer = "https://cp.example.test";
const now = new Date("2026-11-20T12:00:00Z");

const lease = {
  userId: "user-1",
  email: "dev@example.test",
  deviceId: "device-1",
  roles: ["developer"] as const,
  thumbprint: "thumb-1",
  leaseId: "lease-1",
};

describe("leases", () => {
  it("verifies a lease only for the device certificate it was bound to", async () => {
    const key = await generateSigningKey("k1");
    const token = await signLease(key, lease, { issuer, ttlSeconds: 3600, now });
    const jwks = publicJwks([key]);

    const claims = await verifyLease(token, jwks, { issuer, thumbprint: "thumb-1", now });
    expect(claims).toMatchObject({ userId: "user-1", deviceId: "device-1", roles: ["developer"] });

    await expect(
      verifyLease(token, jwks, { issuer, thumbprint: "someone-else", now }),
    ).rejects.toBeInstanceOf(TokenRejected);
  });

  it("rejects an expired lease and one signed by an unknown key", async () => {
    const key = await generateSigningKey("k1");
    const other = await generateSigningKey("k1");
    const token = await signLease(key, lease, { issuer, ttlSeconds: 60, now });

    const later = new Date(now.getTime() + 120_000);
    await expect(
      verifyLease(token, publicJwks([key]), { issuer, thumbprint: "thumb-1", now: later }),
    ).rejects.toBeInstanceOf(TokenRejected);
    await expect(
      verifyLease(token, publicJwks([other]), { issuer, thumbprint: "thumb-1", now }),
    ).rejects.toBeInstanceOf(TokenRejected);
  });

  it("does not accept a policy token as a lease", async () => {
    const key = await generateSigningKey("k1");
    const policy = await signPolicy(
      key,
      { version: 1, document: { schemaVersion: 1, organization: "Example" } },
      { issuer, ttlSeconds: 3600, now },
    );
    await expect(
      verifyLease(policy, publicJwks([key]), { issuer, thumbprint: "thumb-1", now }),
    ).rejects.toBeInstanceOf(TokenRejected);
  });
});

describe("policy tokens", () => {
  it("round-trips the document and version", async () => {
    const key = await generateSigningKey("k1");
    const document = { schemaVersion: 1, organization: "Example" };
    const token = await signPolicy(key, { version: 7, document }, { issuer, ttlSeconds: 60, now });
    const claims = await verifyPolicy(token, publicJwks([key]), { issuer, now });
    expect(claims.version).toBe(7);
    expect(claims.policy).toEqual(document);
  });
});

describe("modelAllowed", () => {
  it.each([
    [undefined, "claude-opus-5-5", true],
    [["claude-*"], "claude-haiku-5-5", true],
    [["claude-haiku-5-5"], "claude-opus-5-5", false],
    [[], "anything", false],
  ] as const)("%j allows %s: %s", (models, model, expected) => {
    expect(modelAllowed(models, model)).toBe(expected);
  });
});
