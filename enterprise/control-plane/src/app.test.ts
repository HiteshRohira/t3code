import { generateSigningKey } from "@t3tools/enterprise-protocol/tokens";
import forge from "node-forge";
import { describe, expect, it } from "vite-plus/test";

import { ControlPlane, isLoopbackRedirect } from "./app.ts";
import { createCertificateAuthority } from "./ca.ts";
import { parseConfig } from "./config.ts";
import { HttpError } from "./http.ts";
import { Store } from "./store.ts";

const env = {
  T3E_GATEWAY_TOKEN: "g".repeat(32),
  T3E_SCIM_TOKEN: "s".repeat(32),
  T3E_OIDC_CLIENT_SECRET: "x",
};

async function planeWith(overrides: Record<string, unknown>) {
  const config = parseConfig(
    {
      publicUrl: "https://cp.example.test",
      organization: "Example Corp",
      tls: { certPath: "tls.crt", keyPath: "tls.key" },
      dataDir: "data",
      oidc: {
        issuer: "https://idp.example.test",
        clientId: "t3",
        groupRoles: { "t3-admins": "admin", "t3-devs": "developer" },
      },
      ...overrides,
    },
    { baseDir: "/tmp", env },
  );
  const ca = createCertificateAuthority("Example Corp", 1);
  const store = new Store(":memory:");
  const plane = new ControlPlane({
    config,
    store,
    ca: {
      certPem: ca.certPem,
      cert: forge.pki.certificateFromPem(ca.certPem),
      key: forge.pki.privateKeyFromPem(ca.keyPem),
    },
    keys: { active: await generateSigningKey("k"), all: [] },
  });
  return { plane, store };
}

const identity = (email: string, groups: ReadonlyArray<string>) => ({
  subject: email,
  email,
  name: null,
  groups,
});

const denial = (body: () => unknown) => {
  try {
    body();
  } catch (error) {
    return error instanceof HttpError ? error.code : "unexpected";
  }
  return undefined;
};

describe("ControlPlane.resolveLogin", () => {
  it("maps IdP groups to roles on every sign-in", async () => {
    const { plane } = await planeWith({});
    expect(plane.resolveLogin(identity("a@example.test", ["t3-admins", "t3-devs"])).roles).toEqual([
      "admin",
      "developer",
    ]);
    // Leaving the admin group in the IdP takes the role away at the next sign-in.
    expect(plane.resolveLogin(identity("a@example.test", ["t3-devs"])).roles).toEqual([
      "developer",
    ]);
    expect(plane.resolveLogin(identity("b@example.test", ["other"])).roles).toEqual(["developer"]);
  });

  it("admits only members of the allowed groups", async () => {
    const { plane } = await planeWith({
      oidc: { issuer: "https://idp.example.test", clientId: "t3", allowedGroups: ["t3-users"] },
    });
    expect(denial(() => plane.resolveLogin(identity("a@example.test", ["contractors"])))).toBe(
      "not_allowed",
    );
    expect(plane.resolveLogin(identity("a@example.test", ["t3-users"])).email).toBe(
      "a@example.test",
    );
  });

  it("with SCIM provisioning, admits only provisioned, active users", async () => {
    const { plane, store } = await planeWith({ provisioning: "scim" });
    expect(denial(() => plane.resolveLogin(identity("new@example.test", [])))).toBe(
      "not_provisioned",
    );
    const user = store.createUser({ email: "known@example.test", roles: ["developer"] });
    expect(plane.resolveLogin(identity("known@example.test", [])).id).toBe(user.id);
    store.deactivateUser(user.id);
    expect(denial(() => plane.resolveLogin(identity("known@example.test", [])))).toBe(
      "user_inactive",
    );
  });
});

describe("isLoopbackRedirect", () => {
  it.each([
    ["http://127.0.0.1:5000/callback", true],
    ["http://localhost:5000/callback", true],
    ["https://127.0.0.1:5000/callback", false],
    ["http://attacker.example/callback", false],
    ["http://user:pass@127.0.0.1/callback", false],
    ["not a url", false],
  ])("%s → %s", (url, expected) => {
    expect(isLoopbackRedirect(url)).toBe(expected);
  });
});
