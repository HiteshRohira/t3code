import * as NodeServices from "@effect/platform-node/NodeServices";
import { assert, describe, it } from "@effect/vitest";
import { generateSigningKey } from "@t3tools/enterprise-protocol/tokens";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as TestClock from "effect/testing/TestClock";

import * as AuditSinks from "./AuditSinks.ts";
import * as CertificateAuthority from "./CertificateAuthority.ts";
import { ControlPlaneConfig, parseConfig } from "./Config.ts";
import * as ControlPlane from "./ControlPlane.ts";
import type { Identity } from "./Oidc.ts";
import * as Retention from "./Retention.ts";
import { isLoopbackRedirect } from "./Routes.ts";
import * as SigningKeys from "./SigningKeys.ts";
import * as Store from "./Store.ts";

const env = {
  T3E_GATEWAY_TOKEN: "g".repeat(32),
  T3E_SCIM_TOKEN: "s".repeat(32),
  T3E_OIDC_CLIENT_SECRET: "x",
};

const layerFor = (overrides: Record<string, unknown>) =>
  ControlPlane.layer.pipe(
    Layer.provideMerge(Store.layer.pipe(Layer.provide(Store.layerSqlite(":memory:")))),
    Layer.provide(Layer.succeed(AuditSinks.AuditSinks, { publish: () => Effect.void })),
    Layer.provide(
      Layer.succeed(CertificateAuthority.CertificateAuthority, {
        certPem: "",
        issueDevice: () => Effect.die("not used"),
        issueServer: () => Effect.die("not used"),
      }),
    ),
    Layer.provide(
      Layer.effect(
        SigningKeys.SigningKeys,
        Effect.map(generateSigningKey("k"), (key) => ({ active: key, all: [key] })),
      ),
    ),
    Layer.provideMerge(
      Layer.effect(
        ControlPlaneConfig,
        parseConfig(
          {
            publicUrl: "https://cp.example.test",
            organization: "Example Corp",
            tls: { certPath: "tls.crt", keyPath: "tls.key" },
            dataDir: "data",
            oidc: { issuer: "https://idp.example.test", clientId: "t3" },
            groupRoles: { "t3-admins": "admin", "t3-devs": "developer" },
            ...overrides,
          },
          { baseDir: "/tmp", env },
        ),
      ),
    ),
    Layer.provide(NodeServices.layer),
  );

const identity = (email: string, groups: ReadonlyArray<string>): Identity => ({
  subject: email,
  email,
  name: null,
  groups,
});

const refusalCode = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
  effect.pipe(
    Effect.flip,
    Effect.map((error) => (error as { code?: string }).code),
  );

describe("ControlPlane.resolveLogin", () => {
  it.effect("maps IdP groups to roles on every sign-in", () =>
    Effect.gen(function* () {
      const plane = yield* ControlPlane.ControlPlane;
      const first = yield* plane.resolveLogin(identity("a@example.test", ["t3-admins", "t3-devs"]));
      assert.deepStrictEqual(first.roles, ["admin", "developer"]);
      // Leaving the admin group in the IdP takes the role away at the next sign-in.
      const second = yield* plane.resolveLogin(identity("a@example.test", ["t3-devs"]));
      assert.deepStrictEqual(second.roles, ["developer"]);
      const other = yield* plane.resolveLogin(identity("b@example.test", ["other"]));
      assert.deepStrictEqual(other.roles, ["developer"]);
    }).pipe(Effect.provide(layerFor({}))),
  );

  it.effect("admits only members of the allowed groups", () =>
    Effect.gen(function* () {
      const plane = yield* ControlPlane.ControlPlane;
      assert.strictEqual(
        yield* refusalCode(plane.resolveLogin(identity("a@example.test", ["contractors"]))),
        "not_allowed",
      );
      const user = yield* plane.resolveLogin(identity("a@example.test", ["t3-devs"]));
      assert.strictEqual(user.email, "a@example.test");
    }).pipe(Effect.provide(layerFor({ allowedGroups: ["t3-devs"] }))),
  );

  it.effect("with SCIM provisioning, admits only provisioned, active users", () =>
    Effect.gen(function* () {
      const plane = yield* ControlPlane.ControlPlane;
      const store = yield* Store.Store;
      assert.strictEqual(
        yield* refusalCode(plane.resolveLogin(identity("new@example.test", []))),
        "not_provisioned",
      );
      const user = yield* store.createUser({
        id: "u-1",
        email: "known@example.test",
        roles: ["developer"],
      });
      assert.strictEqual(
        (yield* plane.resolveLogin(identity("known@example.test", []))).id,
        user.id,
      );
      yield* store.deactivateUser(user.id);
      assert.strictEqual(
        yield* refusalCode(plane.resolveLogin(identity("known@example.test", []))),
        "user_inactive",
      );
    }).pipe(Effect.provide(layerFor({ provisioning: "scim" }))),
  );

  it.effect("uses SCIM-pushed groups when the IdP's token carries none", () =>
    Effect.gen(function* () {
      const plane = yield* ControlPlane.ControlPlane;
      const store = yield* Store.Store;
      yield* store.createUser({ id: "u-1", email: "lead@example.test", roles: ["developer"] });
      yield* store.createGroup({ id: "g-1", displayName: "t3-admins", externalId: null });
      yield* store.setGroupMembers("g-1", ["u-1"]);
      const user = yield* plane.resolveLogin(identity("lead@example.test", []));
      assert.deepStrictEqual(user.roles, ["admin"]);
    }).pipe(Effect.provide(layerFor({}))),
  );
});

describe("Retention.purgeOnce", () => {
  it.effect("deletes audit older than the window, except for users on legal hold", () =>
    Effect.gen(function* () {
      const store = yield* Store.Store;
      for (const id of ["kept", "held"]) {
        yield* store.createUser({ id, email: `${id}@example.test`, roles: ["developer"] });
        yield* store.appendAudit({ id: "device", userId: id }, [
          { id: `${id}-old`, occurredAt: "1970-01-01T00:00:00.000Z", type: "turn.started" },
        ]);
      }
      yield* store.placeLegalHold("held", "case 42", "auditor@example.test");
      yield* TestClock.adjust("40 days");
      yield* store.appendAudit({ id: "device", userId: "kept" }, [
        { id: "kept-new", occurredAt: "1970-02-10T00:00:00.000Z", type: "turn.started" },
      ]);

      assert.strictEqual(yield* Retention.purgeOnce, 1);
      const left = yield* store.listAudit({ limit: 10 });
      assert.deepStrictEqual(
        left.map((event) => event.id),
        ["held-old", "kept-new"],
      );
    }).pipe(Effect.provide(layerFor({ retention: { auditDays: 30 } }))),
  );
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
    assert.strictEqual(isLoopbackRedirect(url), expected);
  });
});
