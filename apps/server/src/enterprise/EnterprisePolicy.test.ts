import * as NodeServices from "@effect/platform-node/NodeServices";
import type { ManagedPolicyDocument } from "@t3tools/contracts";
import { assert, it } from "@effect/vitest";
import {
  generateSigningKey,
  publicJwks,
  signPolicy,
  type SigningKey,
} from "@t3tools/enterprise-protocol/tokens";
import * as ConfigProvider from "effect/ConfigProvider";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Path from "effect/Path";
import * as TestClock from "effect/testing/TestClock";

import type { EnterpriseConfigDocument } from "./EnterpriseConfig.ts";
import * as EnterprisePolicy from "./EnterprisePolicy.ts";

const controlPlaneUrl = "https://cp.example.test";

const configFor = (key: SigningKey): EnterpriseConfigDocument => ({
  schemaVersion: 1,
  organization: "Example Corp",
  controlPlaneUrl,
  gatewayUrl: "https://gateway.example.test",
  policyKeys: { keys: publicJwks([key]).keys.map((jwk) => ({ ...jwk })) },
  bootstrapPolicy: {
    schemaVersion: 1,
    organization: "Example Corp",
    limits: { connect: false, maxRuntimeMode: "approval-required" },
  },
});

const sign = (key: SigningKey, document: unknown, ttlSeconds = 3600) =>
  signPolicy(key, { version: 4, document }, { issuer: controlPlaneUrl, ttlSeconds });

/** Resolves with `token` cached in a fresh state directory. */
const resolveWith = (config: EnterpriseConfigDocument, token: string | undefined) =>
  Effect.gen(function* () {
    const fs = yield* FileSystem.FileSystem;
    const path = yield* Path.Path;
    const dir = yield* fs.makeTempDirectoryScoped({ prefix: "t3-enterprise-policy-" });
    if (token !== undefined) yield* fs.writeFileString(path.join(dir, "policy.jws"), token);
    return yield* EnterprisePolicy.resolve(config, "/etc/t3code/enterprise.json").pipe(
      Effect.provide(
        ConfigProvider.layer(ConfigProvider.fromEnv({ env: { T3CODE_ENTERPRISE_STATE_DIR: dir } })),
      ),
    );
  }).pipe(Effect.scoped);

const orgPolicy: ManagedPolicyDocument = {
  schemaVersion: 1,
  organization: "Example Corp",
  limits: { connect: false, maxRuntimeMode: "auto-accept-edits", telemetry: false },
};

it.layer(NodeServices.layer)("EnterprisePolicy.resolve", (it) => {
  it.effect("enforces the signed policy cached from the control plane", () =>
    Effect.gen(function* () {
      const key = yield* generateSigningKey("k1");
      const resolved = yield* resolveWith(configFor(key), yield* sign(key, orgPolicy));
      assert.strictEqual(resolved.version, 4);
      assert.deepEqual(resolved.document, orgPolicy);
    }),
  );

  it.effect("falls back to the bootstrap policy without a cached one", () =>
    Effect.gen(function* () {
      const key = yield* generateSigningKey("k1");
      const resolved = yield* resolveWith(configFor(key), undefined);
      assert.isUndefined(resolved.version);
      assert.strictEqual(resolved.document.limits?.maxRuntimeMode, "approval-required");
    }),
  );

  it.effect("refuses a policy signed by a key the config does not pin", () =>
    Effect.gen(function* () {
      const pinned = yield* generateSigningKey("k1");
      const forger = yield* generateSigningKey("k1");
      const resolved = yield* resolveWith(configFor(pinned), yield* sign(forger, orgPolicy));
      assert.isUndefined(resolved.version);
    }),
  );

  it.effect("refuses an expired policy", () =>
    Effect.gen(function* () {
      const key = yield* generateSigningKey("k1");
      const token = yield* sign(key, orgPolicy, 60);
      yield* TestClock.adjust("2 minutes");
      const resolved = yield* resolveWith(configFor(key), token);
      assert.isUndefined(resolved.version);
    }),
  );

  it.effect(
    "refuses a policy for another organization or with keys this build cannot enforce",
    () =>
      Effect.gen(function* () {
        const key = yield* generateSigningKey("k1");
        const config = configFor(key);
        const otherOrg = yield* resolveWith(
          config,
          yield* sign(key, { schemaVersion: 1, organization: "Other Corp" }),
        );
        assert.isUndefined(otherOrg.version);
        const unknownKey = yield* resolveWith(
          config,
          yield* sign(key, { ...orgPolicy, limits: { futureRestriction: true } }),
        );
        assert.isUndefined(unknownKey.version);
      }),
  );
});
