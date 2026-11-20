// Control plane, gateway, and a fake provider on loopback: the isolation properties in
// enterprise/PLAN.md §4, exercised over real TLS.
// @effect-diagnostics nodeBuiltinImport:off
import * as NodeCrypto from "node:crypto";
import * as NodeFS from "node:fs";
import * as NodeHttp from "node:http";
import * as NodeHttps from "node:https";
import * as NodeNet from "node:net";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";

import * as NodeServices from "@effect/platform-node/NodeServices";
import {
  createAuthorityPem,
  issueServerCertificatePem,
  parseAuthority,
} from "@t3tools/enterprise-control-plane/CertificateAuthority";
import { parseConfig as parseControlPlaneConfig } from "@t3tools/enterprise-control-plane/Config";
import * as ControlPlaneServer from "@t3tools/enterprise-control-plane/Server";
import { verifyPairingAssertion } from "@t3tools/enterprise-protocol/tokens";
import { enrollmentProofMessage } from "@t3tools/enterprise-protocol/wire";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import { layer } from "@effect/vitest";
import { describe, expect } from "vite-plus/test";

import { parseConfig as parseGatewayConfig } from "./Config.ts";
import * as Gateway from "./Gateway.ts";
import * as GatewayServer from "./Server.ts";

// TLS needs certificates valid now; a fixed epoch with a long life keeps the clock out of tests.
const CERT_EPOCH = Date.UTC(2026, 0, 1);
const CERT_DAYS = 365 * 20;

const authorityFor = (organization: string) => {
  const created = createAuthorityPem(organization, { nowMillis: CERT_EPOCH, years: 20 });
  return { ...created, authority: parseAuthority(created.certPem, created.keyPem) };
};

interface Reply {
  status: number;
  headers: NodeHttp.IncomingHttpHeaders;
  body: string;
}

function call(
  url: string,
  options: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    ca: string;
    cert?: string;
    key?: string;
  },
): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const request = NodeHttps.request(
      url,
      {
        method: options.method ?? "GET",
        headers: options.headers ?? {},
        ca: options.ca,
        ...(options.cert === undefined ? {} : { cert: options.cert }),
        ...(options.key === undefined ? {} : { key: options.key }),
        agent: false,
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () =>
          resolve({
            status: response.statusCode ?? 0,
            headers: response.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          }),
        );
      },
    );
    request.on("error", reject);
    request.end(options.body);
  });
}

const json = (reply: Reply) => JSON.parse(reply.body) as Record<string, unknown>;

async function freePort(): Promise<number> {
  const server = NodeNet.createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  if (address === null || typeof address === "string") throw new Error("no port");
  return address.port;
}

interface DeviceIdentity {
  keyPem: string;
  certPem: string;
  deviceId: string;
}

const dir = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "t3e-e2e-"));
const env = {
  T3E_GATEWAY_TOKEN: NodeCrypto.randomBytes(32).toString("base64url"),
  T3E_SCIM_TOKEN: NodeCrypto.randomBytes(32).toString("base64url"),
  T3E_ADMIN_API_TOKEN: NodeCrypto.randomBytes(32).toString("base64url"),
  UPSTREAM_ANTHROPIC_KEY: "sk-real-org-key",
  UPSTREAM_ANTHROPIC_EU_KEY: "sk-real-org-key-eu",
};

let caPem = "";
let controlPlaneUrl = "";
let gatewayUrl = "";
let jwks: { keys: ReadonlyArray<object> } = { keys: [] };
let sync: Effect.Effect<void, Gateway.ControlPlaneUnavailable> = Effect.void;
const upstreamRequests: Array<{
  headers: NodeHttp.IncomingHttpHeaders;
  body: string;
  region: string;
}> = [];

const admin = (path: string, init: { method?: string; body?: unknown } = {}) =>
  call(`${controlPlaneUrl}/v1/admin${path}`, {
    method: init.method ?? "GET",
    ca: caPem,
    headers: {
      authorization: `Bearer ${env.T3E_ADMIN_API_TOKEN}`,
      "content-type": "application/json",
    },
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  });

const scim = (path: string, init: { method?: string; body?: unknown } = {}) =>
  call(`${controlPlaneUrl}/scim/v2${path}`, {
    method: init.method ?? "GET",
    ca: caPem,
    headers: {
      authorization: `Bearer ${env.T3E_SCIM_TOKEN}`,
      "content-type": "application/scim+json",
    },
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  });

/** Signs in through the development login and enrolls a fresh device key, as `t3 enterprise enroll` does. */
async function enroll(email: string): Promise<DeviceIdentity> {
  const deviceState = NodeCrypto.randomBytes(24).toString("base64url");
  const start = await call(
    `${controlPlaneUrl}/enroll/start?redirect_uri=${encodeURIComponent("http://127.0.0.1:9/callback")}&state=${deviceState}`,
    { ca: caPem },
  );
  expect(start.status).toBe(302);
  const loginState = new URL(start.headers.location!, controlPlaneUrl).searchParams.get("state")!;
  const login = await call(`${controlPlaneUrl}/dev/login`, {
    method: "POST",
    ca: caPem,
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ state: loginState, email }).toString(),
  });
  expect(login.status).toBe(302);
  const callback = new URL(login.headers.location!);
  expect(callback.origin).toBe("http://127.0.0.1:9");
  expect(callback.searchParams.get("state")).toBe(deviceState);
  const code = callback.searchParams.get("code")!;

  const { privateKey, publicKey } = NodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const proof = NodeCrypto.sign(
    "sha256",
    Buffer.from(enrollmentProofMessage(code)),
    privateKey,
  ).toString("base64url");
  const enrolled = await call(`${controlPlaneUrl}/v1/enroll`, {
    method: "POST",
    ca: caPem,
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      code,
      publicKeyPem: publicKey,
      proof,
      hostname: "laptop",
      platform: "darwin",
    }),
  });
  expect(enrolled.status).toBe(200);
  const body = json(enrolled);
  return {
    keyPem: privateKey,
    certPem: String(body["certificatePem"]),
    deviceId: String(body["deviceId"]),
  };
}

const lease = (device: DeviceIdentity) =>
  call(`${controlPlaneUrl}/v1/lease`, {
    method: "POST",
    ca: caPem,
    cert: device.certPem,
    key: device.keyPem,
  });

const leaseToken = async (device: DeviceIdentity) => {
  const reply = await lease(device);
  expect(reply.status).toBe(200);
  return String(json(reply)["lease"]);
};

const message = (device: DeviceIdentity, token: string, model = "claude-haiku-5-5") =>
  call(`${gatewayUrl}/anthropic/v1/messages`, {
    method: "POST",
    ca: caPem,
    cert: device.certPem,
    key: device.keyPem,
    headers: {
      "content-type": "application/json",
      "x-api-key": token,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model,
      max_tokens: 16,
      stream: true,
      messages: [{ role: "user", content: "hi" }],
    }),
  });

const startUpstream = (region: string) =>
  Effect.acquireRelease(
    Effect.promise(() => {
      const upstream = NodeHttp.createServer((request, response) => {
        const chunks: Buffer[] = [];
        request.on("data", (chunk: Buffer) => chunks.push(chunk));
        request.on("end", () => {
          upstreamRequests.push({
            headers: request.headers,
            body: Buffer.concat(chunks).toString("utf8"),
            region,
          });
          response.writeHead(200, { "content-type": "text/event-stream" });
          response.write(
            'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":100,"output_tokens":1}}}\n\n',
          );
          response.end(
            'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":50}}\n\n',
          );
        });
      });
      return new Promise<{ server: NodeHttp.Server; port: number }>((resolve) =>
        upstream.listen(0, "127.0.0.1", () => {
          const address = upstream.address() as NodeNet.AddressInfo;
          resolve({ server: upstream, port: address.port });
        }),
      );
    }),
    ({ server }) =>
      Effect.promise(() => new Promise<void>((resolve) => server.close(() => resolve()))),
  );

/** Control plane, gateway, and two fake upstreams for the whole file. */
const layerHarness = Layer.effectDiscard(
  Effect.gen(function* () {
    const ca = authorityFor("Example Corp");
    NodeFS.writeFileSync(NodePath.join(dir, "ca.crt"), ca.certPem);
    NodeFS.writeFileSync(NodePath.join(dir, "ca.key"), ca.keyPem);
    caPem = ca.certPem;
    const tls = issueServerCertificatePem(ca.authority, {
      hostnames: ["localhost", "127.0.0.1"],
      days: CERT_DAYS,
      nowMillis: CERT_EPOCH,
    });
    NodeFS.writeFileSync(NodePath.join(dir, "tls.crt"), tls.certPem);
    NodeFS.writeFileSync(NodePath.join(dir, "tls.key"), tls.keyPem);

    const upstream = yield* startUpstream("default");
    const upstreamEu = yield* startUpstream("eu");

    const controlPlanePort = yield* Effect.promise(freePort);
    controlPlaneUrl = `https://localhost:${controlPlanePort}`;
    const controlPlaneSettings = yield* parseControlPlaneConfig(
      {
        publicUrl: controlPlaneUrl,
        organization: "Example Corp",
        listen: { host: "127.0.0.1", port: controlPlanePort },
        tls: { certPath: "tls.crt", keyPath: "tls.key" },
        dataDir: "data",
        ca: { certPath: "ca.crt", keyPath: "ca.key" },
        insecureDevLogin: true,
        provisioning: "jit",
        regions: ["eu", "us"],
        groupRoles: { "t3-admins": "admin", "t3-auditors": "auditor" },
      },
      { baseDir: dir, env },
    );

    const gatewayPort = yield* Effect.promise(freePort);
    gatewayUrl = `https://localhost:${gatewayPort}`;
    const gatewaySettings = yield* parseGatewayConfig(
      {
        listen: { host: "127.0.0.1", port: gatewayPort },
        tls: { certPath: "tls.crt", keyPath: "tls.key" },
        deviceCaPath: "ca.crt",
        controlPlaneUrl,
        controlPlaneCaPath: "ca.crt",
        upstreams: [
          {
            family: "anthropic",
            baseUrl: `http://127.0.0.1:${upstream.port}`,
            apiKeyEnv: "UPSTREAM_ANTHROPIC_KEY",
          },
          {
            family: "anthropic",
            region: "eu",
            baseUrl: `http://127.0.0.1:${upstreamEu.port}`,
            apiKeyEnv: "UPSTREAM_ANTHROPIC_EU_KEY",
          },
        ],
        redaction: { mode: "redact" },
      },
      { baseDir: dir, env },
    );

    yield* Layer.build(ControlPlaneServer.layer(controlPlaneSettings));
    const gateway = Context.get(
      yield* Layer.build(GatewayServer.layer(gatewaySettings)),
      Gateway.Gateway,
    );
    sync = gateway.sync;
    yield* sync;
    jwks = JSON.parse(
      (yield* Effect.promise(() => call(`${controlPlaneUrl}/.well-known/jwks.json`, { ca: caPem })))
        .body,
    );
  }),
).pipe(Layer.provide(NodeServices.layer));

layer(layerHarness, { timeout: "60 seconds", excludeTestServices: true })("enterprise", (it) => {
  describe("enrolled device", () => {
    it.effect("streams a turn through the gateway with the org key, never its lease", () =>
      Effect.gen(function* () {
        const device = yield* Effect.promise(() => enroll("dev@example.test"));
        const token = yield* Effect.promise(() => leaseToken(device));
        const reply = yield* Effect.promise(() => message(device, token));
        expect(reply.status).toBe(200);
        expect(reply.body).toContain("message_delta");
        const seen = upstreamRequests.at(-1)!;
        expect(seen.headers["x-api-key"]).toBe("sk-real-org-key");
        expect(JSON.stringify(seen.headers)).not.toContain(token);
      }),
    );

    it.effect("meters usage into the control plane", () =>
      Effect.gen(function* () {
        yield* sync;
        const report = json(yield* Effect.promise(() => admin("/usage")));
        const rows = report["rows"] as Array<Record<string, unknown>>;
        expect(rows.find((row) => row["email"] === "dev@example.test")).toMatchObject({
          inputTokens: 100,
          outputTokens: 50,
        });
      }),
    );
  });

  describe("isolation", () => {
    it.effect("refuses a TLS handshake without a device certificate", () =>
      Effect.promise(() =>
        expect(
          call(`${gatewayUrl}/anthropic/v1/messages`, { method: "POST", ca: caPem, body: "{}" }),
        ).rejects.toThrow(),
      ),
    );

    it.effect("refuses a certificate from another CA", () =>
      Effect.gen(function* () {
        const other = authorityFor("Personal");
        const impostor = issueServerCertificatePem(other.authority, {
          hostnames: ["laptop"],
          days: CERT_DAYS,
          nowMillis: CERT_EPOCH,
        });
        yield* Effect.promise(() =>
          expect(
            call(`${gatewayUrl}/anthropic/v1/messages`, {
              method: "POST",
              ca: caPem,
              cert: impostor.certPem,
              key: impostor.keyPem,
              body: "{}",
            }),
          ).rejects.toThrow(),
        );
      }),
    );

    it.effect("refuses a lease presented by a different enrolled device", () =>
      Effect.gen(function* () {
        const owner = yield* Effect.promise(() => enroll("owner@example.test"));
        const thief = yield* Effect.promise(() => enroll("thief@example.test"));
        const reply = yield* Effect.promise(() =>
          leaseToken(owner).then((token) => message(thief, token)),
        );
        expect(reply.status).toBe(401);
        expect(reply.body).toContain("different device certificate");
      }),
    );

    it.effect("does not hand a lease to a device without a certificate", () =>
      Effect.gen(function* () {
        const reply = yield* Effect.promise(() =>
          call(`${controlPlaneUrl}/v1/lease`, { method: "POST", ca: caPem }),
        );
        expect(reply.status).toBe(401);
      }),
    );
  });

  describe("org controls", () => {
    it.effect("stops a revoked device at the gateway and at lease renewal", () =>
      Effect.gen(function* () {
        const device = yield* Effect.promise(() => enroll("revoked@example.test"));
        const token = yield* Effect.promise(() => leaseToken(device));
        expect((yield* Effect.promise(() => message(device, token))).status).toBe(200);

        expect(
          (yield* Effect.promise(() =>
            admin(`/devices/${device.deviceId}/revoke`, { method: "POST" }),
          )).status,
        ).toBe(200);
        yield* sync;

        expect((yield* Effect.promise(() => message(device, token))).status).toBe(403);
        const renewal = yield* Effect.promise(() => lease(device));
        expect(renewal.status).toBe(403);
        expect(json(renewal)["error"]).toBe("device_revoked");

        // What a revoked device did last is what security most wants to see.
        const audit = yield* Effect.promise(() =>
          call(`${controlPlaneUrl}/v1/audit`, {
            method: "POST",
            ca: caPem,
            cert: device.certPem,
            key: device.keyPem,
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              events: [
                {
                  id: "after-revoke",
                  type: "command.executed",
                  occurredAt: "2026-11-20T12:00:00.000Z",
                },
              ],
            }),
          }),
        );
        expect(json(audit)).toMatchObject({ accepted: 1 });
      }),
    );

    it.effect("enforces a model allow-list carried in the lease", () =>
      Effect.gen(function* () {
        const device = yield* Effect.promise(() => enroll("haiku-only@example.test"));
        const users = json(yield* Effect.promise(() => admin("/users")))["users"] as Array<
          Record<string, unknown>
        >;
        const user = users.find((u) => u["email"] === "haiku-only@example.test")!;
        yield* Effect.promise(() =>
          admin(`/users/${String(user["id"])}`, {
            method: "PATCH",
            body: { models: ["claude-haiku-*"] },
          }),
        );
        const token = yield* Effect.promise(() => leaseToken(device));
        expect(
          (yield* Effect.promise(() => message(device, token, "claude-haiku-5-5"))).status,
        ).toBe(200);
        const denied = yield* Effect.promise(() => message(device, token, "claude-opus-5-5"));
        expect(denied.status).toBe(403);
        expect(json(denied)).toMatchObject({ type: "error", error: { type: "permission_error" } });
      }),
    );

    it.effect("cuts off a user who spends their monthly budget", () =>
      Effect.gen(function* () {
        const device = yield* Effect.promise(() => enroll("budget@example.test"));
        const users = json(yield* Effect.promise(() => admin("/users")))["users"] as Array<
          Record<string, unknown>
        >;
        const user = users.find((u) => u["email"] === "budget@example.test")!;
        yield* Effect.promise(() =>
          admin(`/users/${String(user["id"])}`, { method: "PATCH", body: { monthlyTokens: 100 } }),
        );
        const token = yield* Effect.promise(() => leaseToken(device));
        expect((yield* Effect.promise(() => message(device, token))).status).toBe(200);
        yield* sync;
        yield* sync;

        expect((yield* Effect.promise(() => message(device, token))).status).toBe(429);
        expect(json(yield* Effect.promise(() => lease(device)))["error"]).toBe("over_budget");
      }),
    );

    it.effect("deprovisions through SCIM: the user's devices stop", () =>
      Effect.gen(function* () {
        const created = yield* Effect.promise(() =>
          scim("/Users", {
            method: "POST",
            body: {
              schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
              userName: "leaver@example.test",
              active: true,
            },
          }),
        );
        expect(created.status).toBe(201);
        const device = yield* Effect.promise(() => enroll("leaver@example.test"));
        expect((yield* Effect.promise(() => lease(device))).status).toBe(200);

        const id = String(json(created)["id"]);
        const patched = yield* Effect.promise(() =>
          scim(`/Users/${id}`, {
            method: "PATCH",
            body: {
              schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
              Operations: [{ op: "Replace", path: "active", value: "False" }],
            },
          }),
        );
        expect(json(patched)["active"]).toBe(false);
        expect(json(yield* Effect.promise(() => lease(device)))["error"]).toBe("device_revoked");
      }),
    );

    it.effect("stores device audit events once, with ids as long as T3's event ids", () =>
      Effect.gen(function* () {
        const device = yield* Effect.promise(() => enroll("audited@example.test"));
        // T3 event ids embed the thread and command ids and run past 128 characters.
        const id = `event:thread:mcp%3A${"a".repeat(36)}:command:mcp%3A${"b".repeat(36)}:${"c".repeat(36)}`;
        const send = () =>
          call(`${controlPlaneUrl}/v1/audit`, {
            method: "POST",
            ca: caPem,
            cert: device.certPem,
            key: device.keyPem,
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              events: [
                {
                  id,
                  type: "thread.created",
                  occurredAt: "2026-11-20T12:00:00.000Z",
                  threadId: "t1",
                },
              ],
            }),
          });
        expect(json(yield* Effect.promise(() => send()))).toMatchObject({
          accepted: 1,
          rejected: 0,
        });
        yield* Effect.promise(() => send());
        const events = json(yield* Effect.promise(() => admin("/audit?limit=1000")))[
          "events"
        ] as Array<Record<string, unknown>>;
        expect(events.filter((event) => event["id"] === id)).toHaveLength(1);
      }),
    );

    it.effect("records enrollments and revocations in the audit trail", () =>
      Effect.gen(function* () {
        const events = json(yield* Effect.promise(() => admin("/audit?limit=1000")))[
          "events"
        ] as Array<Record<string, unknown>>;
        const types = new Set(events.map((event) => event["type"]));
        expect(types).toContain("device.enrolled");
        expect(types).toContain("device.revoked");
        expect(types).toContain("user.deactivated");
      }),
    );
  });

  describe("governance", () => {
    const userId = async (email: string) => {
      const users = json(await admin("/users"))["users"] as Array<Record<string, unknown>>;
      return String(users.find((user) => user["email"] === email)!["id"]);
    };

    it.effect(
      "redacts credentials from prompts before they reach the provider, and counts them",
      () =>
        Effect.gen(function* () {
          const device = yield* Effect.promise(() => enroll("leaky@example.test"));
          const token = yield* Effect.promise(() => leaseToken(device));
          const privateKey = NodeCrypto.generateKeyPairSync("rsa", {
            modulusLength: 2048,
            privateKeyEncoding: { type: "pkcs8", format: "pem" },
            publicKeyEncoding: { type: "spki", format: "pem" },
          }).privateKey;
          const reply = yield* Effect.promise(() =>
            call(`${gatewayUrl}/anthropic/v1/messages`, {
              method: "POST",
              ca: caPem,
              cert: device.certPem,
              key: device.keyPem,
              headers: { "content-type": "application/json", "x-api-key": token },
              body: JSON.stringify({
                model: "claude-haiku-5-5",
                max_tokens: 16,
                messages: [
                  {
                    role: "user",
                    content: `deploy with AKIAIOSFODNN7EXAMPLE and this key:\n${privateKey}`,
                  },
                ],
              }),
            }),
          );
          expect(reply.status).toBe(200);
          const seen = upstreamRequests.at(-1)!.body;
          expect(seen).not.toContain("AKIAIOSFODNN7EXAMPLE");
          expect(seen).not.toContain("PRIVATE KEY-----\\nMII");
          expect(seen).toContain("[REDACTED:aws-access-key]");
          expect(seen).toContain("[REDACTED:private-key]");
          expect(() => JSON.parse(seen)).not.toThrow();

          yield* sync;
          const rows = json(yield* Effect.promise(() => admin("/usage")))["rows"] as Array<
            Record<string, unknown>
          >;
          expect(rows.find((row) => row["email"] === "leaky@example.test")).toMatchObject({
            redactions: 2,
          });
        }),
    );

    it.effect("keeps a user's traffic on upstreams in their data region", () =>
      Effect.gen(function* () {
        const device = yield* Effect.promise(() => enroll("eu-dev@example.test"));
        const id = yield* Effect.promise(() => userId("eu-dev@example.test"));
        yield* Effect.promise(() =>
          admin(`/users/${id}`, { method: "PATCH", body: { region: "eu" } }),
        );
        const reply = yield* Effect.promise(() =>
          leaseToken(device).then((token) => message(device, token)),
        );
        expect(reply.status).toBe(200);
        expect(upstreamRequests.at(-1)).toMatchObject({ region: "eu" });
        expect(upstreamRequests.at(-1)!.headers["x-api-key"]).toBe("sk-real-org-key-eu");

        yield* Effect.promise(() =>
          admin(`/users/${id}`, { method: "PATCH", body: { region: "us" } }),
        );
        const refused = yield* Effect.promise(() =>
          leaseToken(device).then((token) => message(device, token)),
        );
        expect(refused.status).toBe(403);
        expect(refused.body).toContain("data region (us)");

        const invalid = yield* Effect.promise(() =>
          admin(`/users/${id}`, { method: "PATCH", body: { region: "mars" } }),
        );
        expect(json(invalid)["error"]).toBe("invalid_region");
      }),
    );

    it.effect("maps SCIM group membership to roles", () =>
      Effect.gen(function* () {
        const created = yield* Effect.promise(() =>
          scim("/Users", {
            method: "POST",
            body: {
              schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
              userName: "lead@example.test",
            },
          }),
        );
        const id = String(json(created)["id"]);
        const group = yield* Effect.promise(() =>
          scim("/Groups", {
            method: "POST",
            body: {
              schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
              displayName: "t3-admins",
              members: [{ value: id }],
            },
          }),
        );
        expect(group.status).toBe(201);
        expect(json(yield* Effect.promise(() => scim(`/Users/${id}`)))["roles"]).toEqual([
          { value: "admin" },
        ]);

        yield* Effect.promise(() =>
          scim(`/Groups/${String(json(group)["id"])}`, {
            method: "PATCH",
            body: {
              schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
              Operations: [{ op: "remove", path: `members[value eq "${id}"]` }],
            },
          }),
        );
        expect(json(yield* Effect.promise(() => scim(`/Users/${id}`)))["roles"]).toEqual([
          { value: "developer" },
        ]);
      }),
    );

    it.effect("places and releases legal holds, recording both", () =>
      Effect.gen(function* () {
        yield* Effect.promise(() => enroll("held@example.test"));
        const id = yield* Effect.promise(() => userId("held@example.test"));
        expect(
          (yield* Effect.promise(() =>
            admin(`/legal-holds/${id}`, { method: "PUT", body: { reason: "case 42" } }),
          )).status,
        ).toBe(200);
        const holds = json(yield* Effect.promise(() => admin("/legal-holds")))["holds"] as Array<
          Record<string, unknown>
        >;
        expect(holds).toEqual([expect.objectContaining({ userId: id, reason: "case 42" })]);
        yield* Effect.promise(() => admin(`/legal-holds/${id}`, { method: "DELETE" }));
        expect(json(yield* Effect.promise(() => admin("/legal-holds")))["holds"]).toEqual([]);
      }),
    );
  });

  describe("SSO-gated pairing", () => {
    const signInFor = async (start: Reply, email: string) => {
      const loginState = new URL(start.headers.location!, controlPlaneUrl).searchParams.get(
        "state",
      )!;
      return call(`${controlPlaneUrl}/dev/login`, {
        method: "POST",
        ca: caPem,
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ state: loginState, email }).toString(),
      });
    };
    const startPairing = (deviceId: string) =>
      call(
        `${controlPlaneUrl}/pair/start?${new URLSearchParams({
          device: deviceId,
          return_to: "https://env.example.test/api/enterprise/pair/callback",
          state: "client-state-123456789",
          nonce: "client-nonce-123456789",
        })}`,
        { ca: caPem },
      );

    it.effect("issues an assertion the environment can verify, after the owner approves", () =>
      Effect.gen(function* () {
        const device = yield* Effect.promise(() => enroll("pairer@example.test"));
        const confirm = yield* Effect.promise(() =>
          startPairing(device.deviceId).then((start) => signInFor(start, "pairer@example.test")),
        );
        expect(confirm.status).toBe(200);
        expect(confirm.body).toContain("https://env.example.test");
        const state = /name="state" value="([^"]+)"/.exec(confirm.body)![1]!;
        const approved = yield* Effect.promise(() =>
          call(`${controlPlaneUrl}/pair/confirm`, {
            method: "POST",
            ca: caPem,
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({ state }).toString(),
          }),
        );
        expect(approved.status).toBe(302);
        const target = new URL(approved.headers.location!);
        expect(target.origin).toBe("https://env.example.test");
        expect(target.searchParams.get("state")).toBe("client-state-123456789");
        const claims = yield* verifyPairingAssertion(target.searchParams.get("assertion")!, jwks, {
          issuer: controlPlaneUrl,
        });
        expect(claims).toMatchObject({
          email: "pairer@example.test",
          deviceId: device.deviceId,
          nonce: "client-nonce-123456789",
        });
      }),
    );

    it.effect("refuses someone who does not own the environment", () =>
      Effect.gen(function* () {
        const device = yield* Effect.promise(() => enroll("owner-of-env@example.test"));
        const refused = yield* Effect.promise(() =>
          startPairing(device.deviceId).then((start) => signInFor(start, "intruder@example.test")),
        );
        expect(refused.status).toBe(403);
        expect(refused.body).toContain("belongs to someone else");
      }),
    );

    it.effect("refuses a return address that is neither https nor loopback", () =>
      Effect.gen(function* () {
        const reply = yield* Effect.promise(() =>
          call(
            `${controlPlaneUrl}/pair/start?${new URLSearchParams({
              device: "d",
              return_to: "http://attacker.example/cb",
              state: "client-state-123456789",
              nonce: "client-nonce-123456789",
            })}`,
            { ca: caPem },
          ),
        );
        expect(reply.status).toBe(400);
      }),
    );
  });

  describe("team features", () => {
    const deviceCall = (
      device: DeviceIdentity,
      path: string,
      init: { method?: string; body?: unknown } = {},
    ) =>
      call(`${controlPlaneUrl}${path}`, {
        method: init.method ?? "GET",
        ca: caPem,
        cert: device.certPem,
        key: device.keyPem,
        headers: { "content-type": "application/json" },
        ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
      });
    const joinTeam = async (email: string, team: string) => {
      const users = json(await admin("/users"))["users"] as Array<Record<string, unknown>>;
      const id = String(users.find((user) => user["email"] === email)!["id"]);
      await admin(`/users/${id}`, { method: "PATCH", body: { team } });
    };

    it.effect("hands each machine the org library, with its team's items taking precedence", () =>
      Effect.gen(function* () {
        const platform = yield* Effect.promise(() => enroll("platform-dev@example.test"));
        const web = yield* Effect.promise(() => enroll("web-dev@example.test"));
        yield* Effect.promise(() => joinTeam("platform-dev@example.test", "platform"));
        yield* Effect.promise(() => joinTeam("web-dev@example.test", "web"));
        const put = (body: Record<string, unknown>) =>
          admin("/library", { method: "PUT", body: { description: "", team: null, ...body } });
        yield* Effect.promise(() =>
          put({ kind: "instructions", name: "guidelines", content: "org rules" }),
        );
        yield* Effect.promise(() =>
          put({
            kind: "instructions",
            name: "guidelines",
            content: "platform rules",
            team: "platform",
          }),
        );
        yield* Effect.promise(() =>
          put({ kind: "skill", name: "deploy", content: "# Deploy", team: "platform" }),
        );
        const invalid = yield* Effect.promise(() =>
          put({ kind: "mcp-server", name: "bad", content: "not json" }),
        );
        expect(invalid.status).toBe(400);

        const library = (device: DeviceIdentity) =>
          Effect.promise(() => deviceCall(device, "/v1/library")).pipe(
            Effect.map((reply) => json(reply)["items"] as Array<Record<string, unknown>>),
          );
        const platformItems = yield* library(platform);
        expect(platformItems.map((item) => [item["name"], item["content"]])).toEqual(
          expect.arrayContaining([
            ["guidelines", "platform rules"],
            ["deploy", "# Deploy"],
          ]),
        );
        expect(platformItems).toHaveLength(2);
        const webItems = yield* library(web);
        expect(webItems.map((item) => [item["name"], item["content"]])).toEqual([
          ["guidelines", "org rules"],
        ]);
      }),
    );

    it.effect("shares a thread with the sharer's team only, and records each import", () =>
      Effect.gen(function* () {
        const sharer = yield* Effect.promise(() => enroll("sharer@example.test"));
        const teammate = yield* Effect.promise(() => enroll("teammate@example.test"));
        const outsider = yield* Effect.promise(() => enroll("outsider@example.test"));
        yield* Effect.promise(() => joinTeam("sharer@example.test", "payments"));
        yield* Effect.promise(() => joinTeam("teammate@example.test", "payments"));
        const created = yield* Effect.promise(() =>
          deviceCall(sharer, "/v1/shared-threads", {
            method: "POST",
            body: {
              title: "Fix refund rounding",
              repository: "git@github.com:example/payments.git",
              branch: "fix/refunds",
              provider: "claudeAgent",
              transcript: "## User\nFix the rounding",
              patch: "diff --git a/x b/x\n",
              audience: "team",
              note: "Tests still fail on EUR",
            },
          }),
        );
        expect(created.status).toBe(201);
        const id = String(json(created)["id"]);

        const listFor = (device: DeviceIdentity) =>
          Effect.promise(() => deviceCall(device, "/v1/shared-threads")).pipe(
            Effect.map((reply) =>
              (json(reply)["threads"] as Array<Record<string, unknown>>).map(
                (thread) => thread["id"],
              ),
            ),
          );
        expect(yield* listFor(teammate)).toContain(id);
        expect(yield* listFor(outsider)).not.toContain(id);
        expect(
          (yield* Effect.promise(() => deviceCall(outsider, `/v1/shared-threads/${id}`))).status,
        ).toBe(404);

        const opened = json(
          yield* Effect.promise(() => deviceCall(teammate, `/v1/shared-threads/${id}`)),
        );
        expect(opened).toMatchObject({
          title: "Fix refund rounding",
          sharedBy: "sharer@example.test",
        });
        expect(opened["patch"]).toContain("diff --git");

        const activity = json(yield* Effect.promise(() => admin("/activity?team=payments")))[
          "events"
        ] as Array<Record<string, unknown>>;
        expect(activity.map((event) => event["type"])).toEqual(
          expect.arrayContaining(["thread.shared", "thread.imported"]),
        );
      }),
    );

    it.effect("shows each machine's last heartbeat in the fleet", () =>
      Effect.gen(function* () {
        const device = yield* Effect.promise(() => enroll("fleet@example.test"));
        const sent = yield* Effect.promise(() =>
          deviceCall(device, "/v1/heartbeat", {
            method: "POST",
            body: {
              clientVersion: "0.9.0",
              platform: "darwin",
              hostname: "laptop",
              policyVersion: 3,
              restartRequired: true,
              activeTurns: 2,
              modelAccess: "ok",
            },
          }),
        );
        expect(sent.status).toBe(200);
        const devices = json(yield* Effect.promise(() => admin("/devices")))["devices"] as Array<
          Record<string, unknown>
        >;
        expect(devices.find((row) => row["id"] === device.deviceId)).toMatchObject({
          clientVersion: "0.9.0",
          heartbeat: expect.objectContaining({ activeTurns: 2, restartRequired: true }),
        });
      }),
    );
  });
});
