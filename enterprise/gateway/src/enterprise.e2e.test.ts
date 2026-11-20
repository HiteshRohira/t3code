// Control plane, gateway, and a fake provider on loopback: the isolation properties in
// enterprise/PLAN.md §4, exercised over real TLS.
import * as NodeCrypto from "node:crypto";
import * as NodeFS from "node:fs";
import * as NodeHttp from "node:http";
import * as NodeHttps from "node:https";
import * as NodeNet from "node:net";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";

import {
  createCertificateAuthority,
  issueServerCertificate,
  loadOrCreateCertificateAuthority,
} from "@t3tools/enterprise-control-plane/ca";
import { parseConfig as parseControlPlaneConfig } from "@t3tools/enterprise-control-plane/config";
import { startControlPlane } from "@t3tools/enterprise-control-plane/server";
import { enrollmentProofMessage } from "@t3tools/enterprise-protocol/wire";

import { parseConfig as parseGatewayConfig } from "./config.ts";
import { startGateway, type Gateway } from "./gateway.ts";

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
};

let caPem = "";
let controlPlaneUrl = "";
let gatewayUrl = "";
let gateway: Gateway;
let closeAll: () => Promise<void>;
const upstreamRequests: Array<{ headers: NodeHttp.IncomingHttpHeaders; body: string }> = [];

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

beforeAll(async () => {
  const ca = createCertificateAuthority("Example Corp");
  NodeFS.writeFileSync(NodePath.join(dir, "ca.crt"), ca.certPem);
  NodeFS.writeFileSync(NodePath.join(dir, "ca.key"), ca.keyPem);
  caPem = ca.certPem;
  const loaded = loadOrCreateCertificateAuthority(
    { certPath: NodePath.join(dir, "ca.crt"), keyPath: NodePath.join(dir, "ca.key") },
    "Example Corp",
  );
  const tls = issueServerCertificate(loaded, { hostnames: ["localhost", "127.0.0.1"], days: 1 });
  NodeFS.writeFileSync(NodePath.join(dir, "tls.crt"), tls.certPem);
  NodeFS.writeFileSync(NodePath.join(dir, "tls.key"), tls.keyPem);

  const upstream: NodeHttp.Server = NodeHttp.createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      upstreamRequests.push({
        headers: request.headers,
        body: Buffer.concat(chunks).toString("utf8"),
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
  await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  const upstreamAddress = upstream.address();
  if (upstreamAddress === null || typeof upstreamAddress === "string")
    throw new Error("no upstream port");

  const controlPlanePort = await freePort();
  controlPlaneUrl = `https://localhost:${controlPlanePort}`;
  const controlPlane = await startControlPlane(
    parseControlPlaneConfig(
      {
        publicUrl: controlPlaneUrl,
        organization: "Example Corp",
        listen: { host: "127.0.0.1", port: controlPlanePort },
        tls: { certPath: "tls.crt", keyPath: "tls.key" },
        dataDir: "data",
        ca: { certPath: "ca.crt", keyPath: "ca.key" },
        insecureDevLogin: true,
        provisioning: "jit",
      },
      { baseDir: dir, env },
    ),
  );

  const gatewayPort = await freePort();
  gatewayUrl = `https://localhost:${gatewayPort}`;
  const started = await startGateway(
    parseGatewayConfig(
      {
        listen: { host: "127.0.0.1", port: gatewayPort },
        tls: { certPath: "tls.crt", keyPath: "tls.key" },
        deviceCaPath: "ca.crt",
        controlPlaneUrl,
        controlPlaneCaPath: "ca.crt",
        upstreams: [
          {
            family: "anthropic",
            baseUrl: `http://127.0.0.1:${upstreamAddress.port}`,
            apiKeyEnv: "UPSTREAM_ANTHROPIC_KEY",
          },
        ],
      },
      { baseDir: dir, env },
    ),
  );
  gateway = started.gateway;
  await gateway.sync();

  closeAll = async () => {
    await started.close();
    await controlPlane.close();
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
  };
});

afterAll(async () => {
  await closeAll();
});

describe("enrolled device", () => {
  it("streams a turn through the gateway with the org key, never its lease", async () => {
    const device = await enroll("dev@example.test");
    const token = await leaseToken(device);
    const reply = await message(device, token);
    expect(reply.status).toBe(200);
    expect(reply.body).toContain("message_delta");
    const seen = upstreamRequests.at(-1)!;
    expect(seen.headers["x-api-key"]).toBe("sk-real-org-key");
    expect(JSON.stringify(seen.headers)).not.toContain(token);
  });

  it("meters usage into the control plane", async () => {
    await gateway.sync();
    const report = json(await admin("/usage"));
    const rows = report["rows"] as Array<Record<string, unknown>>;
    expect(rows.find((row) => row["email"] === "dev@example.test")).toMatchObject({
      inputTokens: 100,
      outputTokens: 50,
    });
  });
});

describe("isolation", () => {
  it("refuses a TLS handshake without a device certificate", async () => {
    await expect(
      call(`${gatewayUrl}/anthropic/v1/messages`, { method: "POST", ca: caPem, body: "{}" }),
    ).rejects.toThrow();
  });

  it("refuses a certificate from another CA", async () => {
    const otherCa = createCertificateAuthority("Personal");
    NodeFS.writeFileSync(NodePath.join(dir, "other-ca.crt"), otherCa.certPem);
    NodeFS.writeFileSync(NodePath.join(dir, "other-ca.key"), otherCa.keyPem);
    const other = loadOrCreateCertificateAuthority(
      { certPath: NodePath.join(dir, "other-ca.crt"), keyPath: NodePath.join(dir, "other-ca.key") },
      "Personal",
    );
    const impostor = issueServerCertificate(other, { hostnames: ["laptop"], days: 1 });
    await expect(
      call(`${gatewayUrl}/anthropic/v1/messages`, {
        method: "POST",
        ca: caPem,
        cert: impostor.certPem,
        key: impostor.keyPem,
        body: "{}",
      }),
    ).rejects.toThrow();
  });

  it("refuses a lease presented by a different enrolled device", async () => {
    const owner = await enroll("owner@example.test");
    const thief = await enroll("thief@example.test");
    const reply = await message(thief, await leaseToken(owner));
    expect(reply.status).toBe(401);
    expect(reply.body).toContain("different device certificate");
  });

  it("does not hand a lease to a device without a certificate", async () => {
    const reply = await call(`${controlPlaneUrl}/v1/lease`, { method: "POST", ca: caPem });
    expect(reply.status).toBe(401);
  });
});

describe("org controls", () => {
  it("stops a revoked device at the gateway and at lease renewal", async () => {
    const device = await enroll("revoked@example.test");
    const token = await leaseToken(device);
    expect((await message(device, token)).status).toBe(200);

    expect((await admin(`/devices/${device.deviceId}/revoke`, { method: "POST" })).status).toBe(
      200,
    );
    await gateway.sync();

    expect((await message(device, token)).status).toBe(403);
    const renewal = await lease(device);
    expect(renewal.status).toBe(403);
    expect(json(renewal)["error"]).toBe("device_revoked");

    // What a revoked device did last is what security most wants to see.
    const audit = await call(`${controlPlaneUrl}/v1/audit`, {
      method: "POST",
      ca: caPem,
      cert: device.certPem,
      key: device.keyPem,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        events: [
          { id: "after-revoke", type: "command.executed", occurredAt: "2026-11-20T12:00:00.000Z" },
        ],
      }),
    });
    expect(json(audit)).toMatchObject({ accepted: 1 });
  });

  it("enforces a model allow-list carried in the lease", async () => {
    const device = await enroll("haiku-only@example.test");
    const users = json(await admin("/users"))["users"] as Array<Record<string, unknown>>;
    const user = users.find((u) => u["email"] === "haiku-only@example.test")!;
    await admin(`/users/${String(user["id"])}`, {
      method: "PATCH",
      body: { models: ["claude-haiku-*"] },
    });
    const token = await leaseToken(device);
    expect((await message(device, token, "claude-haiku-5-5")).status).toBe(200);
    const denied = await message(device, token, "claude-opus-5-5");
    expect(denied.status).toBe(403);
    expect(json(denied)).toMatchObject({ type: "error", error: { type: "permission_error" } });
  });

  it("cuts off a user who spends their monthly budget", async () => {
    const device = await enroll("budget@example.test");
    const users = json(await admin("/users"))["users"] as Array<Record<string, unknown>>;
    const user = users.find((u) => u["email"] === "budget@example.test")!;
    await admin(`/users/${String(user["id"])}`, { method: "PATCH", body: { monthlyTokens: 100 } });
    const token = await leaseToken(device);
    expect((await message(device, token)).status).toBe(200);
    await gateway.sync();
    await gateway.sync();

    expect((await message(device, token)).status).toBe(429);
    expect(json(await lease(device))["error"]).toBe("over_budget");
  });

  it("deprovisions through SCIM: the user's devices stop", async () => {
    const created = await scim("/Users", {
      method: "POST",
      body: {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "leaver@example.test",
        active: true,
      },
    });
    expect(created.status).toBe(201);
    const device = await enroll("leaver@example.test");
    expect((await lease(device)).status).toBe(200);

    const id = String(json(created)["id"]);
    const patched = await scim(`/Users/${id}`, {
      method: "PATCH",
      body: {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [{ op: "Replace", path: "active", value: "False" }],
      },
    });
    expect(json(patched)["active"]).toBe(false);
    expect(json(await lease(device))["error"]).toBe("device_revoked");
  });

  it("stores device audit events once, with ids as long as T3's event ids", async () => {
    const device = await enroll("audited@example.test");
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
            { id, type: "thread.created", occurredAt: "2026-11-20T12:00:00.000Z", threadId: "t1" },
          ],
        }),
      });
    expect(json(await send())).toMatchObject({ accepted: 1, rejected: 0 });
    await send();
    const events = json(await admin("/audit?limit=1000"))["events"] as Array<
      Record<string, unknown>
    >;
    expect(events.filter((event) => event["id"] === id)).toHaveLength(1);
  });

  it("records enrollments and revocations in the audit trail", async () => {
    const events = json(await admin("/audit?limit=1000"))["events"] as Array<
      Record<string, unknown>
    >;
    const types = new Set(events.map((event) => event["type"]));
    expect(types).toContain("device.enrolled");
    expect(types).toContain("device.revoked");
    expect(types).toContain("user.deactivated");
  });
});
