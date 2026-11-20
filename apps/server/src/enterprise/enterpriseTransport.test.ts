// @effect-diagnostics nodeBuiltinImport:off
import * as NodeHttp from "node:http";
import * as NodeHttps from "node:https";
import type * as NodeTls from "node:tls";

import {
  createAuthorityPem,
  issueDeviceCertificatePem,
  issueServerCertificatePem,
  parseAuthority,
} from "@t3tools/enterprise-control-plane/CertificateAuthority";
import { describe, expect, it } from "vite-plus/test";

import {
  generateDeviceKey,
  startLocalProxy,
  type ProxyCredentials,
} from "./enterpriseTransport.ts";

// TLS needs certificates valid now; a fixed epoch with a long life keeps the clock out of tests.
const CERT_EPOCH = Date.UTC(2026, 0, 1);
const CERT_DAYS = 365 * 20;

const authority = () => {
  const created = createAuthorityPem("Example Corp", { nowMillis: CERT_EPOCH, years: 20 });
  return parseAuthority(created.certPem, created.keyPem);
};

interface Seen {
  headers: NodeHttp.IncomingHttpHeaders;
  path: string;
  clientCertificateSubject: string | undefined;
}

async function setup(credentials: () => ProxyCredentials) {
  const ca = authority();
  const tls = issueServerCertificatePem(ca, {
    hostnames: ["localhost", "127.0.0.1"],
    days: CERT_DAYS,
    nowMillis: CERT_EPOCH,
  });
  const seen: Array<Seen> = [];
  const gateway = NodeHttps.createServer(
    {
      cert: tls.certPem,
      key: tls.keyPem,
      ca: ca.certPem,
      requestCert: true,
      rejectUnauthorized: true,
    },
    (request, response) => {
      const peer = (request.socket as NodeTls.TLSSocket).getPeerCertificate();
      seen.push({
        headers: request.headers,
        path: request.url ?? "",
        clientCertificateSubject: [peer.subject?.CN].flat()[0],
      });
      response.writeHead(200, { "content-type": "application/json" });
      response.end('{"ok":true}');
    },
  );
  await new Promise<void>((resolve) => gateway.listen(0, "127.0.0.1", resolve));
  const address = gateway.address();
  if (address === null || typeof address === "string") throw new Error("no gateway port");
  const proxy = await startLocalProxy({
    token: "local-token",
    gatewayUrl: `https://localhost:${address.port}`,
    serverCaPem: ca.certPem,
    credentials,
  });
  const call = (path: string, headers: Record<string, string>) =>
    new Promise<{ status: number; body: string }>((resolve, reject) => {
      const request = NodeHttp.request(
        { host: "127.0.0.1", port: proxy.port, path, method: "POST", headers },
        (response) => {
          let body = "";
          response.on("data", (chunk: Buffer) => (body += chunk.toString("utf8")));
          response.on("end", () => resolve({ status: response.statusCode ?? 0, body }));
        },
      );
      request.on("error", reject);
      request.end('{"model":"claude-haiku-5-5"}');
    });
  return {
    ca,
    seen,
    call,
    [Symbol.asyncDispose]: async () => {
      await proxy.close();
      await new Promise<void>((resolve) => {
        gateway.close(() => resolve());
        gateway.closeAllConnections();
      });
    },
  };
}

describe("startLocalProxy", () => {
  it("forwards with the device certificate and lease, never the local token", async () => {
    const key = generateDeviceKey();
    let ca: ReturnType<typeof authority> | undefined;
    await using harness = await setup(() => {
      const certificate = issueDeviceCertificatePem(ca!, {
        publicKeyPem: key.publicKeyPem,
        deviceId: "device-1",
        userId: "user-1",
        days: CERT_DAYS,
        nowMillis: CERT_EPOCH,
      });
      if (typeof certificate === "string") throw new Error(certificate);
      return {
        ok: true,
        lease: "lease-token",
        keyPem: key.keyPem,
        certificatePem: certificate.certPem,
      };
    });
    ca = harness.ca;

    const reply = await harness.call("/anthropic/v1/messages", { "x-api-key": "local-token" });
    expect(reply.status).toBe(200);
    const seen = harness.seen.at(-1)!;
    expect(seen.path).toBe("/anthropic/v1/messages");
    expect(seen.headers["x-api-key"]).toBe("lease-token");
    expect(seen.clientCertificateSubject).toBe("device-1");

    const openai = await harness.call("/openai/v1/responses", {
      authorization: "Bearer local-token",
    });
    expect(openai.status).toBe(200);
    expect(harness.seen.at(-1)!.headers.authorization).toBe("Bearer lease-token");
  });

  it("refuses callers without the local token", async () => {
    await using harness = await setup(() => ({ ok: false, status: 401, message: "unused" }));
    const reply = await harness.call("/anthropic/v1/messages", { "x-api-key": "guess" });
    expect(reply.status).toBe(401);
    expect(harness.seen).toHaveLength(0);
  });

  it("answers in the provider's error shape when the device has no lease", async () => {
    await using harness = await setup(() => ({
      ok: false,
      status: 401,
      message: "This computer is not enrolled. Run `t3 enterprise enroll`.",
    }));
    const reply = await harness.call("/anthropic/v1/messages", { "x-api-key": "local-token" });
    expect(reply.status).toBe(401);
    expect(JSON.parse(reply.body)).toEqual({
      type: "error",
      error: {
        type: "authentication_error",
        message: "This computer is not enrolled. Run `t3 enterprise enroll`.",
      },
    });
    expect(harness.seen).toHaveLength(0);
  });
});
