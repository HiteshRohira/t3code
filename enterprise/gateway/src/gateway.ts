import * as NodeCrypto from "node:crypto";
import * as NodeFS from "node:fs";
import * as NodeHttp from "node:http";
import * as NodeHttps from "node:https";
import type * as NodeTls from "node:tls";

import type { JSONWebKeySet } from "jose";

import { certificateThumbprint } from "@t3tools/enterprise-protocol/thumbprint";
import {
  modelAllowed,
  TokenRejected,
  verifyLease,
  type LeaseClaims,
} from "@t3tools/enterprise-protocol/tokens";
import { UsageCounter } from "@t3tools/enterprise-protocol/usage";
import { paths, type GatewayState, type UsageRecord } from "@t3tools/enterprise-protocol/wire";

import type { GatewayConfig, ProviderFamily, Upstream } from "./config.ts";

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
  "authorization",
  "x-api-key",
  "cookie",
]);

class Refusal extends Error {
  override readonly name = "Refusal";
  readonly status: number;
  readonly kind: "authentication" | "permission" | "rate_limit" | "invalid_request" | "unavailable";
  constructor(status: number, kind: Refusal["kind"], message: string) {
    super(message);
    this.status = status;
    this.kind = kind;
  }
}

/** Errors in the shape each provider's CLI already knows how to show. */
function refusalBody(family: ProviderFamily, refusal: Refusal) {
  if (family === "anthropic") {
    const type = {
      authentication: "authentication_error",
      permission: "permission_error",
      rate_limit: "rate_limit_error",
      invalid_request: "invalid_request_error",
      unavailable: "overloaded_error",
    }[refusal.kind];
    return { type: "error", error: { type, message: refusal.message } };
  }
  return { error: { message: refusal.message, type: refusal.kind, code: refusal.kind } };
}

interface JsonResponse {
  readonly status: number;
  readonly body: unknown;
}

/** JSON over HTTPS with an optional private CA, which `fetch` cannot take without undici. */
export function requestJson(
  url: string,
  options: { method?: string; headers?: Record<string, string>; body?: unknown; ca?: string },
): Promise<JsonResponse> {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const body = options.body === undefined ? undefined : JSON.stringify(options.body);
    const send = target.protocol === "https:" ? NodeHttps.request : NodeHttp.request;
    const request = send(
      target,
      {
        method: options.method ?? "GET",
        headers: {
          accept: "application/json",
          ...(body === undefined
            ? {}
            : { "content-type": "application/json", "content-length": Buffer.byteLength(body) }),
          ...options.headers,
        },
        ...(options.ca === undefined ? {} : { ca: options.ca }),
        timeout: 15_000,
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          try {
            resolve({
              status: response.statusCode ?? 0,
              body: text.length === 0 ? null : (JSON.parse(text) as unknown),
            });
          } catch {
            reject(new Error(`${url} answered with non-JSON (${response.statusCode})`));
          }
        });
        response.on("error", reject);
      },
    );
    request.on("timeout", () => request.destroy(new Error(`${url} timed out`)));
    request.on("error", reject);
    request.end(body);
  });
}

export interface GatewayOptions {
  readonly now?: () => number;
}

export class Gateway {
  readonly #config: GatewayConfig;
  readonly #controlPlaneCa: string | undefined;
  readonly #now: () => number;
  #jwks: JSONWebKeySet | undefined;
  #state: GatewayState | undefined;
  #stateAt = 0;
  #usage: UsageRecord[] = [];
  readonly #windows = new Map<string, { start: number; count: number }>();
  #timer: NodeJS.Timeout | undefined;

  constructor(config: GatewayConfig, options: GatewayOptions = {}) {
    this.#config = config;
    this.#controlPlaneCa =
      config.controlPlaneCaPath === undefined
        ? undefined
        : NodeFS.readFileSync(config.controlPlaneCaPath, "utf8");
    this.#now = options.now ?? Date.now;
  }

  #controlPlane(path: string, options: { method?: string; body?: unknown } = {}) {
    return requestJson(`${this.#config.controlPlaneUrl}${path}`, {
      ...options,
      headers: { authorization: `Bearer ${this.#config.gatewayToken}` },
      ...(this.#controlPlaneCa === undefined ? {} : { ca: this.#controlPlaneCa }),
    });
  }

  /** Pulls signing keys and revocations, and pushes metered usage. Failures keep the last state. */
  async sync(): Promise<void> {
    const jwks = await this.#controlPlane(paths.jwks);
    if (jwks.status === 200) this.#jwks = jwks.body as JSONWebKeySet;
    const records = this.#usage;
    this.#usage = [];
    if (records.length > 0) {
      const pushed = await this.#controlPlane(paths.gatewayUsage, {
        method: "POST",
        body: { records },
      }).catch((error: unknown) => {
        this.#usage = [...records, ...this.#usage];
        throw error;
      });
      if (pushed.status !== 200) {
        this.#usage = [...records, ...this.#usage];
        throw new Error(`control plane refused usage (${pushed.status})`);
      }
      this.#acceptState((pushed.body as { state: GatewayState }).state);
      return;
    }
    const state = await this.#controlPlane(paths.gatewayState);
    if (state.status !== 200) throw new Error(`control plane refused state (${state.status})`);
    this.#acceptState(state.body as GatewayState);
  }

  #acceptState(state: GatewayState) {
    this.#state = state;
    this.#stateAt = this.#now();
  }

  startSync() {
    const tick = () =>
      this.sync().catch((error: unknown) =>
        console.warn(
          "[gateway] control plane sync failed",
          error instanceof Error ? error.message : error,
        ),
      );
    void tick();
    this.#timer = setInterval(tick, this.#config.syncIntervalSeconds * 1000);
    this.#timer.unref();
  }

  stopSync() {
    if (this.#timer !== undefined) clearInterval(this.#timer);
  }

  pendingUsage(): ReadonlyArray<UsageRecord> {
    return this.#usage;
  }

  #upstreamFor(pathname: string): { upstream: Upstream; rest: string } | undefined {
    for (const upstream of this.#config.upstreams) {
      if (pathname === upstream.prefix || pathname.startsWith(`${upstream.prefix}/`)) {
        return { upstream, rest: pathname.slice(upstream.prefix.length) || "/" };
      }
    }
    return undefined;
  }

  async #authorize(request: NodeHttp.IncomingMessage): Promise<LeaseClaims> {
    const socket = request.socket as NodeTls.TLSSocket;
    const peer = socket.authorized ? socket.getPeerCertificate() : undefined;
    if (peer?.raw === undefined)
      throw new Refusal(401, "authentication", "this gateway needs an enrolled device certificate");
    const header = request.headers["x-api-key"] ?? request.headers.authorization;
    const raw = Array.isArray(header) ? header[0] : header;
    const token = raw?.replace(/^bearer\s+/i, "").trim();
    if (token === undefined || token.length === 0)
      throw new Refusal(401, "authentication", "no lease presented");
    if (this.#jwks === undefined || this.#state === undefined) {
      throw new Refusal(503, "unavailable", "gateway has not reached the control plane yet");
    }
    if (this.#now() - this.#stateAt > this.#config.maxStateAgeSeconds * 1000) {
      throw new Refusal(
        503,
        "unavailable",
        "gateway cannot reach the control plane; requests are paused",
      );
    }
    let lease: LeaseClaims;
    try {
      lease = await verifyLease(token, this.#jwks, {
        issuer: this.#config.controlPlaneUrl,
        thumbprint: certificateThumbprint(peer.raw),
        now: new Date(this.#now()),
      });
    } catch (error) {
      if (error instanceof TokenRejected)
        throw new Refusal(401, "authentication", `lease rejected: ${error.message}`);
      throw error;
    }
    if (this.#state.revokedDevices.includes(lease.deviceId))
      throw new Refusal(403, "permission", "this device was revoked");
    if (this.#state.inactiveUsers.includes(lease.userId))
      throw new Refusal(403, "permission", "this account is deactivated");
    if (this.#state.overBudgetUsers.includes(lease.userId)) {
      throw new Refusal(
        429,
        "rate_limit",
        "this month's model budget is used up; ask your admin to raise it",
      );
    }
    this.#rateLimit(lease.userId);
    return lease;
  }

  #rateLimit(userId: string) {
    const limit = this.#config.requestsPerMinute;
    if (limit === undefined) return;
    const now = this.#now();
    const window = this.#windows.get(userId);
    if (window === undefined || now - window.start >= 60_000) {
      this.#windows.set(userId, { start: now, count: 1 });
      return;
    }
    window.count += 1;
    if (window.count > limit)
      throw new Refusal(429, "rate_limit", `more than ${limit} requests a minute`);
  }

  async #readBody(request: NodeHttp.IncomingMessage): Promise<Buffer> {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of request) {
      size += (chunk as Buffer).length;
      if (size > this.#config.maxRequestBytes)
        throw new Refusal(413, "invalid_request", "request body is too large");
      chunks.push(chunk as Buffer);
    }
    return Buffer.concat(chunks);
  }

  readonly handle = async (
    request: NodeHttp.IncomingMessage,
    response: NodeHttp.ServerResponse,
  ) => {
    const url = new URL(request.url ?? "/", "https://gateway.invalid");
    if (url.pathname === paths.health) {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: true, synced: this.#state !== undefined }));
      return;
    }
    const route = this.#upstreamFor(url.pathname);
    if (route === undefined) {
      response.writeHead(404, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: "no upstream for this path" }));
      return;
    }
    const { upstream, rest } = route;
    try {
      const lease = await this.#authorize(request);
      const body = await this.#readBody(request);
      const model = modelOf(body);
      if (model !== undefined && !modelAllowed(lease.models, model)) {
        throw new Refusal(403, "permission", `your organization does not allow model ${model}`);
      }
      await this.#forward(request, response, {
        upstream,
        path: `${rest}${url.search}`,
        body,
        lease,
        model: model ?? "unknown",
      });
    } catch (error) {
      if (error instanceof Refusal) {
        if (!response.headersSent) {
          response.writeHead(error.status, { "content-type": "application/json" });
          response.end(JSON.stringify(refusalBody(upstream.family, error)));
        }
        return;
      }
      console.error("[gateway] request failed", error);
      if (!response.headersSent) {
        response.writeHead(502, { "content-type": "application/json" });
        response.end(
          JSON.stringify(
            refusalBody(
              upstream.family,
              new Refusal(502, "unavailable", "upstream request failed"),
            ),
          ),
        );
      } else {
        response.destroy();
      }
    }
  };

  #forward(
    request: NodeHttp.IncomingMessage,
    response: NodeHttp.ServerResponse,
    input: { upstream: Upstream; path: string; body: Buffer; lease: LeaseClaims; model: string },
  ): Promise<void> {
    const { upstream, lease } = input;
    const target = new URL(`${upstream.baseUrl}${input.path}`);
    const headers: Record<string, string | string[]> = {};
    for (const [name, value] of Object.entries(request.headers as NodeHttp.IncomingHttpHeaders)) {
      if (value !== undefined && !HOP_BY_HOP.has(name)) headers[name] = value;
    }
    if (upstream.family === "anthropic") headers["x-api-key"] = upstream.apiKey;
    else headers["authorization"] = `Bearer ${upstream.apiKey}`;
    headers["content-length"] = String(input.body.length);

    const send = target.protocol === "https:" ? NodeHttps.request : NodeHttp.request;
    return new Promise((resolve, reject) => {
      const outbound = send(
        target,
        { method: request.method ?? "POST", headers },
        (upstreamResponse) => {
          const responseHeaders: Record<string, string | string[]> = {};
          for (const [name, value] of Object.entries(upstreamResponse.headers)) {
            if (value !== undefined && !HOP_BY_HOP.has(name) && name !== "set-cookie")
              responseHeaders[name] = value;
          }
          response.writeHead(upstreamResponse.statusCode ?? 502, responseHeaders);
          const counter = new UsageCounter();
          upstreamResponse.on("data", (chunk: Buffer) => {
            counter.push(chunk.toString("utf8"));
            response.write(chunk);
          });
          let recorded = false;
          // A stream cut short still spent the tokens it reported, so close records usage too.
          const record = () => {
            if (recorded) return;
            recorded = true;
            const usage = counter.finish();
            this.#usage.push({
              id: NodeCrypto.randomUUID(),
              userId: lease.userId,
              deviceId: lease.deviceId,
              provider: upstream.family,
              model: input.model,
              inputTokens: usage.inputTokens,
              outputTokens: usage.outputTokens,
              status: upstreamResponse.statusCode ?? 0,
              occurredAt: new Date(this.#now()).toISOString(),
            });
            resolve();
          };
          upstreamResponse.on("end", () => {
            response.end();
            record();
          });
          upstreamResponse.on("close", record);
          upstreamResponse.on("error", () => record());
        },
      );
      // A client that hangs up stops the upstream request, so a cancelled turn stops spending.
      response.on("close", () => {
        if (!response.writableFinished) outbound.destroy();
      });
      outbound.on("error", reject);
      outbound.end(input.body);
    });
  }
}

function modelOf(body: Buffer): string | undefined {
  if (body.length === 0) return undefined;
  try {
    const parsed = JSON.parse(body.toString("utf8")) as { model?: unknown };
    return typeof parsed.model === "string" ? parsed.model : undefined;
  } catch {
    return undefined;
  }
}

/** Only devices holding a certificate from the org CA complete the TLS handshake. */
export async function startGateway(config: GatewayConfig, options: GatewayOptions = {}) {
  const gateway = new Gateway(config, options);
  const server: NodeHttps.Server = NodeHttps.createServer(
    {
      cert: NodeFS.readFileSync(config.tls.certPath),
      key: NodeFS.readFileSync(config.tls.keyPath),
      ca: NodeFS.readFileSync(config.deviceCaPath),
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: "TLSv1.2",
    },
    gateway.handle,
  );
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.listen.port, config.listen.host, () => resolve());
  });
  return {
    gateway,
    server,
    close: async () => {
      gateway.stopSync();
      await gateway.sync().catch(() => undefined);
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      });
    },
  };
}
