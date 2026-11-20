/**
 * Gateway - the only holder of the organization's provider keys. It forwards a request only for
 * a device whose certificate the org CA signed (checked at the TLS handshake) and that presents
 * an unexpired lease bound to that certificate, and it meters what each request spent.
 *
 * @module Gateway
 */
import { certificateThumbprint } from "@t3tools/enterprise-protocol/thumbprint";
import { modelAllowed, verifyLease, type LeaseClaims } from "@t3tools/enterprise-protocol/tokens";
import { UsageCounter } from "@t3tools/enterprise-protocol/usage";
import {
  GatewayState,
  paths,
  UsageResult,
  type UsageRecord,
} from "@t3tools/enterprise-protocol/wire";
import * as NodeHttpServerRequest from "@effect/platform-node/NodeHttpServerRequest";
import * as ByteSize from "effect/ByteSize";
import * as Clock from "effect/Clock";
import * as Context from "effect/Context";
import * as DateTime from "effect/DateTime";
import * as SecureRandom from "effect/crypto/SecureRandom";
import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";
import * as Stream from "effect/Stream";
import {
  HttpClient,
  HttpClientRequest,
  HttpClientResponse,
  HttpServerRequest,
  HttpServerResponse,
} from "effect/http";
import * as HttpIncomingMessage from "effect/http/HttpIncomingMessage";
import type * as NodeTls from "node:tls";

import { GatewayConfig, type ProviderFamily, type Upstream } from "./Config.ts";
import { findingCount, redact } from "./Redaction.ts";

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
  "accept-encoding",
  "content-encoding",
]);

type RefusalKind =
  | "authentication"
  | "permission"
  | "rate_limit"
  | "invalid_request"
  | "unavailable";

export class Refusal extends Schema.TaggedError<Refusal>()("Refusal", {
  status: Schema.Number,
  kind: Schema.Literals([
    "authentication",
    "permission",
    "rate_limit",
    "invalid_request",
    "unavailable",
  ]),
  reason: Schema.String,
}) {
  override get message(): string {
    return this.reason;
  }
}

const refuse = (status: number, kind: RefusalKind, reason: string) =>
  new Refusal({ status, kind, reason });

/** Errors in the shape each provider's CLI already knows how to show. */
export function refusalBody(family: ProviderFamily, refusal: Refusal) {
  if (family === "anthropic") {
    const type = {
      authentication: "authentication_error",
      permission: "permission_error",
      rate_limit: "rate_limit_error",
      invalid_request: "invalid_request_error",
      unavailable: "overloaded_error",
    }[refusal.kind];
    return { type: "error", error: { type, message: refusal.reason } };
  }
  return { error: { message: refusal.reason, type: refusal.kind, code: refusal.kind } };
}

export class ControlPlaneUnavailable extends Schema.TaggedError<ControlPlaneUnavailable>()(
  "ControlPlaneUnavailable",
  { reason: Schema.String },
) {
  override get message(): string {
    return this.reason;
  }
}

const Jwks = Schema.Struct({ keys: Schema.Array(Schema.Record(Schema.String, Schema.Unknown)) });

const decoder = new TextDecoder();
const encoder = new TextEncoder();

function modelOf(body: string): string | undefined {
  if (body.length === 0) return undefined;
  try {
    const parsed = JSON.parse(body) as { model?: unknown };
    return typeof parsed.model === "string" ? parsed.model : undefined;
  } catch {
    return undefined;
  }
}

/** The verified client certificate's DER; the TLS layer already refused anyone else. */
const peerCertificate = (request: HttpServerRequest.HttpServerRequest) => {
  const socket = NodeHttpServerRequest.toIncomingMessage(request).socket as NodeTls.TLSSocket;
  const peer = socket.authorized ? socket.getPeerCertificate() : undefined;
  return peer?.raw === undefined || peer.raw.length === 0 ? undefined : peer.raw;
};

export class Gateway extends Context.Service<
  Gateway,
  {
    /** Pulls signing keys and revocations, and pushes metered usage. Failures keep the last state. */
    readonly sync: Effect.Effect<void, ControlPlaneUnavailable>;
    readonly handle: Effect.Effect<
      HttpServerResponse.HttpServerResponse,
      never,
      HttpServerRequest.HttpServerRequest
    >;
    readonly pendingUsage: Effect.Effect<ReadonlyArray<UsageRecord>>;
  }
>()("@t3tools/enterprise-gateway/Gateway") {}

export const make = Effect.fn("Gateway.make")(function* (
  controlPlaneClient: HttpClient.HttpClient,
) {
  const config = yield* GatewayConfig;
  const upstreamClient = yield* HttpClient.HttpClient;
  const random = yield* SecureRandom.SecureRandom;

  let jwks: { readonly keys: ReadonlyArray<object> } | undefined;
  let state: GatewayState | undefined;
  let stateAt = 0;
  let usage: Array<UsageRecord> = [];
  const windows = new Map<string, { start: number; count: number }>();

  const controlPlane = controlPlaneClient.pipe(
    HttpClient.mapRequest(
      HttpClientRequest.setHeader("authorization", `Bearer ${config.gatewayToken}`),
    ),
    HttpClient.filterStatusOk,
  );
  const unavailable = (reason: string) => () => new ControlPlaneUnavailable({ reason });

  const sync = Effect.gen(function* () {
    jwks = yield* controlPlane
      .get(`${config.controlPlaneUrl}${paths.jwks}`)
      .pipe(
        Effect.flatMap(HttpClientResponse.schemaBodyJson(Jwks)),
        Effect.mapError(unavailable("cannot read the control plane's signing keys")),
      );
    const records = usage;
    usage = [];
    const next =
      records.length === 0
        ? yield* controlPlane
            .get(`${config.controlPlaneUrl}${paths.gatewayState}`)
            .pipe(
              Effect.flatMap(HttpClientResponse.schemaBodyJson(GatewayState)),
              Effect.mapError(unavailable("control plane refused state")),
            )
        : yield* HttpClientRequest.post(`${config.controlPlaneUrl}${paths.gatewayUsage}`).pipe(
            HttpClientRequest.bodyJsonUnsafe({ records }),
            controlPlane.execute,
            Effect.flatMap(HttpClientResponse.schemaBodyJson(UsageResult)),
            Effect.map((result) => result.state),
            Effect.mapError(unavailable("control plane refused usage")),
            // Usage that did not land is sent again with the next sync.
            Effect.tapError(() =>
              Effect.sync(() => {
                usage = [...records, ...usage];
              }),
            ),
          );
    state = next;
    stateAt = yield* Clock.currentTimeMillis;
  }).pipe(Effect.withSpan("Gateway.sync"));

  const rateLimit = Effect.fn("Gateway.rateLimit")(function* (userId: string) {
    const limit = config.requestsPerMinute;
    if (limit === undefined) return;
    const now = yield* Clock.currentTimeMillis;
    const window = windows.get(userId);
    if (window === undefined || now - window.start >= 60_000) {
      windows.set(userId, { start: now, count: 1 });
      return;
    }
    window.count += 1;
    if (window.count > limit) {
      return yield* refuse(429, "rate_limit", `more than ${limit} requests a minute`);
    }
  });

  const authorize = Effect.fn("Gateway.authorize")(function* (
    request: HttpServerRequest.HttpServerRequest,
  ) {
    const certificate = peerCertificate(request);
    if (certificate === undefined) {
      return yield* refuse(
        401,
        "authentication",
        "this gateway needs an enrolled device certificate",
      );
    }
    const header = request.headers["x-api-key"] ?? request.headers["authorization"];
    const token = header?.replace(/^bearer\s+/i, "").trim();
    if (token === undefined || token.length === 0) {
      return yield* refuse(401, "authentication", "no lease presented");
    }
    if (jwks === undefined || state === undefined) {
      return yield* refuse(503, "unavailable", "gateway has not reached the control plane yet");
    }
    if ((yield* Clock.currentTimeMillis) - stateAt > config.maxStateAgeSeconds * 1000) {
      return yield* refuse(
        503,
        "unavailable",
        "gateway cannot reach the control plane; requests are paused",
      );
    }
    const lease = yield* verifyLease(token, jwks, {
      issuer: config.controlPlaneUrl,
      thumbprint: certificateThumbprint(certificate),
    }).pipe(
      Effect.mapError((error) => refuse(401, "authentication", `lease rejected: ${error.message}`)),
    );
    if (state.revokedDevices.includes(lease.deviceId)) {
      return yield* refuse(403, "permission", "this device was revoked");
    }
    if (state.inactiveUsers.includes(lease.userId)) {
      return yield* refuse(403, "permission", "this account is deactivated");
    }
    if (state.overBudgetUsers.includes(lease.userId)) {
      return yield* refuse(
        429,
        "rate_limit",
        "this month's model budget is used up; ask your admin to raise it",
      );
    }
    yield* rateLimit(lease.userId);
    return lease;
  });

  /** The upstream for this path in the lease's data region; no region match is a refusal. */
  const route = (pathname: string, lease: LeaseClaims | undefined) => {
    const candidates = config.upstreams.filter(
      (upstream) => pathname === upstream.prefix || pathname.startsWith(`${upstream.prefix}/`),
    );
    const first = candidates[0];
    if (first === undefined) return undefined;
    const region = lease?.region;
    const upstream: Upstream | undefined =
      region === undefined
        ? (candidates.find((candidate) => candidate.region === undefined) ?? first)
        : candidates.find((candidate) => candidate.region === region);
    return { family: first.family, upstream, rest: pathname.slice(first.prefix.length) || "/" };
  };

  const record = Effect.fn("Gateway.record")(function* (input: {
    lease: LeaseClaims;
    upstream: Upstream;
    model: string;
    status: number;
    counter: UsageCounter;
    redactions: number;
  }) {
    const counted = input.counter.finish();
    usage.push({
      id: yield* random.uuidV4(),
      userId: input.lease.userId,
      deviceId: input.lease.deviceId,
      provider: input.upstream.family,
      model: input.model,
      inputTokens: counted.inputTokens,
      outputTokens: counted.outputTokens,
      status: input.status,
      occurredAt: DateTime.formatIso(yield* DateTime.now),
      redactions: input.redactions,
      ...(input.upstream.region === undefined ? {} : { region: input.upstream.region }),
    });
  });

  const forward = Effect.fn("Gateway.forward")(function* (
    request: HttpServerRequest.HttpServerRequest,
    lease: LeaseClaims,
    upstream: Upstream,
    path: string,
  ) {
    const raw = yield* request.arrayBuffer.pipe(
      Effect.provideService(
        HttpIncomingMessage.MaxBodySize,
        ByteSize.bytes(config.maxRequestBytes),
      ),
      Effect.mapError(() => refuse(413, "invalid_request", "request body is too large")),
    );
    let body = decoder.decode(raw);
    const model = modelOf(body);
    if (model !== undefined && !modelAllowed(lease.models, model)) {
      return yield* refuse(403, "permission", `your organization does not allow model ${model}`);
    }
    let redactions = 0;
    if (config.redaction.mode !== "off") {
      const result = redact(body, config.redaction.detectors);
      redactions = findingCount(result.findings);
      if (redactions > 0 && config.redaction.mode === "block") {
        return yield* refuse(
          400,
          "invalid_request",
          `this request contains credentials (${Object.keys(result.findings).join(", ")}); your organization does not send them to model providers`,
        );
      }
      body = result.text;
    }

    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(request.headers)) {
      if (!HOP_BY_HOP.has(name)) headers[name] = value;
    }
    if (upstream.family === "anthropic") headers["x-api-key"] = upstream.apiKey;
    else headers["authorization"] = `Bearer ${upstream.apiKey}`;
    // Uncompressed responses keep token metering exact.
    headers["accept-encoding"] = "identity";

    const response = yield* HttpClientRequest.make(request.method as "POST")(
      `${upstream.baseUrl}${path}`,
    ).pipe(
      HttpClientRequest.setHeaders(headers),
      HttpClientRequest.bodyUint8Array(
        encoder.encode(body),
        headers["content-type"] ?? "application/json",
      ),
      upstreamClient.execute,
      Effect.mapError(() => refuse(502, "unavailable", "upstream request failed")),
    );

    const responseHeaders: Record<string, string> = {};
    for (const [name, value] of Object.entries(response.headers)) {
      if (!HOP_BY_HOP.has(name) && name !== "set-cookie") responseHeaders[name] = value;
    }
    const counter = new UsageCounter();
    const metered = {
      lease,
      upstream,
      model: model ?? "unknown",
      status: response.status,
      counter,
      redactions,
    };
    // A stream cut short still spent the tokens it reported, so an interrupted stream records too.
    const stream = response.stream.pipe(
      Stream.tap((chunk) =>
        Effect.sync(() => counter.push(decoder.decode(chunk, { stream: true }))),
      ),
      Stream.ensuring(record(metered)),
    );
    return HttpServerResponse.stream(stream, {
      status: response.status,
      headers: responseHeaders,
    });
  });

  const handle = Effect.gen(function* () {
    const request = yield* HttpServerRequest.HttpServerRequest;
    const url = new URL(request.originalUrl, "https://gateway.invalid");
    if (url.pathname === paths.health) {
      return HttpServerResponse.jsonUnsafe({ ok: true, synced: state !== undefined });
    }
    const found = route(url.pathname, undefined);
    if (found === undefined) {
      return HttpServerResponse.jsonUnsafe({ error: "no upstream for this path" }, { status: 404 });
    }
    return yield* Effect.gen(function* () {
      const lease = yield* authorize(request);
      const { upstream, rest } = route(url.pathname, lease) ?? found;
      if (upstream === undefined) {
        return yield* refuse(
          403,
          "permission",
          `no ${found.family} upstream serves your data region (${lease.region ?? "none"})`,
        );
      }
      return yield* forward(request, lease, upstream, `${rest}${url.search}`);
    }).pipe(
      Effect.catchTags({
        Refusal: (refusal) =>
          Effect.succeed(
            HttpServerResponse.jsonUnsafe(refusalBody(found.family, refusal), {
              status: refusal.status,
            }),
          ),
      }),
      Effect.catchCause((cause) =>
        Effect.logError("Gateway request failed", { cause }).pipe(
          Effect.as(
            HttpServerResponse.jsonUnsafe(
              refusalBody(found.family, refuse(502, "unavailable", "upstream request failed")),
              { status: 502 },
            ),
          ),
        ),
      ),
    );
  }).pipe(Effect.withSpan("Gateway.handle"));

  return Gateway.of({ sync, handle, pendingUsage: Effect.sync(() => usage) });
});
