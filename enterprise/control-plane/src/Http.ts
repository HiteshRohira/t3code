/**
 * Http - response helpers and request accessors shared by the control plane's routes.
 *
 * @module Http
 */
import * as NodeHttpServerRequest from "@effect/platform-node/NodeHttpServerRequest";
import { ErrorResponse } from "@t3tools/enterprise-protocol/wire";
import * as ByteSize from "effect/ByteSize";
import * as Cause from "effect/Cause";
import * as Effect from "effect/Effect";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import { HttpServerRequest, HttpServerResponse } from "effect/http";
import * as UrlParams from "effect/http/UrlParams";
import * as HttpIncomingMessage from "effect/http/HttpIncomingMessage";
import type * as NodeTls from "node:tls";

import { Refusal } from "./ControlPlane.ts";

const NO_STORE = { "cache-control": "no-store" };
const SECURITY_HEADERS = {
  ...NO_STORE,
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
};
// form-action also governs the redirect after a POST, which can go to a device's loopback listener.
const PAGE_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; form-action 'self' https: http://127.0.0.1:* http://localhost:* http://[::1]:*; frame-ancestors 'none'; base-uri 'none'";

export const json = (body: unknown, status = 200, contentType = "application/json") =>
  HttpServerResponse.jsonUnsafe(body, {
    status,
    headers: NO_STORE,
    contentType: `${contentType}; charset=utf-8`,
  });

export const refusalResponse = (refusal: Refusal) =>
  json({ error: refusal.code, message: refusal.reason } satisfies ErrorResponse, refusal.status);

export const html = (body: string, status = 200) =>
  HttpServerResponse.text(body, {
    status,
    contentType: "text/html; charset=utf-8",
    headers: { ...SECURITY_HEADERS, "content-security-policy": PAGE_CSP },
  });

export const asset = (body: string, contentType: string) =>
  HttpServerResponse.text(body, { contentType, headers: SECURITY_HEADERS });

export const redirect = (location: string, headers: Record<string, string> = {}) =>
  HttpServerResponse.redirect(location, { status: 302, headers: { ...NO_STORE, ...headers } });

export const escapeHtml = (value: string) =>
  value.replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);

export const page = (title: string, body: string) =>
  `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title><link rel="stylesheet" href="/admin/assets/admin.css"></head>
<body><main class="narrow"><h1>${escapeHtml(title)}</h1>${body}</main></body></html>`;

export const messagePage = (title: string, message: string, status: number) =>
  html(page(title, `<p>${escapeHtml(message)}</p>`), status);

export const bearer = (request: HttpServerRequest.HttpServerRequest): string | undefined => {
  const header = request.headers["authorization"];
  if (header === undefined || !header.toLowerCase().startsWith("bearer ")) return undefined;
  return header.slice(7).trim();
};

export const searchParams = (request: HttpServerRequest.HttpServerRequest) =>
  new URL(request.originalUrl, "http://control-plane.invalid").searchParams;

/** The verified client certificate's DER, or undefined when the peer presented none the CA signed. */
export const clientCertificate = (
  request: HttpServerRequest.HttpServerRequest,
): Uint8Array | undefined => {
  const socket = NodeHttpServerRequest.toIncomingMessage(request).socket as NodeTls.TLSSocket;
  if (typeof socket.getPeerCertificate !== "function" || !socket.authorized) return undefined;
  const peer = socket.getPeerCertificate();
  return peer.raw === undefined || peer.raw.length === 0 ? undefined : peer.raw;
};

const isRefusal = Schema.is(Refusal);

const invalid = (reason: string) => new Refusal({ status: 400, code: "invalid_request", reason });

/** Decodes a JSON body, refusing bodies over `limitBytes` and ones the schema rejects. */
export const readJson = <A, I, RD>(schema: Schema.Codec<A, I, RD>, limitBytes = 1024 * 1024) =>
  HttpServerRequest.schemaBodyJson(schema).pipe(
    Effect.provideService(HttpIncomingMessage.MaxBodySize, ByteSize.bytes(limitBytes)),
    Effect.catchTags({
      SchemaError: (error) => Effect.fail(invalid(error.message.replace(/\s*\n\s*/g, " "))),
      HttpServerError: (error) =>
        Effect.fail(
          error.reason._tag === "RequestParseError" && String(error.reason).includes("BodyTooLarge")
            ? new Refusal({ status: 413, code: "too_large", reason: "request body is too large" })
            : invalid("request body is not JSON"),
        ),
    }),
  );

export const readForm = Effect.gen(function* () {
  const request = yield* HttpServerRequest.HttpServerRequest;
  const params = yield* request.urlParamsBody.pipe(
    Effect.provideService(HttpIncomingMessage.MaxBodySize, ByteSize.kilobytes(512)),
    Effect.mapError(() => invalid("request body is not a form")),
  );
  return new URLSearchParams(UrlParams.toString(params));
});

/**
 * Turns a refusal into its JSON response and logs anything else as a 500, so a database or
 * signing failure never leaks its message to the caller.
 */
export const respond = <E, R>(
  handler: Effect.Effect<HttpServerResponse.HttpServerResponse, E, R>,
  options?: { readonly page?: boolean },
): Effect.Effect<HttpServerResponse.HttpServerResponse, never, R> =>
  handler.pipe(
    Effect.catchCause((cause) => {
      const error = Cause.findErrorOption(cause);
      if (Option.isSome(error) && isRefusal(error.value)) {
        return Effect.succeed(
          options?.page === true
            ? messagePage("Cannot continue", error.value.reason, error.value.status)
            : refusalResponse(error.value),
        );
      }
      return Effect.logError("Control plane request failed", { cause }).pipe(
        Effect.as(
          options?.page === true
            ? messagePage("Something went wrong", "Try again in a moment.", 500)
            : json({ error: "internal", message: "internal error" }, 500),
        ),
      );
    }),
  );

/** For routes a person's browser opens: refusals render as a page, not JSON. */
export const respondPage = <E, R>(
  handler: Effect.Effect<HttpServerResponse.HttpServerResponse, E, R>,
) => respond(handler, { page: true });
