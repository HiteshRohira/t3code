import * as NodeCrypto from "node:crypto";
import type * as NodeHttp from "node:http";
import type * as NodeTls from "node:tls";

export class HttpError extends Error {
  override readonly name = "HttpError";
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export async function readBody(
  request: NodeHttp.IncomingMessage,
  limit = 1024 * 1024,
): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = chunk as Buffer;
    size += buffer.length;
    if (size > limit) throw new HttpError(413, "too_large", "request body is too large");
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export async function readJson(
  request: NodeHttp.IncomingMessage,
  limit?: number,
): Promise<unknown> {
  const body = await readBody(request, limit);
  try {
    return JSON.parse(body) as unknown;
  } catch {
    throw new HttpError(400, "invalid_json", "request body is not JSON");
  }
}

export async function readForm(request: NodeHttp.IncomingMessage): Promise<URLSearchParams> {
  return new URLSearchParams(await readBody(request, 64 * 1024));
}

export function sendJson(
  response: NodeHttp.ServerResponse,
  status: number,
  body: unknown,
  contentType = "application/json",
) {
  const text = JSON.stringify(body);
  response.writeHead(status, {
    "content-type": `${contentType}; charset=utf-8`,
    "cache-control": "no-store",
    "content-length": Buffer.byteLength(text),
  });
  response.end(text);
}

export function sendError(response: NodeHttp.ServerResponse, error: HttpError) {
  sendJson(response, error.status, { error: error.code, message: error.message });
}

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
};

export function sendHtml(response: NodeHttp.ServerResponse, status: number, html: string) {
  response.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "content-security-policy":
      "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    ...SECURITY_HEADERS,
  });
  response.end(html);
}

export function sendText(
  response: NodeHttp.ServerResponse,
  status: number,
  text: string,
  type: string,
) {
  response.writeHead(status, {
    "content-type": type,
    "cache-control": "no-store",
    ...SECURITY_HEADERS,
  });
  response.end(text);
}

export function redirect(
  response: NodeHttp.ServerResponse,
  location: string,
  headers: Record<string, string> = {},
) {
  response.writeHead(302, { location, "cache-control": "no-store", ...headers });
  response.end();
}

export const escapeHtml = (value: string) =>
  value.replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);

export function constantTimeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && NodeCrypto.timingSafeEqual(left, right);
}

export function bearer(request: NodeHttp.IncomingMessage): string | undefined {
  const header = request.headers.authorization;
  if (header === undefined || !header.toLowerCase().startsWith("bearer ")) return undefined;
  return header.slice(7).trim();
}

export function cookie(request: NodeHttp.IncomingMessage, name: string): string | undefined {
  for (const part of (request.headers.cookie ?? "").split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return undefined;
}

/** The verified client certificate's DER, or undefined when the peer presented none the CA signed. */
export function verifiedClientCertificate(request: NodeHttp.IncomingMessage): Buffer | undefined {
  const socket = request.socket as NodeTls.TLSSocket;
  if (typeof socket.getPeerCertificate !== "function" || !socket.authorized) return undefined;
  const peer = socket.getPeerCertificate();
  return peer.raw === undefined || peer.raw.length === 0 ? undefined : peer.raw;
}
