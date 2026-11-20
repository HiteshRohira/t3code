// @effect-diagnostics nodeBuiltinImport:off
/**
 * enterpriseTransport - node:http(s) for what `fetch` cannot do: present the device's client
 * certificate, trust a private CA, and stream a provider response through without buffering it.
 *
 * @module enterpriseTransport
 */
import * as NodeCrypto from "node:crypto";
import * as NodeHttp from "node:http";
import * as NodeHttps from "node:https";
import * as NodeTls from "node:tls";

export interface TlsCredentials {
  readonly keyPem?: string;
  readonly certificatePem?: string;
  /** Extra CAs, added to Node's public roots rather than replacing them. */
  readonly serverCaPem?: string;
}

const tlsOptions = (credentials: TlsCredentials) => ({
  ...(credentials.keyPem === undefined ? {} : { key: credentials.keyPem }),
  ...(credentials.certificatePem === undefined ? {} : { cert: credentials.certificatePem }),
  ...(credentials.serverCaPem === undefined
    ? {}
    : { ca: [...NodeTls.rootCertificates, credentials.serverCaPem] }),
});

export interface JsonReply {
  readonly status: number;
  readonly body: unknown;
}

export function requestJson(
  url: string,
  options: {
    readonly method?: string;
    readonly body?: unknown;
    readonly credentials: TlsCredentials;
    readonly timeoutMs?: number;
  },
): Promise<JsonReply> {
  return new Promise((resolve, reject) => {
    const body = options.body === undefined ? undefined : JSON.stringify(options.body);
    const request = NodeHttps.request(
      url,
      {
        method: options.method ?? "GET",
        headers: {
          accept: "application/json",
          ...(body === undefined
            ? {}
            : { "content-type": "application/json", "content-length": Buffer.byteLength(body) }),
        },
        ...tlsOptions(options.credentials),
        agent: false,
        timeout: options.timeoutMs ?? 20_000,
      },
      (response) => {
        const chunks: Array<Buffer> = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let parsed: unknown = null;
          try {
            parsed = text.length === 0 ? null : JSON.parse(text);
          } catch {
            parsed = { error: "invalid_response", message: text.slice(0, 200) };
          }
          resolve({ status: response.statusCode ?? 0, body: parsed });
        });
        response.on("error", reject);
      },
    );
    request.on("timeout", () => request.destroy(new Error(`${url} timed out`)));
    request.on("error", reject);
    request.end(body);
  });
}

/** What the proxy forwards with, or why it cannot. */
export type ProxyCredentials =
  | {
      readonly ok: true;
      readonly lease: string;
      readonly keyPem: string;
      readonly certificatePem: string;
    }
  | { readonly ok: false; readonly status: number; readonly message: string };

export interface LocalProxy {
  readonly port: number;
  readonly close: () => Promise<void>;
}

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "authorization",
  "x-api-key",
]);

const errorBody = (family: string, message: string, status: number) =>
  family === "anthropic"
    ? {
        type: "error",
        error: {
          type:
            status === 429
              ? "rate_limit_error"
              : status === 403
                ? "permission_error"
                : "authentication_error",
          message,
        },
      }
    : { error: { message, type: "enterprise", code: status } };

const sameToken = (a: string, b: string) => {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && NodeCrypto.timingSafeEqual(left, right);
};

/**
 * Loopback HTTP that provider CLIs use as their API base URL. It accepts only `token`, which only
 * processes T3 Code starts receive, and forwards to the gateway with the device certificate and
 * the current lease, so neither ever reaches a provider process.
 */
export function startLocalProxy(options: {
  readonly token: string;
  readonly gatewayUrl: string;
  readonly serverCaPem?: string;
  readonly credentials: () => ProxyCredentials;
  readonly port?: number;
}): Promise<LocalProxy> {
  const gateway = new URL(options.gatewayUrl);
  const server = NodeHttp.createServer((request, response) => {
    const path = request.url ?? "/";
    const family = path.startsWith("/openai") ? "openai" : "anthropic";
    const reply = (status: number, message: string) => {
      response.writeHead(status, { "content-type": "application/json" });
      response.end(JSON.stringify(errorBody(family, message, status)));
    };
    const header = request.headers["x-api-key"] ?? request.headers.authorization;
    const presented = (Array.isArray(header) ? header[0] : header)
      ?.replace(/^bearer\s+/i, "")
      .trim();
    if (presented === undefined || !sameToken(presented, options.token)) {
      reply(401, "This endpoint only serves agents started by T3 Code.");
      return;
    }
    if (!path.startsWith("/anthropic/") && !path.startsWith("/openai/")) {
      reply(404, "Unknown provider path.");
      return;
    }
    const credentials = options.credentials();
    if (!credentials.ok) {
      reply(credentials.status, credentials.message);
      return;
    }
    const headers: Record<string, string | Array<string>> = {};
    for (const [name, value] of Object.entries(request.headers)) {
      if (value !== undefined && !HOP_BY_HOP.has(name)) headers[name] = value;
    }
    if (family === "anthropic") headers["x-api-key"] = credentials.lease;
    else headers["authorization"] = `Bearer ${credentials.lease}`;
    const target = new URL(`${gateway.pathname.replace(/\/$/, "")}${path}`, gateway);
    const outbound = NodeHttps.request(
      target,
      {
        method: request.method ?? "POST",
        headers,
        ...tlsOptions({
          keyPem: credentials.keyPem,
          certificatePem: credentials.certificatePem,
          ...(options.serverCaPem === undefined ? {} : { serverCaPem: options.serverCaPem }),
        }),
      },
      (upstream) => {
        const responseHeaders: Record<string, string | Array<string>> = {};
        for (const [name, value] of Object.entries(upstream.headers)) {
          if (value !== undefined && !HOP_BY_HOP.has(name)) responseHeaders[name] = value;
        }
        response.writeHead(upstream.statusCode ?? 502, responseHeaders);
        upstream.pipe(response);
      },
    );
    outbound.on("error", () => {
      if (!response.headersSent)
        reply(502, `Cannot reach your organization's gateway at ${gateway.host}.`);
      else response.destroy();
    });
    // A cancelled turn closes the request; stop the upstream call so it stops spending.
    response.on("close", () => {
      if (!response.writableFinished) outbound.destroy();
    });
    request.pipe(outbound);
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port ?? 0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        reject(new Error("local proxy has no port"));
        return;
      }
      resolve({
        port: address.port,
        close: () =>
          new Promise<void>((done) => {
            server.close(() => done());
            server.closeAllConnections();
          }),
      });
    });
  });
}

/** RSA because the org CA issues certificates with node-forge, which only signs RSA keys. */
export function generateDeviceKey(): { readonly keyPem: string; readonly publicKeyPem: string } {
  const { privateKey, publicKey } = NodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 3072,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { keyPem: privateKey, publicKeyPem: publicKey };
}

export const signWithDeviceKey = (keyPem: string, message: string) =>
  NodeCrypto.sign("sha256", Buffer.from(message), keyPem).toString("base64url");

export const randomToken = (bytes = 32) => NodeCrypto.randomBytes(bytes).toString("base64url");

export interface LoopbackCallback {
  readonly redirectUri: string;
  /** Resolves with the code once the browser comes back with the expected state. */
  readonly code: Promise<string>;
  readonly close: () => void;
}

const CALLBACK_PAGE = (title: string, detail: string) =>
  `<!doctype html><meta charset="utf-8"><title>${title}</title><body style="font:15px system-ui;margin:48px auto;max-width:420px"><h1 style="font-size:20px">${title}</h1><p>${detail}</p>`;

/** One-shot loopback listener for the enrollment redirect (RFC 8252 §7.3). */
export function awaitLoopbackCallback(state: string): Promise<LoopbackCallback> {
  let settle: { resolve: (code: string) => void; reject: (error: Error) => void } | undefined;
  const code = new Promise<string>((resolve, reject) => {
    settle = { resolve, reject };
  });
  const server = NodeHttp.createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (url.pathname !== "/callback") {
      response.writeHead(404).end();
      return;
    }
    const returned = url.searchParams.get("code");
    if (url.searchParams.get("state") !== state || returned === null) {
      response.writeHead(400, { "content-type": "text/html; charset=utf-8" });
      response.end(
        CALLBACK_PAGE(
          "Enrollment failed",
          "This link does not belong to the enrollment in progress. Start again from T3 Code.",
        ),
      );
      return;
    }
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(CALLBACK_PAGE("Device enrolled", "You can close this tab and return to T3 Code."));
    settle?.resolve(returned);
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        reject(new Error("callback listener has no port"));
        return;
      }
      resolve({
        redirectUri: `http://127.0.0.1:${address.port}/callback`,
        code,
        close: () => {
          settle?.reject(new Error("enrollment was cancelled"));
          server.close();
          server.closeAllConnections();
        },
      });
    });
  });
}
