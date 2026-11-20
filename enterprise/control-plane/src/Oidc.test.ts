// @effect-diagnostics nodeBuiltinImport:off -- a real HTTP server plays the IdP.
import * as NodeHttp from "node:http";

import * as NodeHttpClient from "@effect/platform-node/NodeHttpClient";
import { assert, describe, it } from "@effect/vitest";
import * as Effect from "effect/Effect";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

import * as Oidc from "./Oidc.ts";

/** A minimal OpenID provider: discovery, JWKS, and a token endpoint that signs `claims`. */
const startIdp = (claims: Record<string, unknown>) =>
  Effect.acquireRelease(
    Effect.promise(async () => {
      const { privateKey, publicKey } = await generateKeyPair("RS256");
      const jwk = { ...(await exportJWK(publicKey)), kid: "idp-key", alg: "RS256", use: "sig" };
      const seen: Array<URLSearchParams> = [];
      let issuer = "";
      const server = NodeHttp.createServer((request, response) => {
        const send = (body: unknown) => {
          response.writeHead(200, { "content-type": "application/json" });
          response.end(JSON.stringify(body));
        };
        if (request.url === "/.well-known/openid-configuration") {
          return send({
            issuer,
            authorization_endpoint: `${issuer}/authorize`,
            token_endpoint: `${issuer}/token`,
            jwks_uri: `${issuer}/jwks`,
          });
        }
        if (request.url === "/jwks") return send({ keys: [jwk] });
        if (request.url === "/token" && request.method === "POST") {
          let body = "";
          request.on("data", (chunk: Buffer) => (body += chunk.toString("utf8")));
          request.on("end", async () => {
            seen.push(new URLSearchParams(body));
            const idToken = await new SignJWT(claims)
              .setProtectedHeader({ alg: "RS256", kid: "idp-key" })
              .setIssuer(issuer)
              .setAudience("t3-enterprise")
              .setIssuedAt()
              .setExpirationTime("5m")
              .sign(privateKey);
            send({ id_token: idToken, access_token: "unused", token_type: "Bearer" });
          });
          return;
        }
        response.writeHead(404).end();
      });
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address() as { port: number };
      issuer = `http://127.0.0.1:${address.port}`;
      return { issuer, seen, server };
    }),
    ({ server }) =>
      Effect.promise(
        () =>
          new Promise<void>((resolve) => {
            server.close(() => resolve());
            server.closeAllConnections();
          }),
      ),
  );

const clientFor = (issuer: string) =>
  Oidc.make({
    issuer,
    clientId: "t3-enterprise",
    clientSecret: "secret",
    scopes: ["openid", "email"],
    groupsClaim: "groups",
  });

const exchange = { redirectUri: "https://cp.example/oidc/callback", codeVerifier: "verifier-1" };

describe("Oidc", () => {
  it.live("exchanges a code with PKCE and returns the verified identity", () =>
    Effect.gen(function* () {
      const idp = yield* startIdp({
        sub: "u-1",
        email: "Dev@Example.com",
        nonce: "n-1",
        groups: ["eng"],
        name: "Dev",
      });
      const client = yield* clientFor(idp.issuer);
      const authorize = new URL(
        yield* client.authorizationUrl({ ...exchange, state: "s-1", nonce: "n-1" }),
      );
      assert.strictEqual(authorize.searchParams.get("code_challenge_method"), "S256");
      assert.strictEqual(authorize.searchParams.get("nonce"), "n-1");

      const identity = yield* client.exchange({ ...exchange, code: "code-1", nonce: "n-1" });
      assert.deepStrictEqual(identity, {
        subject: "u-1",
        email: "dev@example.com",
        name: "Dev",
        groups: ["eng"],
      });
      assert.strictEqual(idp.seen[0]?.get("code_verifier"), "verifier-1");
    }).pipe(Effect.scoped, Effect.provide(NodeHttpClient.layerUndici)),
  );

  it.live.each([
    ["an id_token issued for another sign-in", { nonce: "someone-else" }, "nonce mismatch"],
    ["an email the IdP has not verified", { nonce: "n-1", email_verified: false }, "not verified"],
  ] as const)("refuses %s", ([, extra, reason]) =>
    Effect.gen(function* () {
      const idp = yield* startIdp({ sub: "u-1", email: "dev@example.com", ...extra });
      const client = yield* clientFor(idp.issuer);
      const error = yield* Effect.flip(client.exchange({ ...exchange, code: "c", nonce: "n-1" }));
      assert.include(error.reason, reason);
    }).pipe(Effect.scoped, Effect.provide(NodeHttpClient.layerUndici)),
  );
});
