import * as NodeHttp from "node:http";

import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vite-plus/test";

import { OidcClient, OidcError } from "./oidc.ts";

interface IdpOptions {
  readonly claims: Record<string, unknown>;
}

/** A minimal OpenID provider: discovery, JWKS, and a token endpoint that signs `claims`. */
async function startIdp(options: IdpOptions) {
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
        const idToken = await new SignJWT(options.claims)
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
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no idp port");
  issuer = `http://127.0.0.1:${address.port}`;
  return {
    issuer,
    seen,
    [Symbol.asyncDispose]: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      }),
  };
}

const clientFor = (issuer: string) =>
  new OidcClient({
    issuer,
    clientId: "t3-enterprise",
    clientSecret: "secret",
    scopes: ["openid", "email"],
    groupsClaim: "groups",
    groupRoles: {},
  });

describe("OidcClient", () => {
  it("exchanges a code with PKCE and returns the verified identity", async () => {
    await using idp = await startIdp({
      claims: { sub: "u-1", email: "Dev@Example.com", nonce: "n-1", groups: ["eng"], name: "Dev" },
    });
    const client = clientFor(idp.issuer);
    const authorize = new URL(
      await client.authorizationUrl({
        redirectUri: "https://cp.example/oidc/callback",
        state: "s-1",
        nonce: "n-1",
        codeVerifier: "verifier-1",
      }),
    );
    expect(authorize.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorize.searchParams.get("nonce")).toBe("n-1");

    const identity = await client.exchange({
      code: "code-1",
      redirectUri: "https://cp.example/oidc/callback",
      codeVerifier: "verifier-1",
      nonce: "n-1",
    });
    expect(identity).toEqual({
      subject: "u-1",
      email: "dev@example.com",
      name: "Dev",
      groups: ["eng"],
    });
    expect(idp.seen[0]?.get("code_verifier")).toBe("verifier-1");
  });

  it("refuses an id_token issued for another sign-in", async () => {
    await using idp = await startIdp({
      claims: { sub: "u-1", email: "dev@example.com", nonce: "someone-else" },
    });
    await expect(
      clientFor(idp.issuer).exchange({
        code: "code-1",
        redirectUri: "https://cp.example/oidc/callback",
        codeVerifier: "verifier-1",
        nonce: "n-1",
      }),
    ).rejects.toBeInstanceOf(OidcError);
  });

  it("refuses an email the IdP has not verified", async () => {
    await using idp = await startIdp({
      claims: { sub: "u-1", email: "dev@example.com", email_verified: false, nonce: "n-1" },
    });
    await expect(
      clientFor(idp.issuer).exchange({
        code: "code-1",
        redirectUri: "https://cp.example/oidc/callback",
        codeVerifier: "verifier-1",
        nonce: "n-1",
      }),
    ).rejects.toBeInstanceOf(OidcError);
  });
});
