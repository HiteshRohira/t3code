// OpenID Connect relying party: authorization code flow with PKCE against the org's IdP.
import * as NodeCrypto from "node:crypto";

import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

import type { OidcConfig } from "./config.ts";

interface Discovery {
  readonly authorization_endpoint: string;
  readonly token_endpoint: string;
  readonly jwks_uri: string;
  readonly issuer: string;
}

export interface OidcIdentity {
  readonly subject: string;
  readonly email: string;
  readonly name: string | null;
  readonly groups: ReadonlyArray<string>;
}

export class OidcError extends Error {
  override readonly name = "OidcError";
}

export const randomToken = (bytes = 32) => NodeCrypto.randomBytes(bytes).toString("base64url");
export const pkceChallenge = (verifier: string) =>
  NodeCrypto.createHash("sha256").update(verifier).digest("base64url");

export class OidcClient {
  readonly #config: OidcConfig;
  readonly #fetch: typeof fetch;
  #discovery: Promise<Discovery> | undefined;
  #jwks: ReturnType<typeof createRemoteJWKSet> | undefined;

  constructor(config: OidcConfig, fetchImpl: typeof fetch = fetch) {
    this.#config = config;
    this.#fetch = fetchImpl;
  }

  #discover(): Promise<Discovery> {
    this.#discovery ??= this.#fetch(`${this.#config.issuer}/.well-known/openid-configuration`)
      .then(async (response) => {
        if (!response.ok) throw new OidcError(`OIDC discovery failed: ${response.status}`);
        const discovery = (await response.json()) as Discovery;
        if (discovery.issuer.replace(/\/$/, "") !== this.#config.issuer) {
          throw new OidcError("OIDC discovery issuer does not match the configured issuer");
        }
        return discovery;
      })
      .catch((error: unknown) => {
        this.#discovery = undefined;
        throw error;
      });
    return this.#discovery;
  }

  async authorizationUrl(input: {
    redirectUri: string;
    state: string;
    nonce: string;
    codeVerifier: string;
  }): Promise<string> {
    const discovery = await this.#discover();
    const url = new URL(discovery.authorization_endpoint);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", this.#config.clientId);
    url.searchParams.set("redirect_uri", input.redirectUri);
    url.searchParams.set("scope", this.#config.scopes.join(" "));
    url.searchParams.set("state", input.state);
    url.searchParams.set("nonce", input.nonce);
    url.searchParams.set("code_challenge", pkceChallenge(input.codeVerifier));
    url.searchParams.set("code_challenge_method", "S256");
    return url.toString();
  }

  async exchange(input: {
    code: string;
    redirectUri: string;
    codeVerifier: string;
    nonce: string;
  }): Promise<OidcIdentity> {
    const discovery = await this.#discover();
    const response = await this.#fetch(discovery.token_endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${Buffer.from(
          `${encodeURIComponent(this.#config.clientId)}:${encodeURIComponent(this.#config.clientSecret)}`,
        ).toString("base64")}`,
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: input.code,
        redirect_uri: input.redirectUri,
        code_verifier: input.codeVerifier,
      }),
    });
    if (!response.ok) throw new OidcError(`OIDC token exchange failed: ${response.status}`);
    const tokens = (await response.json()) as { id_token?: unknown };
    if (typeof tokens.id_token !== "string") throw new OidcError("IdP returned no id_token");
    this.#jwks ??= createRemoteJWKSet(new URL(discovery.jwks_uri));
    const { payload } = await jwtVerify(tokens.id_token, this.#jwks, {
      issuer: discovery.issuer,
      audience: this.#config.clientId,
    }).catch((cause: unknown) => {
      throw new OidcError(cause instanceof Error ? cause.message : "invalid id_token");
    });
    if (payload["nonce"] !== input.nonce) throw new OidcError("id_token nonce mismatch");
    return identityOf(payload, this.#config.groupsClaim);
  }
}

function identityOf(payload: JWTPayload, groupsClaim: string): OidcIdentity {
  const email = payload["email"];
  if (typeof payload.sub !== "string" || typeof email !== "string") {
    throw new OidcError("id_token has no subject or email");
  }
  if (payload["email_verified"] === false) throw new OidcError("IdP has not verified this email");
  const groups = payload[groupsClaim];
  const name = payload["name"];
  return {
    subject: payload.sub,
    email: email.toLowerCase(),
    name: typeof name === "string" ? name : null,
    groups: Array.isArray(groups) ? groups.filter((g): g is string => typeof g === "string") : [],
  };
}
