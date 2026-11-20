import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  importJWK,
  type JSONWebKeySet,
  type JWK,
  type JWTPayload,
  jwtVerify,
  SignJWT,
} from "jose";

import { isRole, type Role } from "./wire.ts";

export const SIGNING_ALG = "ES256";
export const LEASE_AUDIENCE = "t3-enterprise-gateway";
export const POLICY_AUDIENCE = "t3-enterprise-device";

export interface SigningKey {
  readonly kid: string;
  readonly privateJwk: JWK;
  readonly publicJwk: JWK;
}

export async function generateSigningKey(kid: string): Promise<SigningKey> {
  const { privateKey, publicKey } = await generateKeyPair(SIGNING_ALG, { extractable: true });
  const privateJwk = { ...(await exportJWK(privateKey)), kid, alg: SIGNING_ALG, use: "sig" };
  const publicJwk = { ...(await exportJWK(publicKey)), kid, alg: SIGNING_ALG, use: "sig" };
  return { kid, privateJwk, publicJwk };
}

export const publicJwks = (keys: ReadonlyArray<SigningKey>): JSONWebKeySet => ({
  keys: keys.map((key) => key.publicJwk),
});

async function sign(
  key: SigningKey,
  claims: JWTPayload,
  options: { issuer: string; audience: string; subject?: string; ttlSeconds: number; now: Date },
): Promise<string> {
  const iat = Math.floor(options.now.getTime() / 1000);
  let jwt = new SignJWT(claims)
    .setProtectedHeader({ alg: SIGNING_ALG, kid: key.kid, typ: "JWT" })
    .setIssuer(options.issuer)
    .setAudience(options.audience)
    .setIssuedAt(iat)
    .setExpirationTime(iat + options.ttlSeconds);
  if (options.subject !== undefined) jwt = jwt.setSubject(options.subject);
  return jwt.sign(await importJWK(key.privateJwk, SIGNING_ALG));
}

export interface LeaseClaims {
  readonly userId: string;
  readonly email: string;
  readonly deviceId: string;
  readonly roles: ReadonlyArray<Role>;
  /** Device certificate thumbprint the lease is bound to (RFC 8705 `cnf.x5t#S256`). */
  readonly thumbprint: string;
  /** Model ids or `prefix*` patterns this lease may call; absent allows every model. */
  readonly models?: ReadonlyArray<string>;
  readonly leaseId: string;
  readonly expiresAt: Date;
}

export async function signLease(
  key: SigningKey,
  lease: Omit<LeaseClaims, "expiresAt">,
  options: { issuer: string; ttlSeconds: number; now?: Date },
): Promise<string> {
  return sign(
    key,
    {
      jti: lease.leaseId,
      email: lease.email,
      dev: lease.deviceId,
      roles: [...lease.roles],
      cnf: { "x5t#S256": lease.thumbprint },
      ...(lease.models === undefined ? {} : { models: [...lease.models] }),
    },
    {
      issuer: options.issuer,
      audience: LEASE_AUDIENCE,
      subject: lease.userId,
      ttlSeconds: options.ttlSeconds,
      now: options.now ?? new Date(),
    },
  );
}

export class TokenRejected extends Error {
  override readonly name = "TokenRejected";
}

const stringArray = (value: unknown): ReadonlyArray<string> | undefined =>
  Array.isArray(value) && value.every((item) => typeof item === "string") ? value : undefined;

/** Verifies signature, issuer, audience, expiry, and that the lease belongs to `thumbprint`. */
export async function verifyLease(
  token: string,
  jwks: JSONWebKeySet,
  options: { issuer: string; thumbprint: string; now?: Date },
): Promise<LeaseClaims> {
  const { payload } = await jwtVerify(token, createLocalJWKSet(jwks), {
    issuer: options.issuer,
    audience: LEASE_AUDIENCE,
    algorithms: [SIGNING_ALG],
    ...(options.now === undefined ? {} : { currentDate: options.now }),
  }).catch((cause: unknown) => {
    throw new TokenRejected(cause instanceof Error ? cause.message : "invalid lease");
  });
  const cnf = payload["cnf"] as Record<string, unknown> | undefined;
  const bound = cnf?.["x5t#S256"];
  if (typeof bound !== "string" || bound !== options.thumbprint) {
    throw new TokenRejected("lease is bound to a different device certificate");
  }
  const roles = stringArray(payload["roles"]);
  const models = stringArray(payload["models"]);
  if (
    typeof payload.sub !== "string" ||
    typeof payload.jti !== "string" ||
    typeof payload["dev"] !== "string" ||
    typeof payload["email"] !== "string" ||
    typeof payload.exp !== "number" ||
    roles === undefined ||
    !roles.every(isRole)
  ) {
    throw new TokenRejected("lease is missing required claims");
  }
  return {
    userId: payload.sub,
    email: payload["email"],
    deviceId: payload["dev"],
    roles: roles.filter(isRole),
    thumbprint: bound,
    ...(models === undefined ? {} : { models }),
    leaseId: payload.jti,
    expiresAt: new Date(payload.exp * 1000),
  };
}

export interface PolicyClaims {
  readonly version: number;
  /** An upstream managed policy document; the device validates it like a policy file. */
  readonly policy: unknown;
  readonly issuedAt: Date;
  readonly expiresAt: Date;
}

export async function signPolicy(
  key: SigningKey,
  policy: { version: number; document: unknown },
  options: { issuer: string; ttlSeconds: number; now?: Date },
): Promise<string> {
  return sign(
    key,
    { ver: policy.version, policy: policy.document },
    {
      issuer: options.issuer,
      audience: POLICY_AUDIENCE,
      ttlSeconds: options.ttlSeconds,
      now: options.now ?? new Date(),
    },
  );
}

/** `trusted` are the keys the device's enterprise config pins; nothing fetched is trusted. */
export async function verifyPolicy(
  token: string,
  trusted: JSONWebKeySet,
  options: { issuer: string; now?: Date },
): Promise<PolicyClaims> {
  const { payload } = await jwtVerify(token, createLocalJWKSet(trusted), {
    issuer: options.issuer,
    audience: POLICY_AUDIENCE,
    algorithms: [SIGNING_ALG],
    ...(options.now === undefined ? {} : { currentDate: options.now }),
  }).catch((cause: unknown) => {
    throw new TokenRejected(cause instanceof Error ? cause.message : "invalid policy");
  });
  if (
    typeof payload["ver"] !== "number" ||
    typeof payload.iat !== "number" ||
    typeof payload.exp !== "number" ||
    typeof payload["policy"] !== "object" ||
    payload["policy"] === null
  ) {
    throw new TokenRejected("policy token is missing required claims");
  }
  return {
    version: payload["ver"],
    policy: payload["policy"],
    issuedAt: new Date(payload.iat * 1000),
    expiresAt: new Date(payload.exp * 1000),
  };
}

/** Whether `model` matches an allow-list of exact ids and `prefix*` patterns. */
export function modelAllowed(models: ReadonlyArray<string> | undefined, model: string): boolean {
  if (models === undefined) return true;
  return models.some((pattern) =>
    pattern.endsWith("*") ? model.startsWith(pattern.slice(0, -1)) : model === pattern,
  );
}
