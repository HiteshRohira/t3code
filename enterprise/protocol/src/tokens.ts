// Leases (device → gateway) and policies (control plane → device) are ES256 JWTs. The control
// plane signs both; the gateway trusts its published keys and devices trust keys their
// enterprise config pins.
import * as Clock from "effect/Clock";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";
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

import { Role } from "./wire.ts";

export const SIGNING_ALG = "ES256";
export const LEASE_AUDIENCE = "t3-enterprise-gateway";
export const POLICY_AUDIENCE = "t3-enterprise-device";
export const PAIRING_AUDIENCE = "t3-enterprise-pairing";

export class TokenRejected extends Schema.TaggedError<TokenRejected>()("TokenRejected", {
  reason: Schema.String,
}) {
  override get message(): string {
    return this.reason;
  }
}

export class SigningError extends Schema.TaggedError<SigningError>()("SigningError", {
  cause: Schema.Defect(),
}) {
  override get message(): string {
    return "Signing a token failed.";
  }
}

export const SigningKey = Schema.Struct({
  kid: Schema.String,
  privateJwk: Schema.Record(Schema.String, Schema.Unknown),
  publicJwk: Schema.Record(Schema.String, Schema.Unknown),
});
export type SigningKey = typeof SigningKey.Type;

export const generateSigningKey = Effect.fn("EnterpriseTokens.generateSigningKey")(function* (
  kid: string,
) {
  return yield* Effect.tryPromise({
    try: async (): Promise<SigningKey> => {
      const { privateKey, publicKey } = await generateKeyPair(SIGNING_ALG, { extractable: true });
      const meta = { kid, alg: SIGNING_ALG, use: "sig" };
      return {
        kid,
        privateJwk: { ...(await exportJWK(privateKey)), ...meta },
        publicJwk: { ...(await exportJWK(publicKey)), ...meta },
      };
    },
    catch: (cause) => new SigningError({ cause }),
  });
});

export const publicJwks = (keys: ReadonlyArray<SigningKey>) => ({
  keys: keys.map((key) => key.publicJwk),
});

const nowDate = Effect.map(Clock.currentTimeMillis, (millis) =>
  DateTime.toDate(DateTime.makeUnsafe(millis)),
);

const sign = Effect.fn("EnterpriseTokens.sign")(function* (
  key: SigningKey,
  claims: JWTPayload,
  options: { issuer: string; audience: string; subject?: string; ttlSeconds: number },
) {
  const iat = Math.floor((yield* Clock.currentTimeMillis) / 1000);
  return yield* Effect.tryPromise({
    try: async () => {
      let jwt = new SignJWT(claims)
        .setProtectedHeader({ alg: SIGNING_ALG, kid: key.kid, typ: "JWT" })
        .setIssuer(options.issuer)
        .setAudience(options.audience)
        .setIssuedAt(iat)
        .setExpirationTime(iat + options.ttlSeconds);
      if (options.subject !== undefined) jwt = jwt.setSubject(options.subject);
      return jwt.sign(await importJWK(key.privateJwk as JWK, SIGNING_ALG));
    },
    catch: (cause) => new SigningError({ cause }),
  });
});

const verify = Effect.fn("EnterpriseTokens.verify")(function* (
  token: string,
  keys: { readonly keys: ReadonlyArray<object> },
  options: { issuer: string; audience: string },
) {
  const currentDate = yield* nowDate;
  const { payload } = yield* Effect.tryPromise({
    try: () =>
      jwtVerify(token, createLocalJWKSet(keys as JSONWebKeySet), {
        issuer: options.issuer,
        audience: options.audience,
        algorithms: [SIGNING_ALG],
        currentDate,
      }),
    catch: (cause) =>
      new TokenRejected({ reason: cause instanceof Error ? cause.message : "invalid token" }),
  });
  return payload;
});

const LeasePayload = Schema.Struct({
  sub: Schema.String,
  jti: Schema.String,
  exp: Schema.Number,
  dev: Schema.String,
  email: Schema.String,
  roles: Schema.Array(Role),
  cnf: Schema.Struct({ "x5t#S256": Schema.String }),
  models: Schema.optional(Schema.Array(Schema.String)),
  region: Schema.optional(Schema.String),
});

export interface LeaseClaims {
  readonly userId: string;
  readonly email: string;
  readonly deviceId: string;
  readonly roles: ReadonlyArray<Role>;
  /** Device certificate thumbprint the lease is bound to (RFC 8705 `cnf.x5t#S256`). */
  readonly thumbprint: string;
  /** Model ids or `prefix*` patterns this lease may call; absent allows every model. */
  readonly models?: ReadonlyArray<string> | undefined;
  /** Data region whose upstreams must serve this lease; absent allows any. */
  readonly region?: string | undefined;
  readonly leaseId: string;
  readonly expiresAt: DateTime.Utc;
}

export const signLease = Effect.fn("EnterpriseTokens.signLease")(function* (
  key: SigningKey,
  lease: Omit<LeaseClaims, "expiresAt">,
  options: { issuer: string; ttlSeconds: number },
) {
  return yield* sign(
    key,
    {
      jti: lease.leaseId,
      email: lease.email,
      dev: lease.deviceId,
      roles: [...lease.roles],
      cnf: { "x5t#S256": lease.thumbprint },
      ...(lease.models === undefined ? {} : { models: [...lease.models] }),
      ...(lease.region === undefined ? {} : { region: lease.region }),
    },
    {
      issuer: options.issuer,
      audience: LEASE_AUDIENCE,
      subject: lease.userId,
      ttlSeconds: options.ttlSeconds,
    },
  );
});

const decodeLease = Schema.decodeUnknownEffect(LeasePayload);

/** Verifies signature, issuer, audience, expiry, and that the lease belongs to `thumbprint`. */
export const verifyLease = Effect.fn("EnterpriseTokens.verifyLease")(function* (
  token: string,
  jwks: { readonly keys: ReadonlyArray<object> },
  options: { issuer: string; thumbprint: string },
) {
  const payload = yield* verify(token, jwks, {
    issuer: options.issuer,
    audience: LEASE_AUDIENCE,
  });
  const claims = yield* decodeLease(payload).pipe(
    Effect.mapError(() => new TokenRejected({ reason: "lease is missing required claims" })),
  );
  if (claims.cnf["x5t#S256"] !== options.thumbprint) {
    return yield* new TokenRejected({ reason: "lease is bound to a different device certificate" });
  }
  return {
    userId: claims.sub,
    email: claims.email,
    deviceId: claims.dev,
    roles: claims.roles,
    thumbprint: claims.cnf["x5t#S256"],
    models: claims.models,
    region: claims.region,
    leaseId: claims.jti,
    expiresAt: DateTime.makeUnsafe(claims.exp * 1000),
  } satisfies LeaseClaims;
});

export interface PolicyClaims {
  readonly version: number;
  /** An upstream managed policy document; the device validates it like a policy file. */
  readonly policy: unknown;
  readonly issuedAt: DateTime.Utc;
  readonly expiresAt: DateTime.Utc;
}

export const signPolicy = Effect.fn("EnterpriseTokens.signPolicy")(function* (
  key: SigningKey,
  policy: { version: number; document: unknown },
  options: { issuer: string; ttlSeconds: number },
) {
  return yield* sign(
    key,
    { ver: policy.version, policy: policy.document },
    { issuer: options.issuer, audience: POLICY_AUDIENCE, ttlSeconds: options.ttlSeconds },
  );
});

const PolicyPayload = Schema.Struct({
  ver: Schema.Number,
  iat: Schema.Number,
  exp: Schema.Number,
  policy: Schema.Record(Schema.String, Schema.Unknown),
});
const decodePolicy = Schema.decodeUnknownEffect(PolicyPayload);

/** `trusted` are the keys the device's enterprise config pins; nothing fetched is trusted. */
export const verifyPolicy = Effect.fn("EnterpriseTokens.verifyPolicy")(function* (
  token: string,
  trusted: { readonly keys: ReadonlyArray<object> },
  options: { issuer: string },
) {
  const payload = yield* verify(token, trusted, {
    issuer: options.issuer,
    audience: POLICY_AUDIENCE,
  });
  const claims = yield* decodePolicy(payload).pipe(
    Effect.mapError(() => new TokenRejected({ reason: "policy token is missing required claims" })),
  );
  return {
    version: claims.ver,
    policy: claims.policy,
    issuedAt: DateTime.makeUnsafe(claims.iat * 1000),
    expiresAt: DateTime.makeUnsafe(claims.exp * 1000),
  } satisfies PolicyClaims;
});

const PairingPayload = Schema.Struct({
  sub: Schema.String,
  email: Schema.String,
  dev: Schema.String,
  nonce: Schema.String,
});

/**
 * Proof that the person on a browser signed in to the org as the user who enrolled `deviceId`.
 * The environment checks `nonce` against the pairing it started, so an assertion only completes
 * the pairing it was issued for.
 */
export interface PairingClaims {
  readonly userId: string;
  readonly email: string;
  readonly deviceId: string;
  readonly nonce: string;
}

export const signPairingAssertion = Effect.fn("EnterpriseTokens.signPairingAssertion")(function* (
  key: SigningKey,
  claims: PairingClaims,
  options: { issuer: string; ttlSeconds: number },
) {
  return yield* sign(
    key,
    { email: claims.email, dev: claims.deviceId, nonce: claims.nonce },
    {
      issuer: options.issuer,
      audience: PAIRING_AUDIENCE,
      subject: claims.userId,
      ttlSeconds: options.ttlSeconds,
    },
  );
});

const decodePairing = Schema.decodeUnknownEffect(PairingPayload);

export const verifyPairingAssertion = Effect.fn("EnterpriseTokens.verifyPairingAssertion")(
  function* (
    token: string,
    trusted: { readonly keys: ReadonlyArray<object> },
    options: { issuer: string },
  ) {
    const payload = yield* verify(token, trusted, {
      issuer: options.issuer,
      audience: PAIRING_AUDIENCE,
    });
    const claims = yield* decodePairing(payload).pipe(
      Effect.mapError(
        () => new TokenRejected({ reason: "pairing assertion is missing required claims" }),
      ),
    );
    return {
      userId: claims.sub,
      email: claims.email,
      deviceId: claims.dev,
      nonce: claims.nonce,
    } satisfies PairingClaims;
  },
);

/** Whether `model` matches an allow-list of exact ids and `prefix*` patterns. */
export function modelAllowed(models: ReadonlyArray<string> | undefined, model: string): boolean {
  if (models === undefined) return true;
  return models.some((pattern) =>
    pattern.endsWith("*") ? model.startsWith(pattern.slice(0, -1)) : model === pattern,
  );
}
