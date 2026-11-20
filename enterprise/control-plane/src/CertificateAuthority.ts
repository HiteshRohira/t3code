/**
 * CertificateAuthority - the org CA that signs device certificates. node-forge builds
 * certificates because Node's crypto can verify X.509 but cannot issue it; forge only handles
 * RSA, so device and CA keys are RSA.
 *
 * @module CertificateAuthority
 */
// @effect-diagnostics-next-line nodeBuiltinImport:off -- RSA key generation has no Effect equivalent.
import * as NodeCrypto from "node:crypto";

import * as Clock from "effect/Clock";
import * as Context from "effect/Context";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";
import * as Path from "effect/Path";
import * as Schema from "effect/Schema";
import forge from "node-forge";

import { ControlPlaneConfig } from "./Config.ts";

export interface Authority {
  readonly certPem: string;
  readonly cert: forge.pki.Certificate;
  readonly key: forge.pki.rsa.PrivateKey;
}

export class InvalidDeviceKey extends Schema.TaggedError<InvalidDeviceKey>()("InvalidDeviceKey", {
  reason: Schema.String,
}) {
  override get message(): string {
    return this.reason;
  }
}

export class CertificateAuthorityError extends Schema.TaggedError<CertificateAuthorityError>()(
  "CertificateAuthorityError",
  { reason: Schema.String },
) {
  override get message(): string {
    return this.reason;
  }
}

const DAY_MS = 24 * 3600 * 1000;
const at = (millis: number) => DateTime.toDate(DateTime.makeUnsafe(millis));
const serialNumber = () => `01${NodeCrypto.randomBytes(15).toString("hex")}`;

const rsaKeyPem = (bits: number) =>
  NodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: bits,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

export function createAuthorityPem(
  organization: string,
  options: { nowMillis: number; years?: number },
) {
  const { publicKey, privateKey } = rsaKeyPem(3072);
  const key = forge.pki.privateKeyFromPem(privateKey);
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.publicKeyFromPem(publicKey);
  cert.serialNumber = serialNumber();
  cert.validity.notBefore = at(options.nowMillis - 60_000);
  cert.validity.notAfter = at(options.nowMillis + (options.years ?? 10) * 365 * DAY_MS);
  const subject = [
    { name: "commonName", value: `${organization} T3 Enterprise CA` },
    { name: "organizationName", value: organization },
  ];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.setExtensions([
    { name: "basicConstraints", cA: true, critical: true },
    { name: "keyUsage", keyCertSign: true, cRLSign: true, critical: true },
    { name: "subjectKeyIdentifier" },
  ]);
  cert.sign(key, forge.md.sha256.create());
  return { certPem: forge.pki.certificateToPem(cert), keyPem: privateKey };
}

export const parseAuthority = (certPem: string, keyPem: string): Authority => ({
  certPem,
  cert: forge.pki.certificateFromPem(certPem),
  key: forge.pki.privateKeyFromPem(keyPem),
});

export const deviceUri = (deviceId: string) => `urn:t3-enterprise:device:${deviceId}`;
export const userUri = (userId: string) => `urn:t3-enterprise:user:${userId}`;

function rsaPublicKey(publicKeyPem: string): forge.pki.rsa.PublicKey | string {
  let key: forge.pki.PublicKey;
  try {
    key = forge.pki.publicKeyFromPem(publicKeyPem);
  } catch {
    return "device key must be an RSA public key in PEM (SPKI) form";
  }
  const rsa = key as forge.pki.rsa.PublicKey;
  if (rsa.n === undefined || rsa.n.bitLength() < 2048) {
    return "device key must be RSA with at least 2048 bits";
  }
  return rsa;
}

function issue(
  ca: Authority,
  options: {
    publicKey: forge.pki.rsa.PublicKey;
    commonName: string;
    days: number;
    nowMillis: number;
    extensions: ReadonlyArray<object>;
  },
) {
  const cert = forge.pki.createCertificate();
  cert.publicKey = options.publicKey;
  cert.serialNumber = serialNumber();
  cert.validity.notBefore = at(options.nowMillis - 60_000);
  cert.validity.notAfter = at(options.nowMillis + options.days * DAY_MS);
  cert.setSubject([
    { name: "commonName", value: options.commonName },
    { name: "organizationName", value: ca.cert.subject.getField("O")?.value ?? "T3 Enterprise" },
  ]);
  cert.setIssuer(ca.cert.subject.attributes);
  cert.setExtensions([
    { name: "basicConstraints", cA: false, critical: true },
    {
      name: "authorityKeyIdentifier",
      keyIdentifier: ca.cert.generateSubjectKeyIdentifier().getBytes(),
    },
    ...options.extensions,
  ]);
  cert.sign(ca.key, forge.md.sha256.create());
  return {
    certPem: forge.pki.certificateToPem(cert),
    expiresAt: DateTime.makeUnsafe(cert.validity.notAfter),
  };
}

/** A client certificate naming the device and its user, usable only for TLS client auth. */
export function issueDeviceCertificatePem(
  ca: Authority,
  device: {
    publicKeyPem: string;
    deviceId: string;
    userId: string;
    days: number;
    nowMillis: number;
  },
): { certPem: string; expiresAt: DateTime.Utc } | string {
  const publicKey = rsaPublicKey(device.publicKeyPem);
  if (typeof publicKey === "string") return publicKey;
  return issue(ca, {
    publicKey,
    commonName: device.deviceId,
    days: device.days,
    nowMillis: device.nowMillis,
    extensions: [
      { name: "keyUsage", digitalSignature: true, keyEncipherment: true, critical: true },
      { name: "extKeyUsage", clientAuth: true },
      {
        name: "subjectAltName",
        altNames: [
          { type: 6, value: deviceUri(device.deviceId) },
          { type: 6, value: userUri(device.userId) },
        ],
      },
    ],
  });
}

/** A TLS server certificate, for development setups without a public CA. */
export function issueServerCertificatePem(
  ca: Authority,
  options: { hostnames: ReadonlyArray<string>; days: number; nowMillis: number },
) {
  const { publicKey, privateKey } = rsaKeyPem(2048);
  const issued = issue(ca, {
    publicKey: forge.pki.publicKeyFromPem(publicKey) as forge.pki.rsa.PublicKey,
    commonName: options.hostnames[0] ?? "localhost",
    days: options.days,
    nowMillis: options.nowMillis,
    extensions: [
      { name: "keyUsage", digitalSignature: true, keyEncipherment: true, critical: true },
      { name: "extKeyUsage", serverAuth: true },
      {
        name: "subjectAltName",
        altNames: options.hostnames.map((host) =>
          /^[\d.]+$/.test(host) || host.includes(":")
            ? { type: 7, ip: host }
            : { type: 2, value: host },
        ),
      },
    ],
  });
  return { certPem: issued.certPem, keyPem: privateKey };
}

/** Loads the CA, creating one on first start when neither file exists. */
export const loadOrCreate = Effect.fn("CertificateAuthority.loadOrCreate")(
  function* (paths: { certPath: string; keyPath: string }, organization: string) {
    const fs = yield* FileSystem.FileSystem;
    const path = yield* Path.Path;
    const failure = (reason: string) => new CertificateAuthorityError({ reason });
    const hasCert = yield* fs.exists(paths.certPath).pipe(Effect.orElseSucceed(() => false));
    const hasKey = yield* fs.exists(paths.keyPath).pipe(Effect.orElseSucceed(() => false));
    if (hasCert !== hasKey) {
      return yield* failure(
        `CA certificate and key must both exist: ${paths.certPath}, ${paths.keyPath}`,
      );
    }
    if (!hasCert) {
      const created = createAuthorityPem(organization, {
        nowMillis: yield* Clock.currentTimeMillis,
      });
      yield* fs.makeDirectory(path.dirname(paths.keyPath), { recursive: true, mode: 0o700 });
      yield* fs.writeFileString(paths.keyPath, created.keyPem, { mode: 0o600 });
      yield* fs.writeFileString(paths.certPath, created.certPem, { mode: 0o644 });
    }
    const certPem = yield* fs.readFileString(paths.certPath);
    const keyPem = yield* fs.readFileString(paths.keyPath);
    return yield* Effect.try({
      try: () => parseAuthority(certPem, keyPem),
      catch: () => failure(`cannot parse the CA at ${paths.certPath}`),
    });
  },
  Effect.catchTags({
    PlatformError: (cause) => Effect.fail(new CertificateAuthorityError({ reason: cause.message })),
  }),
);

export class CertificateAuthority extends Context.Service<
  CertificateAuthority,
  {
    readonly certPem: string;
    readonly issueDevice: (device: {
      publicKeyPem: string;
      deviceId: string;
      userId: string;
    }) => Effect.Effect<{ certPem: string; expiresAt: DateTime.Utc }, InvalidDeviceKey>;
    readonly issueServer: (
      hostnames: ReadonlyArray<string>,
    ) => Effect.Effect<{ certPem: string; keyPem: string }>;
  }
>()("@t3tools/enterprise-control-plane/CertificateAuthority") {}

const make = Effect.gen(function* () {
  const config = yield* ControlPlaneConfig;
  const authority = yield* loadOrCreate(config.ca, config.organization);
  return CertificateAuthority.of({
    certPem: authority.certPem,
    issueDevice: Effect.fn("CertificateAuthority.issueDevice")(function* (device) {
      const issued = issueDeviceCertificatePem(authority, {
        ...device,
        days: config.deviceCertDays,
        nowMillis: yield* Clock.currentTimeMillis,
      });
      if (typeof issued === "string") return yield* new InvalidDeviceKey({ reason: issued });
      return issued;
    }),
    issueServer: Effect.fn("CertificateAuthority.issueServer")(function* (hostnames) {
      return issueServerCertificatePem(authority, {
        hostnames,
        days: 397,
        nowMillis: yield* Clock.currentTimeMillis,
      });
    }),
  });
});

export const layer = Layer.effect(CertificateAuthority, make);
