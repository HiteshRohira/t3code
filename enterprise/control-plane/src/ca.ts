// The org certificate authority. node-forge builds certificates because Node's crypto can verify
// X.509 but cannot issue it; forge only handles RSA, so device and CA keys are RSA.
import * as NodeCrypto from "node:crypto";
import * as NodeFS from "node:fs";
import * as NodePath from "node:path";

import forge from "node-forge";

export interface CertificateAuthority {
  readonly certPem: string;
  readonly cert: forge.pki.Certificate;
  readonly key: forge.pki.rsa.PrivateKey;
}

const serialNumber = () => `01${NodeCrypto.randomBytes(15).toString("hex")}`;

const rsaKeyPem = (bits: number) =>
  NodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: bits,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

export function createCertificateAuthority(organization: string, years = 10) {
  const { publicKey, privateKey } = rsaKeyPem(3072);
  const key = forge.pki.privateKeyFromPem(privateKey);
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.publicKeyFromPem(publicKey);
  cert.serialNumber = serialNumber();
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + years * 365 * 24 * 3600 * 1000);
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

/** Loads the CA, creating one on first start when neither file exists. */
export function loadOrCreateCertificateAuthority(
  paths: { certPath: string; keyPath: string },
  organization: string,
): CertificateAuthority {
  const hasCert = NodeFS.existsSync(paths.certPath);
  const hasKey = NodeFS.existsSync(paths.keyPath);
  if (hasCert !== hasKey) {
    throw new Error(`CA certificate and key must both exist: ${paths.certPath}, ${paths.keyPath}`);
  }
  if (!hasCert) {
    const created = createCertificateAuthority(organization);
    NodeFS.mkdirSync(NodePath.dirname(paths.keyPath), { recursive: true, mode: 0o700 });
    NodeFS.writeFileSync(paths.keyPath, created.keyPem, { mode: 0o600 });
    NodeFS.writeFileSync(paths.certPath, created.certPem, { mode: 0o644 });
  }
  const certPem = NodeFS.readFileSync(paths.certPath, "utf8");
  return {
    certPem,
    cert: forge.pki.certificateFromPem(certPem),
    key: forge.pki.privateKeyFromPem(NodeFS.readFileSync(paths.keyPath, "utf8")),
  };
}

export const deviceUri = (deviceId: string) => `urn:t3-enterprise:device:${deviceId}`;
export const userUri = (userId: string) => `urn:t3-enterprise:user:${userId}`;

export class InvalidDeviceKey extends Error {
  override readonly name = "InvalidDeviceKey";
}

function rsaPublicKey(publicKeyPem: string): forge.pki.rsa.PublicKey {
  let key: forge.pki.PublicKey;
  try {
    key = forge.pki.publicKeyFromPem(publicKeyPem);
  } catch {
    throw new InvalidDeviceKey("device key must be an RSA public key in PEM (SPKI) form");
  }
  const rsa = key as forge.pki.rsa.PublicKey;
  if (rsa.n === undefined || rsa.n.bitLength() < 2048) {
    throw new InvalidDeviceKey("device key must be RSA with at least 2048 bits");
  }
  return rsa;
}

function issue(
  ca: CertificateAuthority,
  options: {
    publicKey: forge.pki.rsa.PublicKey;
    commonName: string;
    days: number;
    extensions: ReadonlyArray<object>;
  },
) {
  const cert = forge.pki.createCertificate();
  cert.publicKey = options.publicKey;
  cert.serialNumber = serialNumber();
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + options.days * 24 * 3600 * 1000);
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
  return { certPem: forge.pki.certificateToPem(cert), expiresAt: cert.validity.notAfter };
}

/** A client certificate naming the device and its user, usable only for TLS client auth. */
export function issueDeviceCertificate(
  ca: CertificateAuthority,
  device: { publicKeyPem: string; deviceId: string; userId: string; days: number },
) {
  return issue(ca, {
    publicKey: rsaPublicKey(device.publicKeyPem),
    commonName: device.deviceId,
    days: device.days,
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
export function issueServerCertificate(
  ca: CertificateAuthority,
  options: { hostnames: ReadonlyArray<string>; days: number },
) {
  const { publicKey, privateKey } = rsaKeyPem(2048);
  const issued = issue(ca, {
    publicKey: forge.pki.publicKeyFromPem(publicKey) as forge.pki.rsa.PublicKey,
    commonName: options.hostnames[0] ?? "localhost",
    days: options.days,
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
