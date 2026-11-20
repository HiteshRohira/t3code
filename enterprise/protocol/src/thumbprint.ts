import * as NodeCrypto from "node:crypto";

/** RFC 8705 `x5t#S256`: base64url SHA-256 of the certificate's DER encoding. */
export function certificateThumbprint(
  certificate: string | Buffer | NodeCrypto.X509Certificate,
): string {
  const der =
    certificate instanceof NodeCrypto.X509Certificate
      ? certificate.raw
      : typeof certificate === "string"
        ? new NodeCrypto.X509Certificate(certificate).raw
        : certificate;
  return NodeCrypto.createHash("sha256").update(der).digest("base64url");
}
