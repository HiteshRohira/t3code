/**
 * Crypto - random tokens, digests, and the RSA checks enrollment needs.
 *
 * @module Crypto
 */
// @effect-diagnostics-next-line nodeBuiltinImport:off -- RSA SPKI verification, SHA-256, and timing-safe compare have no service-free Effect equivalent.
import * as NodeCrypto from "node:crypto";

import * as SecureRandom from "effect/crypto/SecureRandom";
import * as Effect from "effect/Effect";
import * as Base64Url from "effect/encoding/Base64Url";

const encoder = new TextEncoder();

export const randomToken = (bytes = 32) =>
  Effect.sync(() => Base64Url.encode(SecureRandom.randomBytesUnsafe(bytes)));

export const uuid = Effect.sync(() => SecureRandom.uuidV4Unsafe());

export const sha256Hex = (text: string) =>
  NodeCrypto.createHash("sha256").update(text).digest("hex");

/** RFC 7636 S256 code challenge. */
export const pkceChallenge = (verifier: string) =>
  NodeCrypto.createHash("sha256").update(verifier).digest("base64url");

export function constantTimeEqual(a: string, b: string): boolean {
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  return left.length === right.length && NodeCrypto.timingSafeEqual(left, right);
}

/** Whether `proof` (base64url RSA-SHA256) signs `message` with the key in `publicKeyPem`. */
export function verifyRsaProof(publicKeyPem: string, message: string, proof: string): boolean {
  try {
    return NodeCrypto.verify(
      "sha256",
      encoder.encode(message),
      NodeCrypto.createPublicKey(publicKeyPem),
      Buffer.from(proof, "base64url"),
    );
  } catch {
    return false;
  }
}
