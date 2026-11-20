import * as NodeCrypto from "node:crypto";
import * as NodeFS from "node:fs";

import { generateSigningKey, type SigningKey } from "@t3tools/enterprise-protocol/tokens";

/** The first key signs; the rest still verify, so a rotation never breaks unexpired tokens. */
export interface SigningKeys {
  readonly active: SigningKey;
  readonly all: ReadonlyArray<SigningKey>;
}

const read = (path: string): ReadonlyArray<SigningKey> =>
  NodeFS.existsSync(path) ? (JSON.parse(NodeFS.readFileSync(path, "utf8")) as SigningKey[]) : [];

const write = (path: string, keys: ReadonlyArray<SigningKey>) =>
  NodeFS.writeFileSync(path, `${JSON.stringify(keys, null, 2)}\n`, { mode: 0o600 });

export async function loadOrCreateSigningKeys(path: string): Promise<SigningKeys> {
  let keys = read(path);
  if (keys.length === 0) {
    keys = [await generateSigningKey(NodeCrypto.randomUUID())];
    write(path, keys);
  }
  return { active: keys[0]!, all: keys };
}

/** Adds a new signing key in front and keeps at most `keep` keys. */
export async function rotateSigningKeys(path: string, keep = 3): Promise<SigningKeys> {
  const keys = [await generateSigningKey(NodeCrypto.randomUUID()), ...read(path)].slice(0, keep);
  write(path, keys);
  return { active: keys[0]!, all: keys };
}
