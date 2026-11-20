/**
 * SigningKeys - the ES256 keys that sign leases and policies. Rotation is staged: `rotate` adds
 * a key that is published (gateways and the device trust block see it) but does not sign until
 * `activate`, so no device ever receives a token signed by a key it does not trust yet.
 *
 * @module SigningKeys
 */
import { generateSigningKey, SigningKey } from "@t3tools/enterprise-protocol/tokens";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";
import * as Path from "effect/Path";
import * as Schema from "effect/Schema";

import { ControlPlaneConfig } from "./Config.ts";
import * as Crypto from "./Crypto.ts";

export class SigningKeysError extends Schema.TaggedError<SigningKeysError>()("SigningKeysError", {
  reason: Schema.String,
}) {
  override get message(): string {
    return this.reason;
  }
}

const KeyFile = Schema.Struct({ active: Schema.String, keys: Schema.Array(SigningKey) });
type KeyFile = typeof KeyFile.Type;
const KeyFileJson = Schema.fromJsonString(KeyFile);
const decodeKeyFile = Schema.decodeUnknownEffect(KeyFileJson);
const encodeKeyFile = Schema.encodeEffect(KeyFileJson);

const KEEP = 4;

export interface KeySet {
  readonly active: SigningKey;
  /** Every published key: the active one, any staged one, and recent retired ones. */
  readonly all: ReadonlyArray<SigningKey>;
}

const toKeySet = (file: KeyFile): KeySet | undefined => {
  const active = file.keys.find((key) => key.kid === file.active);
  return active === undefined ? undefined : { active, all: file.keys };
};

const keyFilePath = Effect.fn("SigningKeys.path")(function* (dataDir: string) {
  const path = yield* Path.Path;
  return path.join(dataDir, "signing-keys.json");
});

const read = Effect.fn("SigningKeys.read")(function* (file: string) {
  const fs = yield* FileSystem.FileSystem;
  if (!(yield* fs.exists(file))) return undefined;
  const parsed = yield* decodeKeyFile(yield* fs.readFileString(file)).pipe(
    Effect.mapError(() => new SigningKeysError({ reason: `${file} is not a signing key file` })),
  );
  return parsed;
});

const write = Effect.fn("SigningKeys.write")(function* (file: string, contents: KeyFile) {
  const fs = yield* FileSystem.FileSystem;
  const text = yield* encodeKeyFile(contents);
  yield* fs.writeFileString(file, `${text}\n`, { mode: 0o600 });
});

export const loadOrCreate = Effect.fn("SigningKeys.loadOrCreate")(function* (dataDir: string) {
  const file = yield* keyFilePath(dataDir);
  const existing = yield* read(file);
  const set = existing === undefined ? undefined : toKeySet(existing);
  if (set !== undefined) return set;
  const key = yield* generateSigningKey(yield* Crypto.uuid);
  yield* write(file, { active: key.kid, keys: [key] });
  return { active: key, all: [key] } satisfies KeySet;
});

/** Stages a new key: published now, signing only after `activate`. */
export const rotate = Effect.fn("SigningKeys.rotate")(function* (dataDir: string) {
  const file = yield* keyFilePath(dataDir);
  const current = yield* read(file);
  if (current === undefined) return yield* new SigningKeysError({ reason: "no keys yet" });
  const key = yield* generateSigningKey(yield* Crypto.uuid);
  const active = current.keys.find((candidate) => candidate.kid === current.active);
  const others = current.keys.filter((candidate) => candidate.kid !== current.active);
  // The active key always survives the trim; the oldest retired keys go first.
  const keys = [key, ...(active === undefined ? [] : [active]), ...others].slice(0, KEEP);
  yield* write(file, { active: current.active, keys });
  return key;
});

/** Makes the newest staged key sign. Run only after devices trust it. */
export const activate = Effect.fn("SigningKeys.activate")(function* (dataDir: string) {
  const file = yield* keyFilePath(dataDir);
  const current = yield* read(file);
  const newest = current?.keys[0];
  if (current === undefined || newest === undefined) {
    return yield* new SigningKeysError({ reason: "no keys yet" });
  }
  if (newest.kid === current.active) {
    return yield* new SigningKeysError({ reason: "no staged key; run rotate-keys first" });
  }
  yield* write(file, { active: newest.kid, keys: current.keys });
  return newest;
});

export class SigningKeys extends Context.Service<SigningKeys, KeySet>()(
  "@t3tools/enterprise-control-plane/SigningKeys",
) {}

export const layer = Layer.effect(
  SigningKeys,
  Effect.gen(function* () {
    const config = yield* ControlPlaneConfig;
    return SigningKeys.of(yield* loadOrCreate(config.dataDir));
  }),
);
