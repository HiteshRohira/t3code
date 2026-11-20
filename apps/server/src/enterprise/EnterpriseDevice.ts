/**
 * EnterpriseDevice - this user's enrollment on disk: the device key and certificate the org CA
 * issued, the signed policy last fetched, and the audit cursor. Only the user's own account can
 * read the key; the control plane never sees it.
 *
 * @module EnterpriseDevice
 */
import * as HostProcess from "@t3tools/shared/HostProcess";
import * as Config from "effect/Config";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Option from "effect/Option";
import * as Path from "effect/Path";
import * as Schema from "effect/Schema";

export interface EnterpriseStatePaths {
  readonly dir: string;
  readonly key: string;
  readonly certificate: string;
  readonly device: string;
  readonly policy: string;
  readonly auditCursor: string;
  readonly status: string;
}

/** `T3CODE_ENTERPRISE_STATE_DIR` relocates it; the files are the user's own either way. */
export const statePaths = Effect.gen(function* () {
  const override = yield* Config.option(Config.String("T3CODE_ENTERPRISE_STATE_DIR")).pipe(
    Effect.orElseSucceed(() => Option.none<string>()),
  );
  const path = yield* Path.Path;
  const dir = Option.isSome(override)
    ? override.value
    : path.join(yield* HostProcess.HomeDirectory, ".t3", "enterprise");
  return {
    dir,
    key: path.join(dir, "device.key"),
    certificate: path.join(dir, "device.crt"),
    device: path.join(dir, "device.json"),
    policy: path.join(dir, "policy.jws"),
    auditCursor: path.join(dir, "audit-cursor"),
    status: path.join(dir, "status.json"),
  } satisfies EnterpriseStatePaths;
});

export const DeviceRecord = Schema.Struct({
  deviceId: Schema.String,
  controlPlaneUrl: Schema.String,
  email: Schema.String,
  roles: Schema.Array(Schema.String),
  enrolledAt: Schema.String,
  expiresAt: Schema.String,
});
export type DeviceRecord = typeof DeviceRecord.Type;

export interface DeviceIdentity {
  readonly record: DeviceRecord;
  readonly keyPem: string;
  readonly certificatePem: string;
}

const decodeRecord = Schema.decodeUnknownEffect(Schema.fromJsonString(DeviceRecord));
const encodeRecord = Schema.encodeEffect(Schema.fromJsonString(DeviceRecord));

/** The enrollment for `controlPlaneUrl`, or none when this user has not enrolled with it. */
export const readIdentity = Effect.fn("EnterpriseDevice.readIdentity")(function* (
  paths: EnterpriseStatePaths,
  controlPlaneUrl: string,
) {
  const fs = yield* FileSystem.FileSystem;
  const read = (path: string) =>
    fs.readFileString(path).pipe(
      Effect.asSome,
      Effect.orElseSucceed(() => Option.none<string>()),
    );
  const [record, keyPem, certificatePem] = yield* Effect.all([
    read(paths.device),
    read(paths.key),
    read(paths.certificate),
  ]);
  if (Option.isNone(record) || Option.isNone(keyPem) || Option.isNone(certificatePem)) {
    return Option.none<DeviceIdentity>();
  }
  const decoded = yield* decodeRecord(record.value).pipe(Effect.option);
  if (Option.isNone(decoded) || decoded.value.controlPlaneUrl !== controlPlaneUrl) {
    return Option.none<DeviceIdentity>();
  }
  return Option.some<DeviceIdentity>({
    record: decoded.value,
    keyPem: keyPem.value,
    certificatePem: certificatePem.value,
  });
});

export const writeIdentity = Effect.fn("EnterpriseDevice.writeIdentity")(function* (
  paths: EnterpriseStatePaths,
  identity: DeviceIdentity,
) {
  const fs = yield* FileSystem.FileSystem;
  yield* fs.makeDirectory(paths.dir, { recursive: true, mode: 0o700 });
  yield* fs.writeFileString(paths.key, identity.keyPem, { mode: 0o600 });
  yield* fs.chmod(paths.key, 0o600);
  yield* fs.writeFileString(paths.certificate, identity.certificatePem, { mode: 0o644 });
  yield* fs.writeFileString(paths.device, `${yield* encodeRecord(identity.record)}\n`, {
    mode: 0o600,
  });
});

/** Forgets the enrollment and everything fetched with it. */
export const removeIdentity = Effect.fn("EnterpriseDevice.removeIdentity")(function* (
  paths: EnterpriseStatePaths,
) {
  const fs = yield* FileSystem.FileSystem;
  yield* Effect.forEach(
    [paths.key, paths.certificate, paths.device, paths.policy, paths.auditCursor, paths.status],
    (path) => fs.remove(path, { force: true }),
    { discard: true },
  );
});

export const readText = Effect.fn("EnterpriseDevice.readText")(function* (path: string) {
  const fs = yield* FileSystem.FileSystem;
  return yield* fs.readFileString(path).pipe(
    Effect.asSome,
    Effect.orElseSucceed(() => Option.none<string>()),
  );
});

/** Replaces `path` through a temporary file so a reader never sees half of it. */
export const writeTextAtomically = Effect.fn("EnterpriseDevice.writeTextAtomically")(function* (
  path: string,
  text: string,
) {
  const fs = yield* FileSystem.FileSystem;
  yield* fs.makeDirectory((yield* Path.Path).dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.tmp`;
  yield* fs.writeFileString(temporary, text, { mode: 0o600 });
  yield* fs.rename(temporary, path);
});
