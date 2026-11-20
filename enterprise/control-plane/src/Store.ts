/**
 * Store - the control plane's SQLite database: directory, devices, leases, usage, audit, policy.
 * A database failure fails the request it serves with a 500.
 *
 * @module Store
 */
import {
  isRole,
  type AuditEvent,
  type Heartbeat,
  type Role,
  type UsageRecord,
} from "@t3tools/enterprise-protocol/wire";
import * as NodeSqliteClient from "@t3tools/shared/nodeSqliteClient";
import * as Context from "effect/Context";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";
import * as Path from "effect/Path";
import * as Schema from "effect/Schema";
import * as SqlClient from "effect/sql/SqlClient";

import { ControlPlaneConfig } from "./Config.ts";

export interface User {
  readonly id: string;
  readonly email: string;
  readonly name: string | null;
  readonly externalId: string | null;
  readonly active: boolean;
  readonly roles: ReadonlyArray<Role>;
  readonly team: string | null;
  readonly models: ReadonlyArray<string> | null;
  readonly monthlyTokens: number | null;
  readonly region: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface Team {
  readonly name: string;
  readonly monthlyTokens: number | null;
  readonly models: ReadonlyArray<string> | null;
  readonly region: string | null;
}

export interface Device {
  readonly id: string;
  readonly userId: string;
  readonly thumbprint: string;
  readonly hostname: string;
  readonly platform: string;
  readonly clientVersion: string | null;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly revokedAt: string | null;
  readonly lastSeenAt: string | null;
  readonly heartbeat: (Heartbeat & { readonly receivedAt: string }) | null;
}

export interface Group {
  readonly id: string;
  readonly displayName: string;
  readonly externalId: string | null;
  readonly members: ReadonlyArray<string>;
}

export interface StoredAuditEvent extends AuditEvent {
  readonly seq: number;
  readonly deviceId: string;
  readonly userId: string;
  readonly receivedAt: string;
}

export interface StoredPolicy {
  readonly version: number;
  readonly document: unknown;
  readonly createdAt: string;
  readonly createdBy: string;
}

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name TEXT,
    external_id TEXT UNIQUE,
    active INTEGER NOT NULL DEFAULT 1,
    roles TEXT NOT NULL DEFAULT '[]',
    team TEXT,
    models TEXT,
    monthly_tokens INTEGER,
    region TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS teams (
    name TEXT PRIMARY KEY,
    monthly_tokens INTEGER,
    models TEXT,
    region TEXT
  )`,
  `CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL UNIQUE,
    external_id TEXT
  )`,
  `CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id),
    PRIMARY KEY (group_id, user_id)
  )`,
  `CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    thumbprint TEXT NOT NULL UNIQUE,
    hostname TEXT NOT NULL,
    platform TEXT NOT NULL,
    client_version TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    last_seen_at TEXT,
    heartbeat TEXT
  )`,
  `CREATE TABLE IF NOT EXISTS enrollment_codes (
    code_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    expires_at TEXT NOT NULL,
    used_at TEXT
  )`,
  `CREATE TABLE IF NOT EXISTS leases (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS usage (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    status INTEGER NOT NULL,
    redactions INTEGER NOT NULL DEFAULT 0,
    region TEXT,
    occurred_at TEXT NOT NULL,
    month TEXT NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS usage_user_month ON usage(user_id, month)`,
  `CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    type TEXT NOT NULL,
    thread_id TEXT,
    project_id TEXT,
    provider TEXT,
    runtime_mode TEXT,
    detail TEXT,
    UNIQUE (device_id, id)
  )`,
  `CREATE INDEX IF NOT EXISTS audit_user ON audit(user_id, seq)`,
  `CREATE INDEX IF NOT EXISTS audit_received ON audit(received_at)`,
  `CREATE TABLE IF NOT EXISTS legal_holds (
    user_id TEXT PRIMARY KEY REFERENCES users(id),
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS policy (
    version INTEGER PRIMARY KEY,
    document TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
  )`,
];

type Row = Record<string, unknown>;

const text = (value: unknown) => (typeof value === "string" ? value : null);
const num = (value: unknown) =>
  typeof value === "number" ? value : typeof value === "bigint" ? Number(value) : null;
const parseJson = (value: unknown): unknown => {
  if (typeof value !== "string") return null;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return null;
  }
};
const parseList = (value: unknown): ReadonlyArray<string> | null => {
  const parsed = parseJson(value);
  return Array.isArray(parsed)
    ? parsed.filter((item): item is string => typeof item === "string")
    : null;
};
const listColumn = (value: ReadonlyArray<string> | null) =>
  value === null ? null : JSON.stringify(value);

const toUser = (row: Row): User => ({
  id: String(row["id"]),
  email: String(row["email"]),
  name: text(row["name"]),
  externalId: text(row["external_id"]),
  active: num(row["active"]) === 1,
  roles: (parseList(row["roles"]) ?? []).filter(isRole),
  team: text(row["team"]),
  models: parseList(row["models"]),
  monthlyTokens: num(row["monthly_tokens"]),
  region: text(row["region"]),
  createdAt: String(row["created_at"]),
  updatedAt: String(row["updated_at"]),
});

const toTeam = (row: Row): Team => ({
  name: String(row["name"]),
  monthlyTokens: num(row["monthly_tokens"]),
  models: parseList(row["models"]),
  region: text(row["region"]),
});

const toDevice = (row: Row): Device => ({
  id: String(row["id"]),
  userId: String(row["user_id"]),
  thumbprint: String(row["thumbprint"]),
  hostname: String(row["hostname"]),
  platform: String(row["platform"]),
  clientVersion: text(row["client_version"]),
  createdAt: String(row["created_at"]),
  expiresAt: String(row["expires_at"]),
  revokedAt: text(row["revoked_at"]),
  lastSeenAt: text(row["last_seen_at"]),
  heartbeat: parseJson(row["heartbeat"]) as Device["heartbeat"],
});

const toAudit = (row: Row): StoredAuditEvent => {
  const optional = (column: string, key: keyof AuditEvent) => {
    const value = text(row[column]);
    return value === null ? {} : { [key]: value };
  };
  const detail = parseJson(row["detail"]);
  return {
    seq: num(row["seq"]) ?? 0,
    id: String(row["id"]),
    deviceId: String(row["device_id"]),
    userId: String(row["user_id"]),
    occurredAt: String(row["occurred_at"]),
    receivedAt: String(row["received_at"]),
    type: String(row["type"]),
    ...optional("thread_id", "threadId"),
    ...optional("project_id", "projectId"),
    ...optional("provider", "provider"),
    ...optional("runtime_mode", "runtimeMode"),
    ...(typeof detail === "object" && detail !== null
      ? { detail: detail as Record<string, unknown> }
      : {}),
  };
};

export const monthOf = (iso: string) => iso.slice(0, 7);

const nowIso = Effect.map(DateTime.now, DateTime.formatIso);
const encodeJsonText = Schema.encodeEffect(Schema.fromJsonString(Schema.Unknown));
// Columns hold plain data the control plane built itself, so encoding cannot fail.
const encodeJson = (value: unknown) => Effect.orDie(encodeJsonText(value));

export interface UserPatch {
  readonly email?: string;
  readonly name?: string | null;
  readonly externalId?: string | null;
  readonly active?: boolean;
  readonly roles?: ReadonlyArray<Role>;
  readonly team?: string | null;
  readonly models?: ReadonlyArray<string> | null;
  readonly monthlyTokens?: number | null;
  readonly region?: string | null;
}

const userColumns = (patch: UserPatch): Record<string, string | number | null> => {
  const columns: Record<string, string | number | null> = {};
  if (patch.email !== undefined) columns["email"] = patch.email;
  if (patch.name !== undefined) columns["name"] = patch.name;
  if (patch.externalId !== undefined) columns["external_id"] = patch.externalId;
  if (patch.active !== undefined) columns["active"] = patch.active ? 1 : 0;
  if (patch.roles !== undefined) columns["roles"] = JSON.stringify(patch.roles);
  if (patch.team !== undefined) columns["team"] = patch.team;
  if (patch.models !== undefined) columns["models"] = listColumn(patch.models);
  if (patch.monthlyTokens !== undefined) columns["monthly_tokens"] = patch.monthlyTokens;
  if (patch.region !== undefined) columns["region"] = patch.region;
  return columns;
};

const make = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;
  yield* sql`PRAGMA foreign_keys = ON`;
  yield* sql`PRAGMA busy_timeout = 5000`;
  for (const statement of SCHEMA) yield* sql.unsafe(statement);

  const one = <A>(rows: ReadonlyArray<Row>, map: (row: Row) => A): A | undefined => {
    const row = rows[0];
    return row === undefined ? undefined : map(row);
  };

  const userById = (id: string) =>
    Effect.map(sql<Row>`SELECT * FROM users WHERE id = ${id}`, (rows) => one(rows, toUser));
  const deviceById = (id: string) =>
    Effect.map(sql<Row>`SELECT * FROM devices WHERE id = ${id}`, (rows) => one(rows, toDevice));
  const currentPolicy = Effect.map(
    sql<Row>`SELECT * FROM policy ORDER BY version DESC LIMIT 1`,
    (rows) =>
      one(rows, (row): StoredPolicy => ({
        version: num(row["version"]) ?? 0,
        document: parseJson(row["document"]),
        createdAt: String(row["created_at"]),
        createdBy: String(row["created_by"]),
      })),
  );

  const updateUser = Effect.fn("Store.updateUser")(function* (id: string, patch: UserPatch) {
    const columns = userColumns(patch);
    if (Object.keys(columns).length > 0) {
      columns["updated_at"] = yield* nowIso;
      yield* sql`UPDATE users SET ${sql.update(columns)} WHERE id = ${id}`;
    }
    return yield* userById(id);
  });

  const groupsOf = (userId: string) =>
    Effect.map(
      sql<Row>`SELECT g.display_name AS name FROM groups g JOIN group_members m ON m.group_id = g.id WHERE m.user_id = ${userId}`,
      (rows) => rows.map((row) => String(row["name"])),
    );

  const groupById = Effect.fn("Store.groupById")(function* (id: string) {
    const group = one(yield* sql<Row>`SELECT * FROM groups WHERE id = ${id}`, (row) => row);
    if (group === undefined) return undefined;
    const members = yield* sql<Row>`SELECT user_id FROM group_members WHERE group_id = ${id}`;
    return {
      id: String(group["id"]),
      displayName: String(group["display_name"]),
      externalId: text(group["external_id"]),
      members: members.map((row) => String(row["user_id"])),
    } satisfies Group;
  });

  const service = {
    userById,
    userByEmail: (email: string) =>
      Effect.map(sql<Row>`SELECT * FROM users WHERE email = ${email}`, (rows) => one(rows, toUser)),
    userByExternalId: (externalId: string) =>
      Effect.map(sql<Row>`SELECT * FROM users WHERE external_id = ${externalId}`, (rows) =>
        one(rows, toUser),
      ),
    listUsers: Effect.map(sql<Row>`SELECT * FROM users ORDER BY email`, (rows) => rows.map(toUser)),
    createUser: Effect.fn("Store.createUser")(function* (input: {
      id: string;
      email: string;
      name?: string | null;
      externalId?: string | null;
      active?: boolean;
      roles: ReadonlyArray<Role>;
      team?: string | null;
      region?: string | null;
    }) {
      const now = yield* nowIso;
      yield* sql`INSERT INTO users ${sql.insert({
        id: input.id,
        email: input.email,
        name: input.name ?? null,
        external_id: input.externalId ?? null,
        active: input.active === false ? 0 : 1,
        roles: yield* encodeJson(input.roles),
        team: input.team ?? null,
        region: input.region ?? null,
        created_at: now,
        updated_at: now,
      })}`;
      return (yield* userById(input.id))!;
    }),
    updateUser,
    /** Deactivating a user also revokes every device they enrolled. */
    deactivateUser: (id: string) =>
      sql.withTransaction(
        Effect.gen(function* () {
          yield* updateUser(id, { active: false });
          const now = yield* nowIso;
          yield* sql`UPDATE devices SET revoked_at = ${now} WHERE user_id = ${id} AND revoked_at IS NULL`;
          return yield* userById(id);
        }),
      ),

    team: (name: string) =>
      Effect.map(sql<Row>`SELECT * FROM teams WHERE name = ${name}`, (rows) => one(rows, toTeam)),
    listTeams: Effect.map(sql<Row>`SELECT * FROM teams ORDER BY name`, (rows) => rows.map(toTeam)),
    upsertTeam: (team: Team) =>
      sql`INSERT INTO teams (name, monthly_tokens, models, region) VALUES (${team.name}, ${team.monthlyTokens}, ${listColumn(team.models)}, ${team.region})
          ON CONFLICT(name) DO UPDATE SET monthly_tokens = excluded.monthly_tokens, models = excluded.models, region = excluded.region`.pipe(
        Effect.asVoid,
      ),
    deleteTeam: (name: string) => sql`DELETE FROM teams WHERE name = ${name}`.pipe(Effect.asVoid),

    groupsOf,
    groupById,
    groupByName: (name: string) =>
      Effect.flatMap(sql<Row>`SELECT id FROM groups WHERE display_name = ${name}`, (rows) =>
        rows[0] === undefined ? Effect.undefined : groupById(String(rows[0]["id"])),
      ),
    listGroups: Effect.flatMap(sql<Row>`SELECT id FROM groups ORDER BY display_name`, (rows) =>
      Effect.forEach(rows, (row) => groupById(String(row["id"]))).pipe(
        Effect.map((groups) => groups.filter((group) => group !== undefined)),
      ),
    ),
    createGroup: (group: { id: string; displayName: string; externalId: string | null }) =>
      sql`INSERT INTO groups (id, display_name, external_id) VALUES (${group.id}, ${group.displayName}, ${group.externalId})`.pipe(
        Effect.asVoid,
      ),
    renameGroup: (id: string, displayName: string) =>
      sql`UPDATE groups SET display_name = ${displayName} WHERE id = ${id}`.pipe(Effect.asVoid),
    deleteGroup: (id: string) => sql`DELETE FROM groups WHERE id = ${id}`.pipe(Effect.asVoid),
    setGroupMembers: (id: string, userIds: ReadonlyArray<string>) =>
      sql.withTransaction(
        Effect.gen(function* () {
          yield* sql`DELETE FROM group_members WHERE group_id = ${id}`;
          for (const userId of new Set(userIds)) {
            yield* sql`INSERT OR IGNORE INTO group_members (group_id, user_id) SELECT ${id}, id FROM users WHERE id = ${userId}`;
          }
        }),
      ),
    addGroupMembers: (id: string, userIds: ReadonlyArray<string>) =>
      Effect.forEach(
        userIds,
        (userId) =>
          sql`INSERT OR IGNORE INTO group_members (group_id, user_id) SELECT ${id}, id FROM users WHERE id = ${userId}`,
        { discard: true },
      ),
    removeGroupMembers: (id: string, userIds: ReadonlyArray<string>) =>
      Effect.forEach(
        userIds,
        (userId) => sql`DELETE FROM group_members WHERE group_id = ${id} AND user_id = ${userId}`,
        { discard: true },
      ),

    createEnrollmentCode: (userId: string, codeHash: string, expiresAt: string) =>
      sql`INSERT INTO enrollment_codes (code_hash, user_id, expires_at) VALUES (${codeHash}, ${userId}, ${expiresAt})`.pipe(
        Effect.asVoid,
      ),
    /** Spends a code once; undefined when it is unknown, spent, or expired. */
    redeemEnrollmentCode: (codeHash: string) =>
      sql.withTransaction(
        Effect.gen(function* () {
          const now = yield* nowIso;
          const rows =
            yield* sql<Row>`SELECT * FROM enrollment_codes WHERE code_hash = ${codeHash}`;
          const row = rows[0];
          if (row === undefined || row["used_at"] !== null) return undefined;
          if (String(row["expires_at"]) < now) return undefined;
          yield* sql`UPDATE enrollment_codes SET used_at = ${now} WHERE code_hash = ${codeHash}`;
          return String(row["user_id"]);
        }),
      ),

    createDevice: Effect.fn("Store.createDevice")(function* (device: {
      id: string;
      userId: string;
      thumbprint: string;
      hostname: string;
      platform: string;
      clientVersion: string | null;
      expiresAt: string;
    }) {
      yield* sql`INSERT INTO devices ${sql.insert({
        id: device.id,
        user_id: device.userId,
        thumbprint: device.thumbprint,
        hostname: device.hostname,
        platform: device.platform,
        client_version: device.clientVersion,
        created_at: yield* nowIso,
        expires_at: device.expiresAt,
      })}`;
      return (yield* deviceById(device.id))!;
    }),
    deviceById,
    deviceByThumbprint: (thumbprint: string) =>
      Effect.map(sql<Row>`SELECT * FROM devices WHERE thumbprint = ${thumbprint}`, (rows) =>
        one(rows, toDevice),
      ),
    listDevices: (userId?: string) =>
      Effect.map(
        userId === undefined
          ? sql<Row>`SELECT * FROM devices ORDER BY created_at DESC`
          : sql<Row>`SELECT * FROM devices WHERE user_id = ${userId} ORDER BY created_at DESC`,
        (rows) => rows.map(toDevice),
      ),
    revokeDevice: (id: string) =>
      Effect.flatMap(nowIso, (now) =>
        sql`UPDATE devices SET revoked_at = ${now} WHERE id = ${id} AND revoked_at IS NULL`.pipe(
          Effect.asVoid,
        ),
      ),
    touchDevice: (id: string) =>
      Effect.flatMap(nowIso, (now) =>
        sql`UPDATE devices SET last_seen_at = ${now} WHERE id = ${id}`.pipe(Effect.asVoid),
      ),
    recordHeartbeat: Effect.fn("Store.recordHeartbeat")(function* (
      id: string,
      heartbeat: Heartbeat,
    ) {
      const now = yield* nowIso;
      const stored = yield* encodeJson({ ...heartbeat, receivedAt: now });
      yield* sql`UPDATE devices SET last_seen_at = ${now}, heartbeat = ${stored}, client_version = ${heartbeat.clientVersion} WHERE id = ${id}`;
    }),
    /** Expired devices fail TLS anyway; listing only unexpired revocations keeps this short. */
    revokedDeviceIds: Effect.flatMap(nowIso, (now) =>
      Effect.map(
        sql<Row>`SELECT id FROM devices WHERE revoked_at IS NOT NULL AND expires_at > ${now}`,
        (rows) => rows.map((row) => String(row["id"])),
      ),
    ),
    inactiveUserIds: Effect.map(sql<Row>`SELECT id FROM users WHERE active = 0`, (rows) =>
      rows.map((row) => String(row["id"])),
    ),

    recordLease: (lease: { id: string; userId: string; deviceId: string; expiresAt: string }) =>
      Effect.flatMap(nowIso, (now) =>
        sql`INSERT INTO leases (id, user_id, device_id, issued_at, expires_at) VALUES (${lease.id}, ${lease.userId}, ${lease.deviceId}, ${now}, ${lease.expiresAt})`.pipe(
          Effect.asVoid,
        ),
      ),

    recordUsage: (records: ReadonlyArray<UsageRecord>) =>
      sql.withTransaction(
        Effect.forEach(
          records,
          (record) =>
            sql`INSERT OR IGNORE INTO usage ${sql.insert({
              id: record.id,
              user_id: record.userId,
              device_id: record.deviceId,
              provider: record.provider,
              model: record.model,
              input_tokens: record.inputTokens,
              output_tokens: record.outputTokens,
              status: record.status,
              redactions: record.redactions ?? 0,
              region: record.region ?? null,
              occurred_at: record.occurredAt,
              month: monthOf(record.occurredAt),
            })}`,
          { discard: true },
        ),
      ),
    tokensUsed: (userId: string, month: string) =>
      Effect.map(
        sql<Row>`SELECT COALESCE(SUM(input_tokens + output_tokens), 0) AS total FROM usage WHERE user_id = ${userId} AND month = ${month}`,
        (rows) => num(rows[0]?.["total"]) ?? 0,
      ),
    teamTokensUsed: (team: string, month: string) =>
      Effect.map(
        sql<Row>`SELECT COALESCE(SUM(u.input_tokens + u.output_tokens), 0) AS total FROM usage u JOIN users p ON p.id = u.user_id WHERE p.team = ${team} AND u.month = ${month}`,
        (rows) => num(rows[0]?.["total"]) ?? 0,
      ),
    usageReport: (month: string) =>
      Effect.map(
        sql<Row>`SELECT p.email AS email, p.team AS team, u.model AS model, u.region AS region,
             SUM(u.input_tokens) AS input_tokens, SUM(u.output_tokens) AS output_tokens,
             SUM(u.redactions) AS redactions, COUNT(*) AS requests
           FROM usage u JOIN users p ON p.id = u.user_id
           WHERE u.month = ${month}
           GROUP BY p.email, p.team, u.model, u.region
           ORDER BY p.team, p.email, u.model`,
        (rows) =>
          rows.map((row) => ({
            email: String(row["email"]),
            team: text(row["team"]),
            model: String(row["model"]),
            region: text(row["region"]),
            inputTokens: num(row["input_tokens"]) ?? 0,
            outputTokens: num(row["output_tokens"]) ?? 0,
            redactions: num(row["redactions"]) ?? 0,
            requests: num(row["requests"]) ?? 0,
          })),
      ),

    /** Stores events once per device and id; returns the ones that were new. */
    appendAudit: (device: { id: string; userId: string }, events: ReadonlyArray<AuditEvent>) =>
      sql.withTransaction(
        Effect.gen(function* () {
          const receivedAt = yield* nowIso;
          const stored: Array<StoredAuditEvent> = [];
          for (const event of events) {
            const rows = yield* sql<Row>`INSERT OR IGNORE INTO audit ${sql.insert({
              id: event.id,
              device_id: device.id,
              user_id: device.userId,
              occurred_at: event.occurredAt,
              received_at: receivedAt,
              type: event.type,
              thread_id: event.threadId ?? null,
              project_id: event.projectId ?? null,
              provider: event.provider ?? null,
              runtime_mode: event.runtimeMode ?? null,
              detail: event.detail === undefined ? null : yield* encodeJson(event.detail),
            })} RETURNING seq`;
            const seq = num(rows[0]?.["seq"]);
            if (seq !== null) {
              stored.push({
                ...event,
                seq,
                deviceId: device.id,
                userId: device.userId,
                receivedAt,
              });
            }
          }
          return stored;
        }),
      ),
    listAudit: (options: {
      afterSeq?: number;
      userIds?: ReadonlyArray<string>;
      types?: ReadonlyArray<string>;
      limit: number;
    }) =>
      Effect.map(
        sql<Row>`SELECT * FROM audit WHERE ${sql.and([
          sql`seq > ${options.afterSeq ?? 0}`,
          ...(options.userIds === undefined ? [] : [sql.in("user_id", options.userIds)]),
          ...(options.types === undefined ? [] : [sql.in("type", options.types)]),
        ])} ORDER BY seq LIMIT ${options.limit}`,
        (rows) => rows.map(toAudit),
      ),
    latestAudit: (options: { userIds: ReadonlyArray<string>; limit: number }) =>
      Effect.map(
        sql<Row>`SELECT * FROM audit WHERE ${sql.in("user_id", options.userIds)} ORDER BY seq DESC LIMIT ${options.limit}`,
        (rows) => rows.map(toAudit),
      ),

    legalHolds: Effect.map(sql<Row>`SELECT * FROM legal_holds ORDER BY created_at`, (rows) =>
      rows.map((row) => ({
        userId: String(row["user_id"]),
        reason: String(row["reason"]),
        createdAt: String(row["created_at"]),
        createdBy: String(row["created_by"]),
      })),
    ),
    placeLegalHold: (userId: string, reason: string, createdBy: string) =>
      Effect.flatMap(nowIso, (now) =>
        sql`INSERT INTO legal_holds (user_id, reason, created_at, created_by) VALUES (${userId}, ${reason}, ${now}, ${createdBy})
            ON CONFLICT(user_id) DO UPDATE SET reason = excluded.reason`.pipe(Effect.asVoid),
      ),
    releaseLegalHold: (userId: string) =>
      sql`DELETE FROM legal_holds WHERE user_id = ${userId}`.pipe(Effect.asVoid),
    /** Deletes rows older than each cutoff, except audit for users on legal hold. */
    purge: (cutoffs: { audit?: string; usage?: string; leases?: string }) =>
      sql.withTransaction(
        Effect.gen(function* () {
          let deleted = 0;
          if (cutoffs.audit !== undefined) {
            const rows = yield* sql<Row>`DELETE FROM audit WHERE received_at < ${cutoffs.audit}
              AND user_id NOT IN (SELECT user_id FROM legal_holds) RETURNING seq`;
            deleted += rows.length;
          }
          if (cutoffs.usage !== undefined) {
            const rows = yield* sql<Row>`DELETE FROM usage WHERE occurred_at < ${cutoffs.usage}
              AND user_id NOT IN (SELECT user_id FROM legal_holds) RETURNING id`;
            deleted += rows.length;
          }
          if (cutoffs.leases !== undefined) {
            const rows =
              yield* sql<Row>`DELETE FROM leases WHERE expires_at < ${cutoffs.leases} RETURNING id`;
            deleted += rows.length;
          }
          const codes =
            yield* sql<Row>`DELETE FROM enrollment_codes WHERE expires_at < ${yield* nowIso} RETURNING code_hash`;
          return deleted + codes.length;
        }),
      ),

    currentPolicy,
    publishPolicy: (document: unknown, createdBy: string) =>
      sql.withTransaction(
        Effect.gen(function* () {
          const version = ((yield* currentPolicy)?.version ?? 0) + 1;
          const stored = yield* encodeJson(document);
          yield* sql`INSERT INTO policy (version, document, created_at, created_by) VALUES (${version}, ${stored}, ${yield* nowIso}, ${createdBy})`;
          return version;
        }),
      ),
  };

  return service;
});

export class Store extends Context.Service<Store, Effect.Success<typeof make>>()(
  "@t3tools/enterprise-control-plane/Store",
) {}

export const layer = Layer.effect(Store, make);

/** The control plane's database file in `dataDir`, or memory for tests. */
export const layerSqlite = (filename: string) =>
  NodeSqliteClient.layer({
    filename,
    spanAttributes: { "db.name": "control-plane", "service.name": "t3-enterprise-control-plane" },
  });

export const layerConfig = Layer.unwrap(
  Effect.gen(function* () {
    const config = yield* ControlPlaneConfig;
    const fs = yield* FileSystem.FileSystem;
    const path = yield* Path.Path;
    yield* fs.makeDirectory(config.dataDir, { recursive: true, mode: 0o700 });
    return layer.pipe(
      Layer.provide(layerSqlite(path.join(config.dataDir, "control-plane.sqlite"))),
    );
  }),
);
