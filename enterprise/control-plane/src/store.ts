import * as NodeCrypto from "node:crypto";
import * as NodeSqlite from "node:sqlite";

import {
  isRole,
  type AuditEvent,
  type Role,
  type UsageRecord,
} from "@t3tools/enterprise-protocol/wire";

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
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface Team {
  readonly name: string;
  readonly monthlyTokens: number | null;
  readonly models: ReadonlyArray<string> | null;
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
}

export interface StoredAuditEvent extends AuditEvent {
  readonly seq: number;
  readonly deviceId: string;
  readonly userId: string;
  readonly receivedAt: string;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name TEXT,
  external_id TEXT UNIQUE,
  active INTEGER NOT NULL DEFAULT 1,
  roles TEXT NOT NULL DEFAULT '[]',
  team TEXT,
  models TEXT,
  monthly_tokens INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS teams (
  name TEXT PRIMARY KEY,
  monthly_tokens INTEGER,
  models TEXT
);
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  thumbprint TEXT NOT NULL UNIQUE,
  hostname TEXT NOT NULL,
  platform TEXT NOT NULL,
  client_version TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  last_seen_at TEXT
);
CREATE TABLE IF NOT EXISTS enrollment_codes (
  code_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  expires_at TEXT NOT NULL,
  used_at TEXT
);
CREATE TABLE IF NOT EXISTS leases (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS usage (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  input_tokens INTEGER NOT NULL,
  output_tokens INTEGER NOT NULL,
  status INTEGER NOT NULL,
  occurred_at TEXT NOT NULL,
  month TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS usage_user_month ON usage(user_id, month);
CREATE TABLE IF NOT EXISTS audit (
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
);
CREATE INDEX IF NOT EXISTS audit_user ON audit(user_id, seq);
CREATE TABLE IF NOT EXISTS policy (
  version INTEGER PRIMARY KEY,
  document TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL
);
`;

type Row = Record<string, unknown>;

const text = (value: unknown) => (typeof value === "string" ? value : null);
const num = (value: unknown) =>
  typeof value === "number" ? value : typeof value === "bigint" ? Number(value) : null;
const parseList = (value: unknown): ReadonlyArray<string> | null => {
  if (typeof value !== "string") return null;
  const parsed: unknown = JSON.parse(value);
  return Array.isArray(parsed)
    ? parsed.filter((item): item is string => typeof item === "string")
    : null;
};

const toUser = (row: Row): User => ({
  id: String(row["id"]),
  email: String(row["email"]),
  name: text(row["name"]),
  externalId: text(row["external_id"]),
  active: row["active"] === 1 || row["active"] === 1n,
  roles: (parseList(row["roles"]) ?? []).filter(isRole),
  team: text(row["team"]),
  models: parseList(row["models"]),
  monthlyTokens: num(row["monthly_tokens"]),
  createdAt: String(row["created_at"]),
  updatedAt: String(row["updated_at"]),
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
});

export const monthOf = (date: Date) => date.toISOString().slice(0, 7);
const hashCode = (code: string) => NodeCrypto.createHash("sha256").update(code).digest("hex");

export class Store {
  readonly #db: NodeSqlite.DatabaseSync;

  constructor(path: string) {
    this.#db = new NodeSqlite.DatabaseSync(path);
    this.#db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;");
    this.#db.exec(SCHEMA);
  }

  close() {
    this.#db.close();
  }

  #transaction<A>(body: () => A): A {
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      const result = body();
      this.#db.exec("COMMIT");
      return result;
    } catch (error) {
      this.#db.exec("ROLLBACK");
      throw error;
    }
  }

  // Users

  userById(id: string): User | undefined {
    const row = this.#db.prepare("SELECT * FROM users WHERE id = ?").get(id) as Row | undefined;
    return row === undefined ? undefined : toUser(row);
  }

  userByEmail(email: string): User | undefined {
    const row = this.#db.prepare("SELECT * FROM users WHERE email = ?").get(email) as
      | Row
      | undefined;
    return row === undefined ? undefined : toUser(row);
  }

  userByExternalId(externalId: string): User | undefined {
    const row = this.#db.prepare("SELECT * FROM users WHERE external_id = ?").get(externalId) as
      | Row
      | undefined;
    return row === undefined ? undefined : toUser(row);
  }

  listUsers(): ReadonlyArray<User> {
    return (this.#db.prepare("SELECT * FROM users ORDER BY email").all() as Row[]).map(toUser);
  }

  createUser(input: {
    email: string;
    name?: string | null;
    externalId?: string | null;
    active?: boolean;
    roles: ReadonlyArray<Role>;
    team?: string | null;
  }): User {
    const now = new Date().toISOString();
    const id = NodeCrypto.randomUUID();
    this.#db
      .prepare(
        "INSERT INTO users (id, email, name, external_id, active, roles, team, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        id,
        input.email,
        input.name ?? null,
        input.externalId ?? null,
        input.active === false ? 0 : 1,
        JSON.stringify(input.roles),
        input.team ?? null,
        now,
        now,
      );
    return this.userById(id)!;
  }

  updateUser(
    id: string,
    patch: Partial<{
      email: string;
      name: string | null;
      externalId: string | null;
      active: boolean;
      roles: ReadonlyArray<Role>;
      team: string | null;
      models: ReadonlyArray<string> | null;
      monthlyTokens: number | null;
    }>,
  ): User | undefined {
    const columns: Array<[string, string | number | null]> = [];
    if (patch.email !== undefined) columns.push(["email", patch.email]);
    if (patch.name !== undefined) columns.push(["name", patch.name]);
    if (patch.externalId !== undefined) columns.push(["external_id", patch.externalId]);
    if (patch.active !== undefined) columns.push(["active", patch.active ? 1 : 0]);
    if (patch.roles !== undefined) columns.push(["roles", JSON.stringify(patch.roles)]);
    if (patch.team !== undefined) columns.push(["team", patch.team]);
    if (patch.models !== undefined) {
      columns.push(["models", patch.models === null ? null : JSON.stringify(patch.models)]);
    }
    if (patch.monthlyTokens !== undefined) columns.push(["monthly_tokens", patch.monthlyTokens]);
    if (columns.length > 0) {
      columns.push(["updated_at", new Date().toISOString()]);
      this.#db
        .prepare(
          `UPDATE users SET ${columns.map(([name]) => `${name} = ?`).join(", ")} WHERE id = ?`,
        )
        .run(...columns.map(([, value]) => value), id);
    }
    return this.userById(id);
  }

  /** Deactivating a user also revokes every device they enrolled. */
  deactivateUser(id: string): User | undefined {
    return this.#transaction(() => {
      this.updateUser(id, { active: false });
      this.#db
        .prepare("UPDATE devices SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL")
        .run(new Date().toISOString(), id);
      return this.userById(id);
    });
  }

  // Teams

  team(name: string): Team | undefined {
    const row = this.#db.prepare("SELECT * FROM teams WHERE name = ?").get(name) as Row | undefined;
    return row === undefined
      ? undefined
      : {
          name: String(row["name"]),
          monthlyTokens: num(row["monthly_tokens"]),
          models: parseList(row["models"]),
        };
  }

  listTeams(): ReadonlyArray<Team> {
    return (this.#db.prepare("SELECT * FROM teams ORDER BY name").all() as Row[]).map((row) => ({
      name: String(row["name"]),
      monthlyTokens: num(row["monthly_tokens"]),
      models: parseList(row["models"]),
    }));
  }

  upsertTeam(team: Team) {
    this.#db
      .prepare(
        "INSERT INTO teams (name, monthly_tokens, models) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET monthly_tokens = excluded.monthly_tokens, models = excluded.models",
      )
      .run(
        team.name,
        team.monthlyTokens,
        team.models === null ? null : JSON.stringify(team.models),
      );
  }

  deleteTeam(name: string) {
    this.#db.prepare("DELETE FROM teams WHERE name = ?").run(name);
  }

  // Enrollment

  createEnrollmentCode(userId: string, code: string, ttlSeconds: number) {
    this.#db
      .prepare("INSERT INTO enrollment_codes (code_hash, user_id, expires_at) VALUES (?, ?, ?)")
      .run(hashCode(code), userId, new Date(Date.now() + ttlSeconds * 1000).toISOString());
  }

  /** Spends a code once; undefined when it is unknown, spent, or expired. */
  redeemEnrollmentCode(code: string): string | undefined {
    return this.#transaction(() => {
      const row = this.#db
        .prepare("SELECT * FROM enrollment_codes WHERE code_hash = ?")
        .get(hashCode(code)) as Row | undefined;
      if (row === undefined || row["used_at"] !== null) return undefined;
      if (new Date(String(row["expires_at"])).getTime() < Date.now()) return undefined;
      this.#db
        .prepare("UPDATE enrollment_codes SET used_at = ? WHERE code_hash = ?")
        .run(new Date().toISOString(), hashCode(code));
      return String(row["user_id"]);
    });
  }

  // Devices

  createDevice(device: Omit<Device, "createdAt" | "revokedAt" | "lastSeenAt">): Device {
    this.#db
      .prepare(
        "INSERT INTO devices (id, user_id, thumbprint, hostname, platform, client_version, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        device.id,
        device.userId,
        device.thumbprint,
        device.hostname,
        device.platform,
        device.clientVersion,
        new Date().toISOString(),
        device.expiresAt,
      );
    return this.deviceById(device.id)!;
  }

  deviceById(id: string): Device | undefined {
    const row = this.#db.prepare("SELECT * FROM devices WHERE id = ?").get(id) as Row | undefined;
    return row === undefined ? undefined : toDevice(row);
  }

  deviceByThumbprint(thumbprint: string): Device | undefined {
    const row = this.#db.prepare("SELECT * FROM devices WHERE thumbprint = ?").get(thumbprint) as
      | Row
      | undefined;
    return row === undefined ? undefined : toDevice(row);
  }

  listDevices(userId?: string): ReadonlyArray<Device> {
    const rows =
      userId === undefined
        ? this.#db.prepare("SELECT * FROM devices ORDER BY created_at DESC").all()
        : this.#db
            .prepare("SELECT * FROM devices WHERE user_id = ? ORDER BY created_at DESC")
            .all(userId);
    return (rows as Row[]).map(toDevice);
  }

  revokeDevice(id: string) {
    this.#db
      .prepare("UPDATE devices SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
      .run(new Date().toISOString(), id);
  }

  touchDevice(id: string) {
    this.#db
      .prepare("UPDATE devices SET last_seen_at = ? WHERE id = ?")
      .run(new Date().toISOString(), id);
  }

  revokedDeviceIds(): ReadonlyArray<string> {
    // Expired devices fail TLS anyway; listing only unexpired revocations keeps this short.
    return (
      this.#db
        .prepare("SELECT id FROM devices WHERE revoked_at IS NOT NULL AND expires_at > ?")
        .all(new Date().toISOString()) as Row[]
    ).map((row) => String(row["id"]));
  }

  inactiveUserIds(): ReadonlyArray<string> {
    return (this.#db.prepare("SELECT id FROM users WHERE active = 0").all() as Row[]).map((row) =>
      String(row["id"]),
    );
  }

  // Leases

  recordLease(lease: { id: string; userId: string; deviceId: string; expiresAt: Date }) {
    this.#db
      .prepare(
        "INSERT INTO leases (id, user_id, device_id, issued_at, expires_at) VALUES (?, ?, ?, ?, ?)",
      )
      .run(
        lease.id,
        lease.userId,
        lease.deviceId,
        new Date().toISOString(),
        lease.expiresAt.toISOString(),
      );
  }

  // Usage

  recordUsage(records: ReadonlyArray<UsageRecord>) {
    const insert = this.#db.prepare(
      "INSERT OR IGNORE INTO usage (id, user_id, device_id, provider, model, input_tokens, output_tokens, status, occurred_at, month) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    );
    this.#transaction(() => {
      for (const record of records) {
        insert.run(
          record.id,
          record.userId,
          record.deviceId,
          record.provider,
          record.model,
          Math.max(0, Math.floor(record.inputTokens)),
          Math.max(0, Math.floor(record.outputTokens)),
          record.status,
          record.occurredAt,
          monthOf(new Date(record.occurredAt)),
        );
      }
    });
  }

  tokensUsed(userId: string, month: string): number {
    const row = this.#db
      .prepare(
        "SELECT COALESCE(SUM(input_tokens + output_tokens), 0) AS total FROM usage WHERE user_id = ? AND month = ?",
      )
      .get(userId, month) as Row;
    return num(row["total"]) ?? 0;
  }

  teamTokensUsed(team: string, month: string): number {
    const row = this.#db
      .prepare(
        "SELECT COALESCE(SUM(u.input_tokens + u.output_tokens), 0) AS total FROM usage u JOIN users p ON p.id = u.user_id WHERE p.team = ? AND u.month = ?",
      )
      .get(team, month) as Row;
    return num(row["total"]) ?? 0;
  }

  usageReport(month: string) {
    return (
      this.#db
        .prepare(
          `SELECT p.email AS email, p.team AS team, u.model AS model,
             SUM(u.input_tokens) AS input_tokens, SUM(u.output_tokens) AS output_tokens, COUNT(*) AS requests
           FROM usage u JOIN users p ON p.id = u.user_id
           WHERE u.month = ?
           GROUP BY p.email, p.team, u.model
           ORDER BY p.team, p.email, u.model`,
        )
        .all(month) as Row[]
    ).map((row) => ({
      email: String(row["email"]),
      team: text(row["team"]),
      model: String(row["model"]),
      inputTokens: num(row["input_tokens"]) ?? 0,
      outputTokens: num(row["output_tokens"]) ?? 0,
      requests: num(row["requests"]) ?? 0,
    }));
  }

  // Audit

  /** Stores events once per device and id; returns the ones that were new. */
  appendAudit(
    device: { id: string; userId: string },
    events: ReadonlyArray<AuditEvent>,
  ): ReadonlyArray<StoredAuditEvent> {
    const receivedAt = new Date().toISOString();
    const insert = this.#db.prepare(
      `INSERT OR IGNORE INTO audit (id, device_id, user_id, occurred_at, received_at, type, thread_id, project_id, provider, runtime_mode, detail)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    return this.#transaction(() =>
      events.flatMap((event) => {
        const result = insert.run(
          event.id,
          device.id,
          device.userId,
          event.occurredAt,
          receivedAt,
          event.type,
          event.threadId ?? null,
          event.projectId ?? null,
          event.provider ?? null,
          event.runtimeMode ?? null,
          event.detail === undefined ? null : JSON.stringify(event.detail),
        );
        if (Number(result.changes) === 0) return [];
        return [
          {
            ...event,
            seq: Number(result.lastInsertRowid),
            deviceId: device.id,
            userId: device.userId,
            receivedAt,
          },
        ];
      }),
    );
  }

  listAudit(options: {
    afterSeq?: number;
    userId?: string;
    limit: number;
  }): ReadonlyArray<StoredAuditEvent> {
    const rows = this.#db
      .prepare(
        `SELECT * FROM audit WHERE seq > ? AND (? IS NULL OR user_id = ?) ORDER BY seq LIMIT ?`,
      )
      .all(
        options.afterSeq ?? 0,
        options.userId ?? null,
        options.userId ?? null,
        options.limit,
      ) as Row[];
    return rows.map((row) => {
      const detail = text(row["detail"]);
      return {
        seq: num(row["seq"]) ?? 0,
        id: String(row["id"]),
        deviceId: String(row["device_id"]),
        userId: String(row["user_id"]),
        occurredAt: String(row["occurred_at"]),
        receivedAt: String(row["received_at"]),
        type: String(row["type"]),
        ...(text(row["thread_id"]) === null ? {} : { threadId: String(row["thread_id"]) }),
        ...(text(row["project_id"]) === null ? {} : { projectId: String(row["project_id"]) }),
        ...(text(row["provider"]) === null ? {} : { provider: String(row["provider"]) }),
        ...(text(row["runtime_mode"]) === null ? {} : { runtimeMode: String(row["runtime_mode"]) }),
        ...(detail === null ? {} : { detail: JSON.parse(detail) as Record<string, unknown> }),
      };
    });
  }

  // Policy

  currentPolicy():
    | { version: number; document: unknown; createdAt: string; createdBy: string }
    | undefined {
    const row = this.#db.prepare("SELECT * FROM policy ORDER BY version DESC LIMIT 1").get() as
      | Row
      | undefined;
    return row === undefined
      ? undefined
      : {
          version: num(row["version"]) ?? 0,
          document: JSON.parse(String(row["document"])) as unknown,
          createdAt: String(row["created_at"]),
          createdBy: String(row["created_by"]),
        };
  }

  publishPolicy(document: unknown, createdBy: string): number {
    return this.#transaction(() => {
      const version = (this.currentPolicy()?.version ?? 0) + 1;
      this.#db
        .prepare(
          "INSERT INTO policy (version, document, created_at, created_by) VALUES (?, ?, ?, ?)",
        )
        .run(version, JSON.stringify(document), new Date().toISOString(), createdBy);
      return version;
    });
  }
}
