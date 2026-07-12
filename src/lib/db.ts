import Database from "better-sqlite3";
import path from "path";
import fs from "fs";
import bcrypt from "bcryptjs";

const DATA_DIR = path.join(process.cwd(), "data");

interface UserRow {
  id: string;
  username: string;
  password_hash: string;
  role: string;
  must_change_pwd: number;
  created_at: string;
}

interface User {
  id: string;
  username: string;
  passwordHash: string;
  role: "admin" | "analyst";
  mustChangePwd: boolean;
  createdAt: string;
}

let db: Database.Database | null = null;

export function getDb(): Database.Database {
  if (db) return db;

  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    const dbPath = path.join(DATA_DIR, "nids.db");
    db = new Database(dbPath);
    db.pragma("journal_mode = WAL");
    db.pragma("foreign_keys = ON");
  } catch {
    db = new Database(":memory:");
    db.pragma("foreign_keys = ON");
  }

  initializeSchema();
  seedDefaults();

  return db;
}

function initializeSchema(): void {
  if (!db) return;

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'analyst',
      must_change_pwd INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      action TEXT NOT NULL,
      details TEXT,
      ip TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS persisted_packets (
      id TEXT PRIMARY KEY,
      timestamp INTEGER NOT NULL,
      src_ip TEXT NOT NULL,
      dst_ip TEXT NOT NULL,
      src_port INTEGER NOT NULL,
      dst_port INTEGER NOT NULL,
      protocol TEXT NOT NULL,
      length INTEGER NOT NULL,
      ttl INTEGER NOT NULL DEFAULT 64,
      flags TEXT DEFAULT '[]',
      payload TEXT DEFAULT '',
      is_malicious INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS persisted_alerts (
      id TEXT PRIMARY KEY,
      timestamp INTEGER NOT NULL,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      severity TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'new',
      packet_id TEXT,
      rule_id TEXT,
      source_ip TEXT,
      destination_ip TEXT,
      protocol TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
}

async function seedDefaults(): Promise<void> {
  if (!db) return;

  const count = db.prepare("SELECT COUNT(*) as cnt FROM users").get() as { cnt: number };
  if (count.cnt > 0) return;

  const hash = await bcrypt.hash("admin123", 12);
  db.prepare(
    "INSERT INTO users (id, username, password_hash, role, must_change_pwd) VALUES (?, ?, ?, ?, ?)"
  ).run("user_admin_001", "admin", hash, "admin", 1);

  db.prepare(
    "INSERT INTO settings (key, value) VALUES (?, ?)"
  ).run("jwt_secret", [...crypto.getRandomValues(new Uint8Array(32))]
    .map((b) => b.toString(16).padStart(2, "0")).join(""));

  console.log("[DB] Seeded default admin user (password: admin123, must change on first login)");
}

export async function createUser(
  username: string,
  password: string,
  role: "admin" | "analyst" = "analyst"
): Promise<User> {
  const database = getDb();
  const hash = await bcrypt.hash(password, 12);
  const id = `user_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;

  database.prepare(
    "INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)"
  ).run(id, username, hash, role);

  return {
    id,
    username,
    passwordHash: hash,
    role,
    mustChangePwd: false,
    createdAt: new Date().toISOString(),
  };
}

export function getUserByUsername(username: string): User | null {
  const database = getDb();
  const row = database.prepare("SELECT * FROM users WHERE username = ?").get(username) as
    | UserRow
    | undefined;

  if (!row) return null;

  return {
    id: row.id,
    username: row.username,
    passwordHash: row.password_hash,
    role: row.role as "admin" | "analyst",
    mustChangePwd: row.must_change_pwd === 1,
    createdAt: row.created_at,
  };
}

export function updateUserPassword(id: string, newHash: string): void {
  const database = getDb();
  database.prepare("UPDATE users SET password_hash = ?, must_change_pwd = 0 WHERE id = ?").run(newHash, id);
}

export function auditLog(userId: string, action: string, details: string, ip: string): void {
  const database = getDb();
  database.prepare(
    "INSERT INTO audit_log (user_id, action, details, ip) VALUES (?, ?, ?, ?)"
  ).run(userId, action, details, ip);
}

export function getAuditLogs(limit = 100): unknown[] {
  const database = getDb();
  return database.prepare("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?").all(limit);
}

export function getSetting(key: string): string | null {
  const database = getDb();
  const row = database.prepare("SELECT value FROM settings WHERE key = ?").get(key) as
    | { value: string }
    | undefined;
  return row?.value ?? null;
}

export function setSetting(key: string, value: string): void {
  const database = getDb();
  database.prepare(
    "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at"
  ).run(key, value);
}

export { DATA_DIR };
