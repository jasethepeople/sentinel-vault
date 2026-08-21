import { index, int, longtext, mysqlEnum, mysqlTable, text, timestamp, uniqueIndex, varchar } from "drizzle-orm/mysql-core";

/**
 * Core user table backing auth flow.
 * Extend this file with additional tables as your product grows.
 * Columns use camelCase to match both database fields and generated types.
 */
export const users = mysqlTable("users", {
  /**
   * Surrogate primary key. Auto-incremented numeric value managed by the database.
   * Use this for relations between tables.
   */
  id: int("id").autoincrement().primaryKey(),
  /** Manus OAuth identifier (openId) returned from the OAuth callback. Unique per user. */
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;

export const escalationStates = ["ARMED", "ALERT", "CRITICAL", "TRIGGERED"] as const;
export const auditEventKinds = ["CHECK_IN", "STATE_TRANSITION", "CONFIG_UPDATED", "PANIC_WIPE", "VAULT_CREATED", "VAULT_DELETED"] as const;
export const triggerChannels = ["SECURE_WEBHOOK", "AUTOMATED_EMAIL", "MESH_PING"] as const;

/** Owner-specific dead-man's-switch configuration. No vault plaintext belongs here. */
export const sentinelProfiles = mysqlTable("sentinel_profiles", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull().references(() => users.id, { onDelete: "cascade" }),
  state: mysqlEnum("state", escalationStates).notNull().default("ARMED"),
  checkInIntervalMinutes: int("checkInIntervalMinutes").notNull().default(1440),
  alertGraceMinutes: int("alertGraceMinutes").notNull().default(120),
  criticalGraceMinutes: int("criticalGraceMinutes").notNull().default(120),
  lastCheckInAt: timestamp("lastCheckInAt").notNull().defaultNow(),
  stateChangedAt: timestamp("stateChangedAt").notNull().defaultNow(),
  scheduleCronTaskUid: varchar("scheduleCronTaskUid", { length: 65 }),
  scheduleNextExecutionAt: timestamp("scheduleNextExecutionAt"),
  createdAt: timestamp("createdAt").notNull().defaultNow(),
  updatedAt: timestamp("updatedAt").notNull().defaultNow().onUpdateNow(),
}, table => [
  uniqueIndex("sentinel_profiles_user_unique").on(table.userId),
  index("sentinel_profiles_schedule_idx").on(table.scheduleCronTaskUid),
]);

/** AES-GCM ciphertext records. The server stores neither a passphrase nor any decryptable plaintext metadata. */
export const vaultEntries = mysqlTable("vault_entries", {
  id: varchar("id", { length: 32 }).primaryKey(),
  userId: int("userId").notNull().references(() => users.id, { onDelete: "cascade" }),
  ciphertext: longtext("ciphertext").notNull(),
  iv: varchar("iv", { length: 128 }).notNull(),
  encryptionVersion: varchar("encryptionVersion", { length: 32 }).notNull().default("AES-GCM-256/v1"),
  createdAt: timestamp("createdAt").notNull().defaultNow(),
}, table => [index("vault_entries_owner_idx").on(table.userId)]);

/** Non-sensitive event codes provide an auditable state-transition history without retaining vault content. */
export const sentinelAuditEvents = mysqlTable("sentinel_audit_events", {
  id: varchar("id", { length: 32 }).primaryKey(),
  userId: int("userId").notNull().references(() => users.id, { onDelete: "cascade" }),
  eventKind: mysqlEnum("eventKind", auditEventKinds).notNull(),
  fromState: varchar("fromState", { length: 16 }),
  toState: varchar("toState", { length: 16 }),
  createdAt: timestamp("createdAt").notNull().defaultNow(),
}, table => [index("sentinel_audit_owner_time_idx").on(table.userId, table.createdAt)]);

/** Simulated channel dispatches are retained as operational evidence only; no recipient or message plaintext is saved. */
export const sentinelTriggerEvents = mysqlTable("sentinel_trigger_events", {
  id: varchar("id", { length: 32 }).primaryKey(),
  userId: int("userId").notNull().references(() => users.id, { onDelete: "cascade" }),
  channel: mysqlEnum("channel", triggerChannels).notNull(),
  escalationState: mysqlEnum("escalationState", escalationStates).notNull(),
  status: varchar("status", { length: 32 }).notNull().default("SIMULATED_DISPATCHED"),
  dispatchedAt: timestamp("dispatchedAt").notNull().defaultNow(),
}, table => [index("sentinel_trigger_owner_time_idx").on(table.userId, table.dispatchedAt)]);

export type SentinelProfile = typeof sentinelProfiles.$inferSelect;
export type VaultEntry = typeof vaultEntries.$inferSelect;
export type SentinelAuditEvent = typeof sentinelAuditEvents.$inferSelect;
export type SentinelTriggerEvent = typeof sentinelTriggerEvents.$inferSelect;
