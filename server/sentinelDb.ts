import { and, desc, eq } from "drizzle-orm";
import { nanoid } from "nanoid";
import {
  escalationStates,
  sentinelAuditEvents,
  sentinelProfiles,
  sentinelTriggerEvents,
  triggerChannels,
  vaultEntries,
  type SentinelProfile,
} from "../drizzle/schema";
import { getDb } from "./db";

export type EscalationState = (typeof escalationStates)[number];

const MINUTE = 60_000;

function requireDb<T>(db: T | null): T {
  if (!db) throw new Error("Database connection is unavailable");
  return db;
}

export function getNextDeadline(profile: SentinelProfile): Date | null {
  if (profile.state === "TRIGGERED") return null;
  const baseline = profile.state === "ARMED" ? profile.lastCheckInAt : profile.stateChangedAt;
  const graceMinutes = profile.state === "ARMED"
    ? profile.checkInIntervalMinutes
    : profile.state === "ALERT"
      ? profile.alertGraceMinutes
      : profile.criticalGraceMinutes;
  return new Date(baseline.getTime() + graceMinutes * MINUTE);
}

export function getNextEscalationState(state: EscalationState): EscalationState | null {
  if (state === "ARMED") return "ALERT";
  if (state === "ALERT") return "CRITICAL";
  if (state === "CRITICAL") return "TRIGGERED";
  return null;
}

export function changedExactlyOneRow(result: unknown): boolean {
  const header = (Array.isArray(result) ? result[0] : result) as { affectedRows?: unknown } | undefined;
  return header?.affectedRows === 1;
}

export async function writeEscalationTransition(
  tx: any,
  profile: SentinelProfile,
  newState: EscalationState,
  now: Date
): Promise<boolean> {
  const updateResult = await tx.update(sentinelProfiles).set({ state: newState, stateChangedAt: now }).where(and(eq(sentinelProfiles.id, profile.id), eq(sentinelProfiles.state, profile.state)));
  if (!changedExactlyOneRow(updateResult)) return false;
  await tx.insert(sentinelAuditEvents).values({ id: nanoid(), userId: profile.userId, eventKind: "STATE_TRANSITION", fromState: profile.state, toState: newState });
  await tx.insert(sentinelTriggerEvents).values(triggerChannels.map(channel => ({
    id: nanoid(), userId: profile.userId, channel, escalationState: newState, status: "SIMULATED_DISPATCHED",
  })));
  return true;
}

export async function ensureSentinelProfile(userId: number) {
  const db = requireDb(await getDb());
  const existing = await db.select().from(sentinelProfiles).where(eq(sentinelProfiles.userId, userId)).limit(1);
  if (existing[0]) return existing[0];
  await db.insert(sentinelProfiles).values({ userId });
  const created = await db.select().from(sentinelProfiles).where(eq(sentinelProfiles.userId, userId)).limit(1);
  if (!created[0]) throw new Error("Could not create sentinel profile");
  return created[0];
}

export async function getSentinelOverview(userId: number) {
  const db = requireDb(await getDb());
  const profile = await ensureSentinelProfile(userId);
  const [entries, audit, triggers] = await Promise.all([
    db.select().from(vaultEntries).where(eq(vaultEntries.userId, userId)).orderBy(desc(vaultEntries.createdAt)),
    db.select().from(sentinelAuditEvents).where(eq(sentinelAuditEvents.userId, userId)).orderBy(desc(sentinelAuditEvents.createdAt)).limit(40),
    db.select().from(sentinelTriggerEvents).where(eq(sentinelTriggerEvents.userId, userId)).orderBy(desc(sentinelTriggerEvents.dispatchedAt)).limit(24),
  ]);
  return { profile: { ...profile, nextDeadlineAt: getNextDeadline(profile) }, entries, audit, triggers };
}

export async function storeVaultEntry(userId: number, input: { ciphertext: string; iv: string; encryptionVersion: string }) {
  const db = requireDb(await getDb());
  const id = nanoid();
  await db.transaction(async tx => {
    await tx.insert(vaultEntries).values({ id, userId, ...input });
    await tx.insert(sentinelAuditEvents).values({ id: nanoid(), userId, eventKind: "VAULT_CREATED" });
  });
  return id;
}

export function ownerVaultCondition(userId: number, id: string) {
  return and(eq(vaultEntries.id, id), eq(vaultEntries.userId, userId));
}

export async function deleteVaultEntry(userId: number, id: string) {
  const db = requireDb(await getDb());
  const matchingEntries = await db.select({ id: vaultEntries.id }).from(vaultEntries).where(ownerVaultCondition(userId, id)).limit(1);
  if (!matchingEntries[0]) return false;
  await db.transaction(async tx => {
    await tx.delete(vaultEntries).where(ownerVaultCondition(userId, id));
    await tx.insert(sentinelAuditEvents).values({ id: nanoid(), userId, eventKind: "VAULT_DELETED" });
  });
  return true;
}

export async function configureSentinel(userId: number, input: { checkInIntervalMinutes: number; alertGraceMinutes: number; criticalGraceMinutes: number }) {
  const db = requireDb(await getDb());
  await ensureSentinelProfile(userId);
  await db.update(sentinelProfiles).set(input).where(eq(sentinelProfiles.userId, userId));
  await db.insert(sentinelAuditEvents).values({ id: nanoid(), userId, eventKind: "CONFIG_UPDATED" });
  const profile = await db.select().from(sentinelProfiles).where(eq(sentinelProfiles.userId, userId)).limit(1);
  if (!profile[0]) throw new Error("Sentinel profile disappeared during update");
  return profile[0];
}

export async function saveScheduleReference(userId: number, scheduleCronTaskUid: string | null, scheduleNextExecutionAt: Date | null) {
  const db = requireDb(await getDb());
  await db.update(sentinelProfiles).set({ scheduleCronTaskUid, scheduleNextExecutionAt }).where(eq(sentinelProfiles.userId, userId));
}

export async function recordCheckIn(userId: number) {
  const db = requireDb(await getDb());
  const profile = await ensureSentinelProfile(userId);
  const now = new Date();
  await db.transaction(async tx => {
    await tx.update(sentinelProfiles).set({ state: "ARMED", lastCheckInAt: now, stateChangedAt: now }).where(eq(sentinelProfiles.userId, userId));
    await tx.insert(sentinelAuditEvents).values({
      id: nanoid(), userId, eventKind: "CHECK_IN", fromState: profile.state, toState: "ARMED",
    });
  });
}

export async function panicWipeVault(userId: number) {
  const db = requireDb(await getDb());
  const profile = await ensureSentinelProfile(userId);
  await db.transaction(async tx => {
    await writePanicWipe(tx, userId, profile.state);
  });
  return profile.scheduleCronTaskUid;
}

export async function writePanicWipe(tx: any, userId: number, fromState: EscalationState) {
  const now = new Date();
  await tx.delete(vaultEntries).where(eq(vaultEntries.userId, userId));
  await tx.update(sentinelProfiles).set({ state: "ARMED", lastCheckInAt: now, stateChangedAt: now, scheduleCronTaskUid: null, scheduleNextExecutionAt: null }).where(eq(sentinelProfiles.userId, userId));
  await tx.insert(sentinelAuditEvents).values({ id: nanoid(), userId, eventKind: "PANIC_WIPE", fromState, toState: "ARMED" });
}

export async function advanceEscalationForTask(taskUid: string) {
  const db = requireDb(await getDb());
  const profileRows = await db.select().from(sentinelProfiles).where(eq(sentinelProfiles.scheduleCronTaskUid, taskUid)).limit(1);
  const profile = profileRows[0];
  if (!profile) return { skipped: "orphan" as const };
  const deadline = getNextDeadline(profile);
  if (!deadline || deadline > new Date()) return { skipped: "within-grace" as const, state: profile.state, deadline };
  const newState = getNextEscalationState(profile.state);
  if (!newState) return { skipped: "terminal" as const, state: profile.state, deadline: null };
  const now = new Date();
  let transitioned = false;
  await db.transaction(async tx => {
    transitioned = await writeEscalationTransition(tx, profile, newState, now);
  });
  if (!transitioned) return { skipped: "concurrent-transition" as const, state: profile.state };
  return { transitioned: true as const, fromState: profile.state, toState: newState };
}
