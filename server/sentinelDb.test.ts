import { describe, expect, it, vi } from "vitest";
import { MySqlDialect } from "drizzle-orm/mysql-core";
import type { SentinelProfile } from "../drizzle/schema";
import { changedExactlyOneRow, getNextDeadline, getNextEscalationState, ownerVaultCondition, writeEscalationTransition, writePanicWipe } from "./sentinelDb";

function profile(state: SentinelProfile["state"], overrides: Partial<SentinelProfile> = {}): SentinelProfile {
  return {
    id: 1,
    userId: 1,
    state,
    checkInIntervalMinutes: 60,
    alertGraceMinutes: 20,
    criticalGraceMinutes: 10,
    lastCheckInAt: new Date("2026-01-01T00:00:00.000Z"),
    stateChangedAt: new Date("2026-01-01T02:00:00.000Z"),
    scheduleCronTaskUid: null,
    scheduleNextExecutionAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };
}

describe("sentinel escalation state machine", () => {
  it("advances through the required sequence and stops after TRIGGERED", () => {
    expect(getNextEscalationState("ARMED")).toBe("ALERT");
    expect(getNextEscalationState("ALERT")).toBe("CRITICAL");
    expect(getNextEscalationState("CRITICAL")).toBe("TRIGGERED");
    expect(getNextEscalationState("TRIGGERED")).toBeNull();
  });

  it("calculates the next threshold from the correct state-specific grace window", () => {
    expect(getNextDeadline(profile("ARMED"))?.toISOString()).toBe("2026-01-01T01:00:00.000Z");
    expect(getNextDeadline(profile("ALERT"))?.toISOString()).toBe("2026-01-01T02:20:00.000Z");
    expect(getNextDeadline(profile("CRITICAL"))?.toISOString()).toBe("2026-01-01T02:10:00.000Z");
    expect(getNextDeadline(profile("TRIGGERED"))).toBeNull();
  });

  it("recognizes the conditional write outcome used to suppress duplicate cron retry evidence", () => {
    expect(changedExactlyOneRow([{ affectedRows: 1 }])).toBe(true);
    expect(changedExactlyOneRow([{ affectedRows: 0 }])).toBe(false);
    expect(changedExactlyOneRow({ affectedRows: 1 })).toBe(true);
    expect(changedExactlyOneRow(undefined)).toBe(false);
  });

  it("does not create audit or channel records when a concurrent cron has already advanced the state", async () => {
    const insert = vi.fn();
    const tx = {
      update: vi.fn(() => ({ set: () => ({ where: async () => [{ affectedRows: 0 }] }) })),
      insert,
    };
    const wrote = await writeEscalationTransition(tx, profile("ARMED"), "ALERT", new Date());
    expect(wrote).toBe(false);
    expect(insert).not.toHaveBeenCalled();
  });

  it("writes one audit event and all simulated channel records after a successful conditional state update", async () => {
    const values = vi.fn();
    const tx = {
      update: vi.fn(() => ({ set: () => ({ where: async () => [{ affectedRows: 1 }] }) })),
      insert: vi.fn(() => ({ values })),
    };
    const wrote = await writeEscalationTransition(tx, profile("ARMED"), "ALERT", new Date());
    expect(wrote).toBe(true);
    expect(tx.insert).toHaveBeenCalledTimes(2);
    expect(values).toHaveBeenCalledTimes(2);
    expect(values.mock.calls[1]?.[0]).toHaveLength(3);
  });

  it("shreds ciphertext rows, resets the profile, and records the destructive operation", async () => {
    const where = vi.fn();
    const values = vi.fn();
    const tx = {
      delete: vi.fn(() => ({ where })),
      update: vi.fn(() => ({ set: () => ({ where }) })),
      insert: vi.fn(() => ({ values })),
    };
    await writePanicWipe(tx, 42, "CRITICAL");
    expect(tx.delete).toHaveBeenCalledTimes(1);
    expect(tx.update).toHaveBeenCalledTimes(1);
    expect(tx.insert).toHaveBeenCalledTimes(1);
    expect(values).toHaveBeenCalledWith(expect.objectContaining({ userId: 42, eventKind: "PANIC_WIPE", fromState: "CRITICAL", toState: "ARMED" }));
  });

  it("builds vault deletion criteria that constrain both ciphertext record and authenticated owner", () => {
    const query = new MySqlDialect().sqlToQuery(ownerVaultCondition(17, "vault-entry-000001"));
    expect(query.sql).toContain("`vault_entries`.`id` = ?");
    expect(query.sql).toContain("`vault_entries`.`userId` = ?");
    expect(query.params).toEqual(["vault-entry-000001", 17]);
  });
});
