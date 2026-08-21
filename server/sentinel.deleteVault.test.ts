import { MySqlDialect } from "drizzle-orm/mysql-core";
import { describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ getDb: vi.fn() }));
vi.mock("./db", () => ({ getDb: mocks.getDb }));

const { deleteVaultEntry } = await import("./sentinelDb");

function transactionHarness(ownsRecord = true) {
  const deleteWhere = vi.fn();
  const auditValues = vi.fn();
  const tx = {
    delete: vi.fn(() => ({ where: deleteWhere })),
    insert: vi.fn(() => ({ values: auditValues })),
  };
  const lookupWhere = vi.fn(() => ({ limit: async () => ownsRecord ? [{ id: "matched" }] : [] }));
  const select = vi.fn(() => ({ from: () => ({ where: lookupWhere }) }));
  mocks.getDb.mockResolvedValue({ select, transaction: async (callback: (value: typeof tx) => unknown) => callback(tx) });
  return { tx, deleteWhere, auditValues, lookupWhere };
}

describe("deleteVaultEntry owner isolation", () => {
  it("executes the deletion helper with both the requested ciphertext ID and the authenticated owner ID", async () => {
    const { tx, deleteWhere, auditValues } = transactionHarness();
    await expect(deleteVaultEntry(17, "vault-entry-000001")).resolves.toBe(true);
    expect(tx.delete).toHaveBeenCalledTimes(1);
    const query = new MySqlDialect().sqlToQuery(deleteWhere.mock.calls[0]?.[0]);
    expect(query.params).toEqual(["vault-entry-000001", 17]);
    expect(auditValues).toHaveBeenCalledWith(expect.objectContaining({ userId: 17, eventKind: "VAULT_DELETED" }));
  });

  it("leaves a non-owner's ciphertext untouched when the owner-qualified lookup has no match", async () => {
    const nonOwner = transactionHarness(false);
    await expect(deleteVaultEntry(28, "shared-record-id")).resolves.toBe(false);
    expect(nonOwner.tx.delete).not.toHaveBeenCalled();
    expect(nonOwner.tx.insert).not.toHaveBeenCalled();
    const lookupQuery = new MySqlDialect().sqlToQuery(nonOwner.lookupWhere.mock.calls[0]?.[0]);
    expect(lookupQuery.params).toEqual(["shared-record-id", 28]);
  });
});
