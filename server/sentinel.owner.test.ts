import { describe, expect, it, vi } from "vitest";
import type { TrpcContext } from "./_core/context";

const sentinelMocks = vi.hoisted(() => ({
  configureSentinel: vi.fn(),
  deleteVaultEntry: vi.fn(),
  getSentinelOverview: vi.fn(),
  panicWipeVault: vi.fn(),
  recordCheckIn: vi.fn(),
  saveScheduleReference: vi.fn(),
  storeVaultEntry: vi.fn(),
}));

vi.mock("./sentinelDb", () => sentinelMocks);
vi.mock("./_core/heartbeat", () => ({ createHeartbeatJob: vi.fn(), deleteHeartbeatJob: vi.fn(), updateHeartbeatJob: vi.fn() }));
vi.mock("./_core/env", () => ({ ENV: { isProduction: false } }));

const { appRouter } = await import("./routers");

function ownerContext(id: number): TrpcContext {
  return {
    user: { id, openId: `owner-${id}`, name: "Owner", email: null, loginMethod: "manus", role: "user", createdAt: new Date(), updatedAt: new Date(), lastSignedIn: new Date() },
    req: { headers: {}, protocol: "https" } as TrpcContext["req"],
    res: {} as TrpcContext["res"],
  };
}

describe("sentinel owner scoping", () => {
  it("passes the authenticated operator ID to vault deletion rather than accepting an owner from client input", async () => {
    const caller = appRouter.createCaller(ownerContext(17));
    await caller.sentinel.deleteVault({ id: "vault-entry-000001" });
    expect(sentinelMocks.deleteVaultEntry).toHaveBeenCalledWith(17, "vault-entry-000001");
    expect(sentinelMocks.deleteVaultEntry).not.toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ userId: expect.anything() }));
  });

  it("runs the destructive panic-wipe backend path against the authenticated operator only", async () => {
    sentinelMocks.panicWipeVault.mockResolvedValue(null);
    const caller = appRouter.createCaller(ownerContext(29));
    await expect(caller.sentinel.panicWipe({ confirmation: "WIPE" })).resolves.toEqual({ ok: true, confirmation: "WIPE" });
    expect(sentinelMocks.panicWipeVault).toHaveBeenCalledWith(29);
  });
});
