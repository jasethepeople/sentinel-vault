import { describe, expect, it } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

function anonymousContext(): TrpcContext {
  return {
    user: null,
    req: { headers: {}, protocol: "https" } as TrpcContext["req"],
    res: {} as TrpcContext["res"],
  };
}

function authenticatedContext(): TrpcContext {
  return {
    user: {
      id: 7, openId: "operator-7", name: "Operator", email: null, loginMethod: "manus", role: "user",
      createdAt: new Date(), updatedAt: new Date(), lastSignedIn: new Date(),
    },
    req: { headers: {}, protocol: "https" } as TrpcContext["req"],
    res: {} as TrpcContext["res"],
  };
}

describe("sentinel procedure protections", () => {
  it("blocks anonymous callers from reading an owner-scoped overview", async () => {
    await expect(appRouter.createCaller(anonymousContext()).sentinel.overview()).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });

  it("rejects a panic wipe unless the destructive confirmation literal is supplied", async () => {
    const caller = appRouter.createCaller(authenticatedContext());
    await expect(caller.sentinel.panicWipe({ confirmation: "NOPE" as "WIPE" })).rejects.toMatchObject({ code: "BAD_REQUEST" });
  });

  it("rejects an empty ciphertext payload before it can reach persistence", async () => {
    const caller = appRouter.createCaller(authenticatedContext());
    await expect(caller.sentinel.createVault({ ciphertext: "", iv: "12345678", encryptionVersion: "AES-GCM-256/v1" })).rejects.toMatchObject({ code: "BAD_REQUEST" });
  });
});
