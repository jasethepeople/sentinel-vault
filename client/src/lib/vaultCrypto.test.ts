import { describe, expect, it } from "vitest";
import { webcrypto } from "node:crypto";
import { decryptVaultPayload, encryptVaultPayload } from "./vaultCrypto";

if (!globalThis.crypto?.subtle) Object.defineProperty(globalThis, "crypto", { value: webcrypto });

describe("browser-only vault crypto", () => {
  it("emits an opaque ciphertext-only server payload and restores it locally with the passphrase", async () => {
    const payload = { label: "CONTINGENCY", kind: "SECRET" as const, body: "the plaintext must not cross the network", createdAt: "2026-01-01T00:00:00.000Z" };
    const encrypted = await encryptVaultPayload(payload, "a-durable-local-passphrase");
    expect(encrypted).toEqual(expect.objectContaining({ encryptionVersion: "AES-GCM-256/v1" }));
    expect(encrypted.ciphertext).not.toContain(payload.body);
    expect(encrypted.ciphertext).not.toContain("a-durable-local-passphrase");
    await expect(decryptVaultPayload(encrypted.ciphertext, encrypted.iv, "a-durable-local-passphrase")).resolves.toEqual(payload);
  });

  it("rejects weak passphrases before an encrypt mutation can receive data", async () => {
    await expect(encryptVaultPayload({ label: "A", kind: "SECRET", body: "B", createdAt: new Date().toISOString() }, "short")).rejects.toThrow("at least 12");
  });
});
