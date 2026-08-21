const encoder = new TextEncoder();
const decoder = new TextDecoder();
const SALT_BYTES = 16;
const PBKDF2_ITERATIONS = 310_000;

const toBase64 = (bytes: Uint8Array) => {
  let binary = "";
  bytes.forEach(byte => { binary += String.fromCharCode(byte); });
  return btoa(binary);
};

const fromBase64 = (value: string) => Uint8Array.from(atob(value), char => char.charCodeAt(0));

const asArrayBuffer = (bytes: Uint8Array) => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;

async function deriveKey(passphrase: string, salt: Uint8Array) {
  const source = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: asArrayBuffer(salt), iterations: PBKDF2_ITERATIONS },
    source,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export type VaultPayload = { label: string; kind: "SECRET" | "MESSAGE" | "FILE_REFERENCE"; body: string; createdAt: string };

/** Encrypts the entire payload in-browser. Only the AES-GCM ciphertext, IV, and embedded random salt leave the device. */
export async function encryptVaultPayload(payload: VaultPayload, passphrase: string) {
  if (!crypto?.subtle) throw new Error("Web Crypto API is unavailable in this browser.");
  if (passphrase.length < 12) throw new Error("Use a vault passphrase of at least 12 characters.");
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt);
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: asArrayBuffer(iv) }, key, encoder.encode(JSON.stringify(payload))));
  const packed = new Uint8Array(salt.length + encrypted.length);
  packed.set(salt);
  packed.set(encrypted, salt.length);
  return { ciphertext: toBase64(packed), iv: toBase64(iv), encryptionVersion: "AES-GCM-256/v1" as const };
}

/** Decrypts locally with a memory-only passphrase. The passphrase is never written to browser storage or sent to the server. */
export async function decryptVaultPayload(ciphertext: string, iv: string, passphrase: string): Promise<VaultPayload> {
  const packed = fromBase64(ciphertext);
  const salt = packed.slice(0, SALT_BYTES);
  const encrypted = packed.slice(SALT_BYTES);
  const key = await deriveKey(passphrase, salt);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: asArrayBuffer(fromBase64(iv)) }, key, asArrayBuffer(encrypted));
  return JSON.parse(decoder.decode(plaintext)) as VaultPayload;
}
