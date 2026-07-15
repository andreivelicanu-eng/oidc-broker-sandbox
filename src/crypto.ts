import crypto from "node:crypto";

function mustBase64ToBuf(name: string, b64: string, expectedBytes: number): Buffer {
  let buf: Buffer;
  try {
    buf = Buffer.from(b64, "base64");
  } catch {
    throw new Error(`${name} must be base64`);
  }
  if (buf.length !== expectedBytes) {
    throw new Error(`${name} must decode to ${expectedBytes} bytes`);
  }
  return buf;
}

export function getAesKeyFromBase64(b64: string): Buffer {
  return mustBase64ToBuf("TENANT_SECRET_ENCRYPTION_KEY", b64, 32);
}

export function getSessionSigningKeyFromBase64(b64: string): Buffer {
  return mustBase64ToBuf("SESSION_SIGNING_KEY", b64, 32);
}

export function encryptAes256Gcm(plaintext: string, key: Buffer): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
  const tag = cipher.getAuthTag();
  // format: v1.<iv>.<tag>.<ciphertext>
  return `v1.${iv.toString("base64")}.${tag.toString("base64")}.${ciphertext.toString("base64")}`;
}

export function decryptAes256Gcm(payload: string, key: Buffer): string {
  const parts = payload.split(".");
  if (parts.length !== 4 || parts[0] !== "v1") throw new Error("Unsupported secret encoding");
  const iv = Buffer.from(parts[1]!, "base64");
  const tag = Buffer.from(parts[2]!, "base64");
  const ciphertext = Buffer.from(parts[3]!, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString("utf8");
}

export function randomUrlSafeString(bytes = 32): string {
  return crypto.randomBytes(bytes).toString("base64url");
}

export function sha256Base64Url(input: string): string {
  return crypto.createHash("sha256").update(input).digest("base64url");
}

export function signHmacSha256Base64Url(payload: string, key: Buffer): string {
  return crypto.createHmac("sha256", key).update(payload).digest("base64url");
}

