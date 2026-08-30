import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/**
 * Complaint narrative confidentiality (spec §3/§5.3): narrative plaintext is
 * never stored — only the AES-256-GCM envelope (base64 nonce|ciphertext|tag)
 * and the SHA-256 digest. The key is env-only (BLUEECONOMY_WELFARE_NARRATIVE_KEY,
 * 64 lowercase hex chars = 32 bytes); complaint intake fails closed (503)
 * when it is not configured.
 *
 * Decryption exists only for views inside the CONFIDENTIAL boundary (the
 * complainant's own timeline and the NIMASA flag-state caseload). Narratives
 * never appear in events, logs, metrics or traces.
 */

export const NARRATIVE_KEY_ENV = "BLUEECONOMY_WELFARE_NARRATIVE_KEY";
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

export class NarrativeKey {
  private constructor(private readonly key: Buffer) {}

  public static fromHex(encoded: string): NarrativeKey {
    if (!/^[0-9a-f]{64}$/.test(encoded)) {
      throw new Error(`${NARRATIVE_KEY_ENV} must be 64 lowercase hex characters (32 bytes)`);
    }
    return new NarrativeKey(Buffer.from(encoded, "hex"));
  }

  public encrypt(plaintext: string): string {
    const nonce = randomBytes(NONCE_BYTES);
    const cipher = createCipheriv("aes-256-gcm", this.key, nonce);
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([nonce, ciphertext, tag]).toString("base64");
  }

  public decrypt(encoded: string): string {
    const raw = Buffer.from(encoded, "base64");
    if (raw.length <= NONCE_BYTES + TAG_BYTES) throw new Error("stored narrative envelope is truncated");
    const nonce = raw.subarray(0, NONCE_BYTES);
    const tag = raw.subarray(raw.length - TAG_BYTES);
    const ciphertext = raw.subarray(NONCE_BYTES, raw.length - TAG_BYTES);
    const decipher = createDecipheriv("aes-256-gcm", this.key, nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  }
}

/** Fail-closed factory: returns undefined when unset (intake then 503s). */
export function narrativeKeyFromEnv(env: NodeJS.ProcessEnv = process.env): NarrativeKey | undefined {
  const encoded = env[NARRATIVE_KEY_ENV];
  if (encoded === undefined || encoded.trim().length === 0) return undefined;
  return NarrativeKey.fromHex(encoded.trim());
}
