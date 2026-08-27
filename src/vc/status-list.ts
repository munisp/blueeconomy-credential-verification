import { gunzipSync, gzipSync } from "node:zlib";
import { asJsonValue, type JsonValue } from "./jcs.js";
import { VC2_CONTEXT } from "./types.js";

/**
 * W3C Bitstring Status List v1.0 primitives. The revocation bitstring is
 * 128 KiB (1 048 576 entries), gzip-compressed and base64url-encoded into a
 * BitstringStatusListCredential that wallets and verifiers can resolve and
 * verify offline from a snapshot.
 */

export const STATUS_LIST_BITS = 1_048_576;
export const STATUS_LIST_BYTES = STATUS_LIST_BITS / 8;
export const BITSTRING_STATUS_LIST_TYPE = "BitstringStatusListCredential" as const;

export interface BitstringStatusListCredential {
  "@context": [typeof VC2_CONTEXT];
  id: string;
  type: ["VerifiableCredential", typeof BITSTRING_STATUS_LIST_TYPE];
  issuer: string;
  validFrom: string;
  credentialSubject: {
    id: string;
    type: "BitstringStatusList";
    statusPurpose: "revocation";
    encodedList: string;
  };
  proof?: Record<string, JsonValue>;
}

export function createBitstring(): Uint8Array {
  return new Uint8Array(STATUS_LIST_BYTES);
}

export function setStatusBit(bits: Uint8Array, index: number, revoked: boolean): void {
  assertIndex(bits, index);
  const byteIndex = Math.floor(index / 8);
  const mask = 1 << (index % 8);
  const current = bits[byteIndex] ?? 0;
  bits[byteIndex] = revoked ? current | mask : current & ~mask;
}

export function getStatusBit(bits: Uint8Array, index: number): boolean {
  assertIndex(bits, index);
  return ((bits[Math.floor(index / 8)] ?? 0) & (1 << (index % 8))) !== 0;
}

export function encodeBitstring(bits: Uint8Array): string {
  if (bits.length !== STATUS_LIST_BYTES) {
    throw new Error(`status bitstring must be exactly ${STATUS_LIST_BYTES} bytes`);
  }
  return gzipSync(Buffer.from(bits.buffer, bits.byteOffset, bits.byteLength), { level: 9 }).toString("base64url");
}

export function decodeBitstring(encodedList: string): Uint8Array {
  let compressed: Buffer;
  try {
    compressed = Buffer.from(encodedList, "base64url");
  } catch {
    throw new Error("status list encodedList is not valid base64url");
  }
  let bits: Buffer;
  try {
    bits = gunzipSync(compressed);
  } catch {
    throw new Error("status list encodedList is not valid gzip data");
  }
  if (bits.length !== STATUS_LIST_BYTES) {
    throw new Error(`status list must expand to exactly ${STATUS_LIST_BYTES} bytes`);
  }
  return new Uint8Array(bits.buffer, bits.byteOffset, bits.byteLength);
}

export function buildStatusListCredential(
  id: string,
  issuer: string,
  bits: Uint8Array,
  validFrom: Date,
): BitstringStatusListCredential {
  return {
    "@context": [VC2_CONTEXT],
    id,
    type: ["VerifiableCredential", BITSTRING_STATUS_LIST_TYPE],
    issuer,
    validFrom: validFrom.toISOString(),
    credentialSubject: {
      id: `${id}#list`,
      type: "BitstringStatusList",
      statusPurpose: "revocation",
      encodedList: encodeBitstring(bits),
    },
  };
}

export function assertStatusListCredential(value: unknown): BitstringStatusListCredential {
  const candidate = value as Partial<BitstringStatusListCredential>;
  if (typeof candidate !== "object" || candidate === null) throw new Error("status list credential must be an object");
  const context = candidate["@context"];
  if (!Array.isArray(context) || context[0] !== VC2_CONTEXT) throw new Error("status list credential context is not the VC 2.0 context");
  if (!Array.isArray(candidate.type) || candidate.type[0] !== "VerifiableCredential" || !candidate.type.includes(BITSTRING_STATUS_LIST_TYPE)) {
    throw new Error("status list credential must be a VerifiableCredential of type BitstringStatusListCredential");
  }
  if (typeof candidate.id !== "string" || candidate.id.length === 0) throw new Error("status list credential id is required");
  if (typeof candidate.issuer !== "string" || candidate.issuer.length === 0) throw new Error("status list credential issuer is required");
  if (typeof candidate.validFrom !== "string" || !Number.isFinite(Date.parse(candidate.validFrom))) {
    throw new Error("status list credential validFrom must be a valid date-time");
  }
  const subject = candidate.credentialSubject;
  if (typeof subject !== "object" || subject === null) throw new Error("status list credential subject is required");
  if (subject.type !== "BitstringStatusList" || subject.statusPurpose !== "revocation") {
    throw new Error("status list credential subject must be a revocation BitstringStatusList");
  }
  if (typeof subject.encodedList !== "string" || subject.encodedList.length === 0) {
    throw new Error("status list credential subject encodedList is required");
  }
  return candidate as BitstringStatusListCredential;
}

export function statusListCredentialToJson(credential: BitstringStatusListCredential): Record<string, JsonValue> {
  return asJsonValue(credential) as Record<string, JsonValue>;
}

function assertIndex(bits: Uint8Array, index: number): void {
  if (!Number.isInteger(index) || index < 0 || index >= bits.length * 8) {
    throw new Error("status list index is out of range");
  }
}
