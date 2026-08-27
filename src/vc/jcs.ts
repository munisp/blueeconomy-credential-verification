/**
 * RFC 8785 JSON Canonicalization Scheme (JCS).
 *
 * Deterministic serialization used by the eddsa-jcs-2022 Data Integrity
 * cryptosuite. No external dependencies: numbers follow ECMAScript
 * Number-to-String semantics, strings use minimal JSON escaping, and object
 * keys are sorted by UTF-16 code units.
 */

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export function asJsonValue(value: unknown): JsonValue {
  return value as JsonValue;
}

export function canonicalizeJson(value: JsonValue): string {
  return serialize(value);
}

export function canonicalizeBytes(value: JsonValue): Uint8Array {
  return new TextEncoder().encode(serialize(value));
}

function serialize(value: JsonValue): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return serializeNumber(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((entry) => serialize(entry)).join(",")}]`;
  }
  const keys = Object.keys(value).sort();
  const entries = keys.map((key) => `${JSON.stringify(key)}:${serialize(value[key] as JsonValue)}`);
  return `{${entries.join(",")}}`;
}

function serializeNumber(value: number): string {
  if (!Number.isFinite(value)) {
    throw new Error("JCS cannot canonicalize non-finite numbers");
  }
  return JSON.stringify(value);
}
