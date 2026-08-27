/**
 * Minimal multibase base58btc codec ("z" prefix) used for Data Integrity
 * proof values and Ed25519 multikey verification methods.
 */

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE = 58n;
const MULTIBASE_BASE58BTC_PREFIX = "z";

export function encodeBase58Btc(data: Uint8Array): string {
  if (data.length === 0) return MULTIBASE_BASE58BTC_PREFIX;
  let value = 0n;
  for (const byte of data) {
    value = value * 256n + BigInt(byte);
  }
  let encoded = "";
  while (value > 0n) {
    const remainder = Number(value % BASE);
    encoded = ALPHABET[remainder] + encoded;
    value = value / BASE;
  }
  for (const byte of data) {
    if (byte === 0) encoded = ALPHABET[0] + encoded;
    else break;
  }
  return MULTIBASE_BASE58BTC_PREFIX + encoded;
}

export function decodeBase58Btc(encoded: string): Uint8Array {
  if (!encoded.startsWith(MULTIBASE_BASE58BTC_PREFIX)) {
    throw new Error("multibase value must carry the base58btc 'z' prefix");
  }
  const body = encoded.slice(1);
  if (body.length === 0) return new Uint8Array(0);
  let value = 0n;
  for (const character of body) {
    const digit = ALPHABET.indexOf(character);
    if (digit < 0) throw new Error("multibase value contains a non-base58btc character");
    value = value * BASE + BigInt(digit);
  }
  const bytes: number[] = [];
  while (value > 0n) {
    bytes.unshift(Number(value % 256n));
    value = value / 256n;
  }
  let leadingZeroes = 0;
  while (leadingZeroes < body.length && body[leadingZeroes] === ALPHABET[0]) leadingZeroes += 1;
  return new Uint8Array([...new Array<number>(leadingZeroes).fill(0), ...bytes]);
}
